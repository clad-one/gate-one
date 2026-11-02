// Package usagewal implements the durable, per-event-type write-ahead
// log used by the usage-event bus. One WAL exists per (node, event
// type). Subscribers read with a cursor and acknowledge offsets; the
// store truncates segments only when every subscriber of the type has
// acknowledged them.
//
// The store never blocks the caller on a slow subscriber: appends are
// bounded by a per-type share of the node budget (Reserve returns
// ErrFull, which the proxy turns into a 503 on the affected routes).
// When a subscriber exceeds its lag budget, DropSubscriber moves its
// cursor to the lag limit so older segments become evictable.
package usagewal

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cladone/gate-one/pkg/usage"
)

var (
	ErrFull          = errors.New("usagewal: budget share full")
	ErrEventTooLarge = errors.New("usagewal: event larger than the reservation")
	ErrClosed        = errors.New("usagewal: closed")
	ErrCorrupt       = errors.New("usagewal: corrupt record")
	ErrNoSubscriber  = errors.New("usagewal: unknown subscriber")
)

// FsyncMode is the durability contract of an event type.
type FsyncMode string

const (
	// FsyncNone relies on the OS page cache (tests / best-effort).
	FsyncNone FsyncMode = "none"
	// FsyncWindow group-commits every WindowMS.
	FsyncWindow FsyncMode = "window_ms"
	// FsyncAlways fsyncs before Append returns (zero loss).
	FsyncAlways FsyncMode = "always"
)

// TypeConfig is the per-event-type WAL configuration.
type TypeConfig struct {
	// ShareBytes is the maximum size of this type's WAL on this node.
	ShareBytes int64
	// Fsync is "none", "window_ms" or "always".
	Fsync FsyncMode
	// WindowMS is the group-commit interval for FsyncWindow.
	WindowMS int
	// SegmentBytes rotates the append file; 0 = share/4 capped at 8 MiB.
	SegmentBytes int64
}

// Config configures the node WAL.
type Config struct {
	Dir         string
	BudgetBytes int64
	Types       map[usage.EventType]TypeConfig
}

// Ticket is a reservation of WAL space for one event.
type Ticket struct {
	typ      usage.EventType
	size     int64
	released atomic.Bool
	consumed atomic.Bool
}

// Record is one entry read from the WAL.
type Record struct {
	Offset int64
	Next   int64
	Event  usage.Event
}

// Store is the per-node WAL store.
type Store struct {
	dir    string
	types  map[usage.EventType]*typeWAL
	closed atomic.Bool
}

// Open opens (or creates) the WAL store.
func Open(cfg Config) (*Store, error) {
	if strings.TrimSpace(cfg.Dir) == "" {
		return nil, fmt.Errorf("usagewal: dir is required")
	}
	if cfg.BudgetBytes <= 0 {
		return nil, fmt.Errorf("usagewal: budgetBytes must be > 0")
	}
	if len(cfg.Types) == 0 {
		return nil, fmt.Errorf("usagewal: at least one event type is required")
	}
	var sum int64
	for typ, tc := range cfg.Types {
		if tc.Fsync == "" {
			tc.Fsync = FsyncNone
			cfg.Types[typ] = tc
		}
		if !usage.ValidEventType(typ) {
			return nil, fmt.Errorf("usagewal: unknown event type %q", typ)
		}
		if tc.ShareBytes <= 0 {
			return nil, fmt.Errorf("usagewal: %s: shareBytes must be > 0", typ)
		}
		switch tc.Fsync {
		case FsyncNone, FsyncAlways:
		case FsyncWindow:
			if tc.WindowMS <= 0 {
				return nil, fmt.Errorf(
					"usagewal: %s: windowMs must be > 0", typ)
			}
		default:
			return nil, fmt.Errorf(
				"usagewal: %s: unknown fsync %q", typ, tc.Fsync)
		}
		sum += tc.ShareBytes
	}
	if sum > cfg.BudgetBytes {
		return nil, fmt.Errorf(
			"usagewal: sum of shares (%d) exceeds budgetBytes (%d)",
			sum, cfg.BudgetBytes)
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: cfg.Dir, types: map[usage.EventType]*typeWAL{}}
	for typ, tc := range cfg.Types {
		tw, err := openType(cfg.Dir, typ, tc)
		if err != nil {
			_ = s.Close()
			return nil, err
		}
		s.types[typ] = tw
	}
	return s, nil
}

// Close stops the group-commit goroutines and syncs every WAL.
func (s *Store) Close() error {
	if s == nil || s.closed.Swap(true) {
		return nil
	}
	var first error
	for _, tw := range s.types {
		if err := tw.close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (s *Store) wal(typ usage.EventType) (*typeWAL, error) {
	if s.closed.Load() {
		return nil, ErrClosed
	}
	tw := s.types[typ]
	if tw == nil {
		return nil, fmt.Errorf("usagewal: no WAL for type %q", typ)
	}
	return tw, nil
}

// Reserve reserves up to size bytes in the type's share. It returns
// ErrFull when the share would be exceeded. Release must be called if
// Append is not called.
func (s *Store) Reserve(typ usage.EventType, size int64) (*Ticket, error) {
	tw, err := s.wal(typ)
	if err != nil {
		return nil, err
	}
	if size <= 0 {
		return nil, fmt.Errorf("usagewal: reservation size must be > 0")
	}
	if err := tw.reserve(size); err != nil {
		return nil, err
	}
	return &Ticket{typ: typ, size: size}, nil
}

// Release returns an unused reservation.
func (s *Store) Release(t *Ticket) {
	if t == nil || t.consumed.Load() ||
		!t.released.CompareAndSwap(false, true) {
		return
	}
	if tw := s.types[t.typ]; tw != nil {
		tw.release(t.size)
	}
}

// Append writes the event using a reservation. It returns the record
// start offset. With FsyncAlways the record is fsynced before return.
func (s *Store) Append(t *Ticket, ev *usage.Event) (int64, error) {
	if t == nil {
		return 0, fmt.Errorf("usagewal: nil ticket")
	}
	if t.consumed.Load() {
		return 0, fmt.Errorf("usagewal: ticket already used")
	}
	if t.released.Load() {
		return 0, fmt.Errorf("usagewal: ticket already released")
	}
	tw, err := s.wal(t.typ)
	if err != nil {
		return 0, err
	}
	start, written, err := tw.append(t.size, ev)
	if written {
		t.consumed.Store(true)
	}
	return start, err
}

// Register creates a cursor for a subscriber at the current tail.
func (s *Store) Register(typ usage.EventType, sub string) (int64, error) {
	tw, err := s.wal(typ)
	if err != nil {
		return 0, err
	}
	return tw.register(sub)
}

// Remove drops a subscriber cursor entirely.
func (s *Store) Remove(typ usage.EventType, sub string) error {
	tw, err := s.wal(typ)
	if err != nil {
		return err
	}
	return tw.remove(sub)
}

// Ack advances a subscriber cursor and evicts fully acknowledged
// segments.
func (s *Store) Ack(typ usage.EventType, sub string, offset int64) error {
	tw, err := s.wal(typ)
	if err != nil {
		return err
	}
	return tw.ack(sub, offset)
}

// DropSubscriber moves the cursor to the lag limit: the subscriber
// loses older events but no longer blocks their eviction.
func (s *Store) DropSubscriber(
	typ usage.EventType, sub string, lagBytes int64,
) (int64, error) {
	tw, err := s.wal(typ)
	if err != nil {
		return 0, err
	}
	return tw.dropSubscriber(sub, lagBytes)
}

// Read returns up to maxBytes of records after the subscriber cursor.
func (s *Store) Read(
	typ usage.EventType, sub string, maxBytes int64,
) ([]Record, error) {
	tw, err := s.wal(typ)
	if err != nil {
		return nil, err
	}
	cur, err := tw.cursor(sub)
	if err != nil {
		return nil, err
	}
	return tw.readAfter(cur, maxBytes)
}

// Cursor returns a subscriber cursor.
func (s *Store) Cursor(typ usage.EventType, sub string) (int64, error) {
	tw, err := s.wal(typ)
	if err != nil {
		return 0, err
	}
	return tw.cursor(sub)
}

// Lag returns tail - cursor for a subscriber.
func (s *Store) Lag(
	typ usage.EventType, sub string,
) (int64, error) {
	cur, err := s.Cursor(typ, sub)
	if err != nil {
		return 0, err
	}
	tw, _ := s.wal(typ)
	return tw.tail() - cur, nil
}

// Tail returns the current logical end offset.
func (s *Store) Tail(typ usage.EventType) (int64, error) {
	tw, err := s.wal(typ)
	if err != nil {
		return 0, err
	}
	return tw.tail(), nil
}

// Size returns the bytes currently stored for a type.
func (s *Store) Size(typ usage.EventType) (int64, error) {
	tw, err := s.wal(typ)
	if err != nil {
		return 0, err
	}
	tw.mu.Lock()
	defer tw.mu.Unlock()
	return tw.total, nil
}

// typeWAL is one (node, event type) append-only log.
type typeWAL struct {
	typ          usage.EventType
	dir          string
	share        int64
	fsync        FsyncMode
	window       time.Duration
	segmentBytes int64

	mu       sync.Mutex
	current  *os.File
	segBase  int64
	segSize  int64
	total    int64
	reserved int64
	tailOff  int64
	cursors  map[string]int64
	dirty    bool

	stop chan struct{}
	wg   sync.WaitGroup
}

const (
	recordHeader  = 4
	recordTrailer = 4
	maxRecord     = 4 << 20
)

func openType(dir string, typ usage.EventType, tc TypeConfig) (*typeWAL, error) {
	typeDir := filepath.Join(dir, string(typ))
	if err := os.MkdirAll(typeDir, 0o700); err != nil {
		return nil, err
	}
	tw := &typeWAL{
		typ:          typ,
		dir:          typeDir,
		share:        tc.ShareBytes,
		fsync:        tc.Fsync,
		window:       time.Duration(tc.WindowMS) * time.Millisecond,
		segmentBytes: tc.SegmentBytes,
		cursors:      map[string]int64{},
		stop:         make(chan struct{}),
	}
	if tw.segmentBytes <= 0 {
		tw.segmentBytes = tw.share / 4
		if tw.segmentBytes > 8<<20 {
			tw.segmentBytes = 8 << 20
		}
		if tw.segmentBytes < 64<<10 {
			tw.segmentBytes = 64 << 10
		}
	}
	if err := tw.load(); err != nil {
		return nil, err
	}
	if tw.fsync == FsyncWindow {
		tw.wg.Add(1)
		go tw.flusher()
	}
	return tw, nil
}

type meta struct {
	Cursors map[string]int64 `json:"cursors"`
}

func (tw *typeWAL) metaPath() string {
	return filepath.Join(tw.dir, "meta.json")
}

func (tw *typeWAL) load() error {
	segs, err := tw.segments()
	if err != nil {
		return err
	}
	if len(segs) > 0 {
		last := segs[len(segs)-1]
		valid, err := validateSegment(last.path)
		if err != nil {
			return err
		}
		if valid < last.size {
			if err := os.Truncate(last.path, valid); err != nil {
				return err
			}
			last.size = valid
		}
		tw.segBase = last.base
		tw.segSize = last.size
		tw.tailOff = last.base + last.size
		tw.current, err = os.OpenFile(last.path, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		for _, seg := range segs {
			tw.total += seg.size
		}
	}
	raw, err := os.ReadFile(tw.metaPath())
	if err == nil {
		var m meta
		if err := json.Unmarshal(raw, &m); err != nil {
			return fmt.Errorf("usagewal: %s: meta: %w", tw.typ, err)
		}
		for sub, off := range m.Cursors {
			if off < 0 {
				off = 0
			}
			if off > tw.tailOff {
				off = tw.tailOff
			}
			tw.cursors[sub] = off
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

type segment struct {
	base int64
	size int64
	path string
}

func (tw *typeWAL) segments() ([]segment, error) {
	entries, err := os.ReadDir(tw.dir)
	if err != nil {
		return nil, err
	}
	var segs []segment
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".seg") {
			continue
		}
		base, err := strconv.ParseInt(strings.TrimSuffix(name, ".seg"), 10, 64)
		if err != nil || base < 0 {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		segs = append(segs, segment{
			base: base, size: info.Size(),
			path: filepath.Join(tw.dir, name),
		})
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].base < segs[j].base })
	return segs, nil
}

// validateSegment scans records and returns the valid byte length.
func validateSegment(path string) (int64, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	var off int64
	for off < int64(len(raw)) {
		size, err := recordSize(raw[off:])
		if err != nil {
			break
		}
		off += size
	}
	return off, nil
}

func recordSize(b []byte) (int64, error) {
	if len(b) < recordHeader {
		return 0, ErrCorrupt
	}
	n := int64(binary.BigEndian.Uint32(b[:recordHeader]))
	if n <= 0 || n > maxRecord {
		return 0, ErrCorrupt
	}
	total := recordHeader + n + recordTrailer
	if int64(len(b)) < total {
		return 0, ErrCorrupt
	}
	sum := crc32.ChecksumIEEE(b[recordHeader : recordHeader+n])
	if sum != binary.BigEndian.Uint32(b[recordHeader+n:total]) {
		return 0, ErrCorrupt
	}
	return total, nil
}

func encodeRecord(ev *usage.Event) ([]byte, error) {
	payload, err := json.Marshal(ev)
	if err != nil {
		return nil, err
	}
	if len(payload) > maxRecord {
		return nil, ErrEventTooLarge
	}
	out := make([]byte, recordHeader+len(payload)+recordTrailer)
	binary.BigEndian.PutUint32(out[:recordHeader], uint32(len(payload)))
	copy(out[recordHeader:], payload)
	binary.BigEndian.PutUint32(
		out[recordHeader+len(payload):],
		crc32.ChecksumIEEE(payload))
	return out, nil
}

func (tw *typeWAL) reserve(size int64) error {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if tw.total+tw.reserved+size > tw.share {
		return ErrFull
	}
	tw.reserved += size
	return nil
}

func (tw *typeWAL) release(size int64) {
	tw.mu.Lock()
	tw.reserved -= size
	if tw.reserved < 0 {
		tw.reserved = 0
	}
	tw.mu.Unlock()
}

func (tw *typeWAL) append(
	reservedSize int64, ev *usage.Event,
) (int64, bool, error) {
	rec, err := encodeRecord(ev)
	if err != nil {
		return 0, false, err
	}
	size := int64(len(rec))
	if size > reservedSize {
		return 0, false, ErrEventTooLarge
	}
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if tw.current == nil || (tw.segSize > 0 && tw.segSize+size > tw.segmentBytes) {
		if err := tw.rotateLocked(); err != nil {
			return 0, false, err
		}
	}
	start := tw.tailOff
	if _, err := tw.current.Write(rec); err != nil {
		return 0, false, err
	}
	tw.reserved -= reservedSize
	if tw.reserved < 0 {
		tw.reserved = 0
	}
	tw.segSize += size
	tw.total += size
	tw.tailOff += size
	tw.dirty = true
	if tw.fsync == FsyncAlways {
		if err := tw.current.Sync(); err != nil {
			return start, true, err
		}
		tw.dirty = false
	}
	return start, true, nil
}

func (tw *typeWAL) rotateLocked() error {
	if tw.current != nil {
		if err := tw.current.Sync(); err != nil {
			return err
		}
		if err := tw.current.Close(); err != nil {
			return err
		}
		tw.current = nil
	}
	path := filepath.Join(tw.dir, fmt.Sprintf("%020d.seg", tw.tailOff))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	tw.current = f
	tw.segBase = tw.tailOff
	tw.segSize = 0
	return nil
}

func (tw *typeWAL) flusher() {
	defer tw.wg.Done()
	t := time.NewTicker(tw.window)
	defer t.Stop()
	for {
		select {
		case <-tw.stop:
			return
		case <-t.C:
			tw.mu.Lock()
			if tw.dirty && tw.current != nil {
				if err := tw.current.Sync(); err == nil {
					tw.dirty = false
				}
			}
			tw.mu.Unlock()
		}
	}
}

func (tw *typeWAL) close() error {
	close(tw.stop)
	tw.wg.Wait()
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if tw.current != nil {
		err := tw.current.Sync()
		if cerr := tw.current.Close(); err == nil {
			err = cerr
		}
		tw.current = nil
		return err
	}
	return nil
}

func (tw *typeWAL) tail() int64 {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	return tw.tailOff
}

func (tw *typeWAL) register(sub string) (int64, error) {
	if strings.TrimSpace(sub) == "" {
		return 0, fmt.Errorf("usagewal: empty subscriber")
	}
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if _, ok := tw.cursors[sub]; ok {
		return tw.cursors[sub], nil
	}
	tw.cursors[sub] = tw.tailOff
	if err := tw.saveMetaLocked(); err != nil {
		return 0, err
	}
	return tw.tailOff, nil
}

func (tw *typeWAL) cursor(sub string) (int64, error) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	off, ok := tw.cursors[sub]
	if !ok {
		return 0, ErrNoSubscriber
	}
	return off, nil
}

func (tw *typeWAL) remove(sub string) error {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if _, ok := tw.cursors[sub]; !ok {
		return ErrNoSubscriber
	}
	delete(tw.cursors, sub)
	if err := tw.saveMetaLocked(); err != nil {
		return err
	}
	return tw.truncateLocked()
}

func (tw *typeWAL) ack(sub string, offset int64) error {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	cur, ok := tw.cursors[sub]
	if !ok {
		return ErrNoSubscriber
	}
	if offset < cur {
		return nil
	}
	if offset > tw.tailOff {
		offset = tw.tailOff
	}
	tw.cursors[sub] = offset
	if err := tw.saveMetaLocked(); err != nil {
		return err
	}
	return tw.truncateLocked()
}

func (tw *typeWAL) dropSubscriber(sub string, lagBytes int64) (int64, error) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if _, ok := tw.cursors[sub]; !ok {
		return 0, ErrNoSubscriber
	}
	if lagBytes < 0 {
		lagBytes = 0
	}
	first := tw.firstAvailableLocked()
	off := tw.tailOff - lagBytes
	if off < first {
		off = first
	}
	if off < 0 {
		off = 0
	}
	tw.cursors[sub] = off
	if err := tw.saveMetaLocked(); err != nil {
		return 0, err
	}
	if err := tw.truncateLocked(); err != nil {
		return 0, err
	}
	return off, nil
}

func (tw *typeWAL) firstAvailableLocked() int64 {
	segs, err := tw.segments()
	if err != nil || len(segs) == 0 {
		return tw.tailOff
	}
	return segs[0].base
}

func (tw *typeWAL) saveMetaLocked() error {
	raw, err := json.Marshal(meta{Cursors: tw.cursors})
	if err != nil {
		return err
	}
	tmp := tw.metaPath() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, tw.metaPath()); err != nil {
		return err
	}
	if d, err := os.Open(tw.dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// truncateLocked deletes segments whose end is at or below the minimum
// active cursor. With no subscriber, everything before the current
// segment is evictable.
func (tw *typeWAL) truncateLocked() error {
	min := tw.tailOff
	if len(tw.cursors) > 0 {
		first := true
		for _, off := range tw.cursors {
			if first || off < min {
				min = off
				first = false
			}
		}
	}
	segs, err := tw.segments()
	if err != nil {
		return err
	}
	for _, seg := range segs {
		end := seg.base + seg.size
		if end > min {
			continue
		}
		if tw.current != nil && seg.base == tw.segBase {
			continue // keep the current append file
		}
		if err := os.Remove(seg.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		if seg.size > 0 && tw.total >= seg.size {
			tw.total -= seg.size
		}
	}
	return nil
}

func (tw *typeWAL) readAfter(after, maxBytes int64) ([]Record, error) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	segs, err := tw.segments()
	if err != nil {
		return nil, err
	}
	if len(segs) == 0 {
		return nil, nil
	}
	if after < segs[0].base {
		after = segs[0].base
	}
	var out []Record
	var used int64
	for _, seg := range segs {
		end := seg.base + seg.size
		if end <= after {
			continue
		}
		raw, err := os.ReadFile(seg.path)
		if err != nil {
			return nil, err
		}
		off := int64(0)
		for off < int64(len(raw)) {
			size, err := recordSize(raw[off:])
			if err != nil {
				return out, fmt.Errorf("%w: %s",
					ErrCorrupt, seg.path)
			}
			recOff := seg.base + off
			if recOff < after {
				off += size
				continue
			}
			if used > 0 && used+size > maxBytes {
				return out, nil
			}
			payload := raw[off+recordHeader : off+recordHeader+
				int64(binary.BigEndian.Uint32(raw[off:off+recordHeader]))]
			var ev usage.Event
			if err := json.Unmarshal(payload, &ev); err != nil {
				return out, fmt.Errorf("%w: %s: %v",
					ErrCorrupt, seg.path, err)
			}
			out = append(out, Record{
				Offset: recOff,
				Next:   recOff + size,
				Event:  ev,
			})
			used += size
			off += size
			if used >= maxBytes {
				return out, nil
			}
		}
	}
	return out, nil
}
