// Package outbox is the bounded, append-only delivery buffer of the
// billing path. It is deliberately small: it survives a transport outage
// for a few hours, then refuses new records (fail-closed) instead of
// growing an unbounded financial archive on the operator's host.
//
// Records are opaque bytes. The sink (push or signed export) defines the
// payload format; the outbox only guarantees ordering, framing, fsync and
// the offset/commit contract.
package outbox

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// ErrFull means a bound (age, bytes or records) is reached.
	ErrFull = errors.New("outbox: full")
	// ErrCorrupt means a record failed its checksum.
	ErrCorrupt = errors.New("outbox: corrupt record")
	// ErrClosed means the store was closed.
	ErrClosed = errors.New("outbox: closed")
)

const (
	recordHeader  = 4
	recordTrailer = 4
	commitFile    = "commit"
	segSuffix     = ".seg"
	defaultSeg    = 8 << 20
)

// Config bounds the buffer.
type Config struct {
	// Dir is the outbox directory (created if absent).
	Dir string
	// MaxAge refuses new records when the oldest pending one is older.
	MaxAge time.Duration
	// MaxBytes / MaxRecords bound the pending volume.
	MaxBytes   int64
	MaxRecords int64
	// OnFull is "block" (default, returns ErrFull) or "drop" (Append
	// returns no error and discards the record). Drop is never silent: the
	// caller counts it.
	OnFull string
	// SegmentBytes is the rotation threshold (default 8 MiB).
	SegmentBytes int64
}

func (c Config) normalized() Config {
	if c.SegmentBytes <= 0 {
		c.SegmentBytes = defaultSeg
	}
	if c.OnFull == "" {
		c.OnFull = "block"
	}
	return c
}

// Record is one pending entry.
type Record struct {
	Offset  int64
	Payload []byte
}

type segment struct {
	base  int64
	size  int64
	path  string
	mtime time.Time
}

// Store is the append-only outbox.
type Store struct {
	mu      sync.Mutex
	dir     string
	cfg     Config
	seg     *segment
	file    *os.File
	head    int64
	records int64
	bytes   int64
	commit  int64
	oldest  time.Time
	dropped int64
	closed  bool
}

// Open opens (or creates) an outbox.
func Open(cfg Config) (*Store, error) {
	cfg = cfg.normalized()
	if strings.TrimSpace(cfg.Dir) == "" {
		return nil, fmt.Errorf("outbox: dir is required")
	}
	if cfg.OnFull != "block" && cfg.OnFull != "drop" {
		return nil, fmt.Errorf("outbox: onFull must be block or drop")
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: cfg.Dir, cfg: cfg}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	// Commit offset.
	if raw, err := os.ReadFile(filepath.Join(s.dir, commitFile)); err == nil {
		if v, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); err == nil {
			s.commit = v
		}
	}
	segs, err := s.segments()
	if err != nil {
		return err
	}
	s.head = s.commit
	s.records = 0
	s.bytes = 0
	for _, seg := range segs {
		metas, err := scanSegment(seg.path)
		if err != nil {
			return err
		}
		for _, m := range metas {
			if m.offset < s.commit {
				continue
			}
			s.records++
			s.bytes += m.size
			if s.oldest.IsZero() {
				s.oldest = seg.mtime
			}
		}
		if seg.base+seg.size > s.head {
			s.head = seg.base + seg.size
		}
	}
	// Append to the last segment.
	if len(segs) > 0 {
		last := segs[len(segs)-1]
		f, err := os.OpenFile(last.path, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		s.seg, s.file = &last, f
	} else {
		if err := s.rotate(s.head); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) segments() ([]segment, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var out []segment
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), segSuffix) {
			continue
		}
		base, err := strconv.ParseInt(
			strings.TrimSuffix(e.Name(), segSuffix), 10, 64)
		if err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		out = append(out, segment{
			base: base, size: info.Size(),
			path: filepath.Join(s.dir, e.Name()), mtime: info.ModTime(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].base < out[j].base })
	return out, nil
}

func (s *Store) rotate(base int64) error {
	if s.file != nil {
		_ = s.file.Close()
	}
	path := filepath.Join(s.dir, fmt.Sprintf("%020d%s", base, segSuffix))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	s.seg = &segment{base: base, size: info.Size(), path: path, mtime: info.ModTime()}
	s.file = f
	return nil
}

// Append writes one record, fsynced. It returns the record offset.
func (s *Store) Append(payload []byte) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrClosed
	}
	if len(payload) == 0 {
		return 0, fmt.Errorf("outbox: empty payload")
	}
	if s.fullLocked(time.Now()) {
		if s.cfg.OnFull == "drop" {
			s.dropped++
			return 0, nil
		}
		return 0, ErrFull
	}
	if s.seg.size > 0 && s.seg.size+int64(len(payload)+recordHeader+recordTrailer) > s.cfg.SegmentBytes {
		if err := s.rotate(s.head); err != nil {
			return 0, err
		}
	}
	offset := s.head
	rec := make([]byte, recordHeader+len(payload)+recordTrailer)
	binary.BigEndian.PutUint32(rec[:recordHeader], uint32(len(payload)))
	copy(rec[recordHeader:], payload)
	binary.BigEndian.PutUint32(
		rec[recordHeader+len(payload):],
		crc32.ChecksumIEEE(payload))
	if _, err := s.file.Write(rec); err != nil {
		return 0, err
	}
	if err := s.file.Sync(); err != nil {
		return 0, err
	}
	s.head += int64(len(rec))
	s.seg.size += int64(len(rec))
	s.records++
	s.bytes += int64(len(rec))
	if s.oldest.IsZero() {
		s.oldest = time.Now()
	}
	return offset, nil
}

func (s *Store) fullLocked(now time.Time) bool {
	if s.cfg.MaxBytes > 0 && s.bytes >= s.cfg.MaxBytes {
		return true
	}
	if s.cfg.MaxRecords > 0 && s.records >= s.cfg.MaxRecords {
		return true
	}
	if s.cfg.MaxAge > 0 && !s.oldest.IsZero() && now.Sub(s.oldest) > s.cfg.MaxAge {
		return true
	}
	return false
}

// Read returns up to maxRecords / maxBytes after from, and the offset to
// resume from (the end of the last returned record).
func (s *Store) Read(from int64, maxRecords, maxBytes int) ([]Record, int64, error) {
	s.mu.Lock()
	segs := append([]segment(nil), s.segmentsCache()...)
	commit := s.commit
	s.mu.Unlock()

	if from < commit {
		from = commit
	}
	var out []Record
	next := from
	bytes := int64(0)
	for _, seg := range segs {
		if seg.base+seg.size <= from {
			continue
		}
		metas, err := scanSegment(seg.path)
		if err != nil {
			return nil, from, err
		}
		f, err := os.Open(seg.path)
		if err != nil {
			return nil, from, err
		}
		for _, m := range metas {
			if m.offset < from {
				continue
			}
			if maxRecords > 0 && len(out) >= maxRecords {
				_ = f.Close()
				return out, next, nil
			}
			if maxBytes > 0 && bytes+m.size > int64(maxBytes) && len(out) > 0 {
				_ = f.Close()
				return out, next, nil
			}
			payload, err := readRecord(f, m, seg.base)
			if err != nil {
				_ = f.Close()
				return nil, from, err
			}
			out = append(out, Record{Offset: m.offset, Payload: payload})
			bytes += m.size
			next = m.offset + m.size
		}
		_ = f.Close()
	}
	return out, next, nil
}

func (s *Store) segmentsCache() []segment {
	segs, _ := s.segments()
	return segs
}

// Commit acknowledges everything before offset: the commit marker moves
// and fully acknowledged segments are removed.
func (s *Store) Commit(offset int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if offset <= s.commit {
		return nil
	}
	if offset > s.head {
		offset = s.head
	}
	// Persist the marker atomically before deleting anything.
	tmp := filepath.Join(s.dir, commitFile+".tmp")
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(offset, 10)), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(s.dir, commitFile)); err != nil {
		return err
	}
	s.commit = offset

	segs, err := s.segments()
	if err != nil {
		return err
	}
	for _, seg := range segs {
		if seg.base+seg.size > offset {
			break
		}
		if s.seg != nil && seg.path == s.seg.path {
			continue
		}
		_ = os.Remove(seg.path)
	}
	// Recompute counters and the oldest pending timestamp.
	return s.recountLocked()
}

func (s *Store) recountLocked() error {
	segs, err := s.segments()
	if err != nil {
		return err
	}
	s.records, s.bytes, s.oldest = 0, 0, time.Time{}
	for _, seg := range segs {
		metas, err := scanSegment(seg.path)
		if err != nil {
			return err
		}
		for _, m := range metas {
			if m.offset < s.commit {
				continue
			}
			s.records++
			s.bytes += m.size
			if s.oldest.IsZero() {
				s.oldest = seg.mtime
			}
		}
	}
	return nil
}

// Head is the next append offset.
func (s *Store) Head() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.head
}

// CommitOffset is the acknowledged offset.
func (s *Store) CommitOffset() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commit
}

// Full reports whether a bound is reached (a new Append would fail in
// block mode). Admission checks it before authorising a request.
func (s *Store) Full() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fullLocked(time.Now())
}

// Stats reports the pending state.
func (s *Store) Stats() (records, bytes int64, oldest time.Time, dropped int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.records, s.bytes, s.oldest, s.dropped
}

// Close releases the current segment.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.file != nil {
		err := s.file.Sync()
		if cerr := s.file.Close(); err == nil {
			err = cerr
		}
		return err
	}
	return nil
}

type meta struct {
	offset int64
	size   int64
}

func scanSegment(path string) ([]meta, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	base := int64(0)
	name := filepath.Base(path)
	if v, err := strconv.ParseInt(strings.TrimSuffix(name, segSuffix), 10, 64); err == nil {
		base = v
	}
	var out []meta
	off := int64(0)
	for off < info.Size() {
		hdr := make([]byte, recordHeader)
		if _, err := f.ReadAt(hdr, off); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		n := int64(binary.BigEndian.Uint32(hdr))
		size := recordHeader + n + recordTrailer
		if n <= 0 || off+size > info.Size() {
			break // torn tail: ignore it
		}
		out = append(out, meta{offset: base + off, size: size})
		off += size
	}
	return out, nil
}

func readRecord(f *os.File, m meta, base int64) ([]byte, error) {
	raw := make([]byte, m.size)
	if _, err := f.ReadAt(raw, m.offset-base); err != nil {
		return nil, err
	}
	payload := raw[recordHeader : len(raw)-recordTrailer]
	want := binary.BigEndian.Uint32(raw[len(raw)-recordTrailer:])
	if crc32.ChecksumIEEE(payload) != want {
		return nil, ErrCorrupt
	}
	return payload, nil
}
