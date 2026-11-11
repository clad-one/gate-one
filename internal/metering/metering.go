// Package metering defines the generic measurement model shared by every
// billable service behind Gate One: a metric describes what is counted, a
// measure records one fact, and a decision fixes the monetary amount.
//
// The model is deliberately service-agnostic: an API call, an LLM token,
// a commission on a sale, a byte transferred or a second of session are
// all (metric, quantity, dimensions) tuples. Nothing here knows about
// plugins, payments or providers.
package metering

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"
)

// Scales allowed for a quantity. 0 = whole units, 3 = milli, 6 = micro.
const (
	ScaleUnits = 0
	ScaleMilli = 3
	ScaleMicro = 6
)

var (
	// ErrInvalidMetric reports a metric definition that cannot be used.
	ErrInvalidMetric = errors.New("metering: invalid metric")
	// ErrInvalidMeasure reports a measure that does not fit its metric.
	ErrInvalidMeasure = errors.New("metering: invalid measure")
	// ErrDimension reports an unknown, missing or malformed dimension.
	ErrDimension = errors.New("metering: dimension")
	// ErrOverflow reports a quantity or amount outside the int64 range.
	ErrOverflow = errors.New("metering: overflow")
)

// DimType is the type of a dimension value.
type DimType string

const (
	// DimString accepts any string up to MaxLength.
	DimString DimType = "string"
	// DimEnum accepts one of Values.
	DimEnum DimType = "enum"
)

// DimSpec declares one allowed dimension of a metric.
type DimSpec struct {
	Type      DimType  `json:"type"`
	MaxLength int      `json:"maxLength,omitempty"`
	Values    []string `json:"values,omitempty"`
}

// Measurement is the cadence at which a metric is measured.
type Measurement string

const (
	// MeasurementEvent is a discrete fact (request, order, seat change).
	MeasurementEvent Measurement = "event"
	// MeasurementPeriodic is a continuous quantity measured by heartbeat
	// (session time, bytes, storage). Each heartbeat records a DELTA
	// since the previous one, never the cumulative total.
	MeasurementPeriodic Measurement = "periodic"
)

// Pricing names the pricing path of a metric.
const (
	// PricingDeclarative uses the core rate table.
	PricingDeclarative = "declarative"
	// PricingPlugin delegates to a signed pricing plugin.
	PricingPlugin = "plugin"
)

// Metric is the definition of one billable quantity.
type Metric struct {
	// Code is the stable identifier used by measures (e.g. "api.request").
	Code string `json:"code"`
	// Unit is a free-form label ("request", "token", "byte", "second").
	Unit string `json:"unit"`
	// Scale is the number of decimals carried by Quantity (0, 3 or 6).
	Scale int `json:"scale"`
	// MaxDimensions caps the number of dimensions accepted per measure.
	MaxDimensions int `json:"maxDimensions"`
	// Dimensions declares the allowed dimension names and their types.
	Dimensions map[string]DimSpec `json:"dimensions,omitempty"`
	// Measurement is "event" (default) or "periodic".
	Measurement Measurement `json:"measurement,omitempty"`
	// HeartbeatSeconds is the emission period of a periodic metric.
	HeartbeatSeconds int `json:"heartbeatSeconds,omitempty"`
	// Pricing is "declarative" (default) or "plugin".
	Pricing string `json:"pricing,omitempty"`
	// Fallback names the declarative tariff used when a plugin pricing is
	// unavailable. Required when Pricing is "plugin".
	Fallback string `json:"fallback,omitempty"`
}

// Normalized returns the metric with defaults applied. It does not
// validate; call Validate afterwards.
func (m Metric) Normalized() Metric {
	if m.Measurement == "" {
		m.Measurement = MeasurementEvent
	}
	if m.Pricing == "" {
		m.Pricing = PricingDeclarative
	}
	if m.Measurement == MeasurementPeriodic && m.HeartbeatSeconds == 0 {
		m.HeartbeatSeconds = 60
	}
	return m
}

// Validate checks a metric definition.
func (m Metric) Validate() error {
	if strings.TrimSpace(m.Code) == "" {
		return fmt.Errorf("%w: code is required", ErrInvalidMetric)
	}
	if strings.TrimSpace(m.Unit) == "" {
		return fmt.Errorf("%w: %s: unit is required", ErrInvalidMetric, m.Code)
	}
	switch m.Scale {
	case ScaleUnits, ScaleMilli, ScaleMicro:
	default:
		return fmt.Errorf(
			"%w: %s: scale must be 0, 3 or 6 (got %d)",
			ErrInvalidMetric, m.Code, m.Scale)
	}
	if m.MaxDimensions < 0 {
		return fmt.Errorf(
			"%w: %s: maxDimensions must be >= 0", ErrInvalidMetric, m.Code)
	}
	if m.MaxDimensions > len(m.Dimensions) {
		return fmt.Errorf(
			"%w: %s: maxDimensions (%d) exceeds the %d declared dimension(s)",
			ErrInvalidMetric, m.Code, m.MaxDimensions, len(m.Dimensions))
	}
	for name, spec := range m.Dimensions {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf(
				"%w: %s: empty dimension name", ErrInvalidMetric, m.Code)
		}
		switch spec.Type {
		case DimString:
		case DimEnum:
			if len(spec.Values) == 0 {
				return fmt.Errorf(
					"%w: %s: dimension %q is an enum without values",
					ErrInvalidMetric, m.Code, name)
			}
		default:
			return fmt.Errorf(
				"%w: %s: dimension %q has unknown type %q",
				ErrInvalidMetric, m.Code, name, spec.Type)
		}
	}
	switch m.Measurement {
	case MeasurementEvent, MeasurementPeriodic:
	default:
		return fmt.Errorf(
			"%w: %s: measurement must be event or periodic",
			ErrInvalidMetric, m.Code)
	}
	if m.Measurement == MeasurementPeriodic {
		if m.HeartbeatSeconds < 10 || m.HeartbeatSeconds > 3600 {
			return fmt.Errorf(
				"%w: %s: heartbeatSeconds must be 10..3600",
				ErrInvalidMetric, m.Code)
		}
	}
	switch m.Pricing {
	case PricingDeclarative:
		if m.Fallback != "" {
			return fmt.Errorf(
				"%w: %s: fallback is only valid with pricing=plugin",
				ErrInvalidMetric, m.Code)
		}
	case PricingPlugin:
		if strings.TrimSpace(m.Fallback) == "" {
			return fmt.Errorf(
				"%w: %s: pricing=plugin requires a declarative fallback",
				ErrInvalidMetric, m.Code)
		}
	default:
		return fmt.Errorf(
			"%w: %s: pricing must be declarative or plugin",
			ErrInvalidMetric, m.Code)
	}
	return nil
}

// Measure is one recorded fact. Quantity carries Scale decimals from the
// metric: quantity=1500 with scale=3 means 1.5 units.
type Measure struct {
	Tenant      string            `json:"tenant"`
	Metric      string            `json:"metric"`
	Quantity    int64             `json:"quantity"`
	Dimensions  map[string]string `json:"dimensions,omitempty"`
	Idempotency string            `json:"idempotencyKey"`
	At          time.Time         `json:"at"`
	RequestID   string            `json:"requestId,omitempty"`
}

// ValidateFor checks a measure against its metric.
func (m Measure) ValidateFor(metric Metric) error {
	if strings.TrimSpace(m.Tenant) == "" {
		return fmt.Errorf("%w: tenant is required", ErrInvalidMeasure)
	}
	if m.Metric != metric.Code {
		return fmt.Errorf(
			"%w: metric %q does not match %q",
			ErrInvalidMeasure, m.Metric, metric.Code)
	}
	if m.Quantity < 0 {
		return fmt.Errorf("%w: negative quantity", ErrInvalidMeasure)
	}
	if strings.TrimSpace(m.Idempotency) == "" {
		return fmt.Errorf("%w: idempotencyKey is required", ErrInvalidMeasure)
	}
	if m.At.IsZero() {
		return fmt.Errorf("%w: at is required", ErrInvalidMeasure)
	}
	if len(m.Dimensions) > metric.MaxDimensions {
		return fmt.Errorf(
			"%w: %s: %d dimensions given, max %d",
			ErrDimension, metric.Code, len(m.Dimensions), metric.MaxDimensions)
	}
	for name, value := range m.Dimensions {
		spec, ok := metric.Dimensions[name]
		if !ok {
			return fmt.Errorf(
				"%w: %s: unknown dimension %q", ErrDimension, metric.Code, name)
		}
		switch spec.Type {
		case DimEnum:
			if !contains(spec.Values, value) {
				return fmt.Errorf(
					"%w: %s: dimension %q value %q is not allowed",
					ErrDimension, metric.Code, name, value)
			}
		case DimString:
			if spec.MaxLength > 0 && len(value) > spec.MaxLength {
				return fmt.Errorf(
					"%w: %s: dimension %q exceeds %d bytes",
					ErrDimension, metric.Code, name, spec.MaxLength)
			}
		}
	}
	return nil
}

// Decision is the priced outcome of one measure (or of a price quote).
// AmountMicro is an integer in micro-units of Currency.
type Decision struct {
	AmountMicro   int64          `json:"amountMicro"`
	Currency      string         `json:"currency"`
	PriceVersion  string         `json:"priceVersion"`
	EngineVersion string         `json:"engineVersion"`
	InputsHash    string         `json:"inputsHash"`
	Inputs        map[string]any `json:"inputs,omitempty"`
	ExpiresAt     time.Time      `json:"expiresAt,omitempty"`
	Signature     []byte         `json:"signature,omitempty"`
}

// InputsHash is the canonical sha256 of a decision's inputs.
func InputsHash(inputs map[string]any) (string, error) {
	raw, err := json.Marshal(inputs)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Pow10 returns 10^n as an int64, refusing out-of-range values.
func Pow10(n int) (int64, error) {
	if n < 0 || n > 18 {
		return 0, fmt.Errorf("%w: invalid power %d", ErrOverflow, n)
	}
	v := int64(1)
	for i := 0; i < n; i++ {
		v *= 10
	}
	return v, nil
}

// MulDivRound computes quantity*price/10^scale, rounding half-up when
// roundUp is false and up when it is true (holds must never under-reserve).
func MulDivRound(quantity, price int64, scale int, roundUp bool) (int64, error) {
	if quantity < 0 || price < 0 {
		return 0, fmt.Errorf("%w: negative operand", ErrOverflow)
	}
	num := new(big.Int).Mul(big.NewInt(quantity), big.NewInt(price))
	den, err := Pow10(scale)
	if err != nil {
		return 0, err
	}
	return divRound(num, big.NewInt(den), roundUp)
}

// PercentRound computes base*basisPoints/10000, rounded half-up.
func PercentRound(base, basisPoints int64) (int64, error) {
	if base < 0 || basisPoints < 0 {
		return 0, fmt.Errorf("%w: negative operand", ErrOverflow)
	}
	num := new(big.Int).Mul(big.NewInt(base), big.NewInt(basisPoints))
	return divRound(num, big.NewInt(10000), false)
}

func divRound(num, den *big.Int, roundUp bool) (int64, error) {
	if den.Sign() == 0 {
		return 0, fmt.Errorf("%w: zero divisor", ErrOverflow)
	}
	q, r := new(big.Int), new(big.Int)
	q.QuoRem(num, den, r)
	if r.Sign() > 0 {
		if roundUp {
			q.Add(q, big.NewInt(1))
		} else {
			twice := new(big.Int).Lsh(r, 1)
			if twice.Cmp(den) >= 0 {
				q.Add(q, big.NewInt(1))
			}
		}
	}
	if !q.IsInt64() {
		return 0, fmt.Errorf("%w: result does not fit int64", ErrOverflow)
	}
	return q.Int64(), nil
}

// Canonical returns the deterministic JSON used for signing and hashing.
func Canonical(v any) ([]byte, error) {
	return json.Marshal(v)
}

// SortStrings returns a sorted copy (deterministic snapshots).
func SortStrings(in map[string]string) []string {
	out := make([]string, 0, len(in))
	for k := range in {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
