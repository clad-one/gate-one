// Package pricing implements the declarative rate table of the core: a
// pure function from (measure, tariff version) to a monetary decision.
//
// It deliberately knows nothing about plugins, payments or providers: a
// plugin may REPLACE the computation (Lot 5), but the core stays
// auditable with these models only.
package pricing

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"cladone/gate-one/internal/metering"
)

// Model is a charge model.
type Model string

const (
	// ModelUnit charges quantity * amount per unit.
	ModelUnit Model = "unit"
	// ModelTiered applies each range to the portion inside it (graduated).
	ModelTiered Model = "tiered"
	// ModelVolume applies the range containing the total to the whole.
	ModelVolume Model = "volume"
	// ModelPackage bills whole packages.
	ModelPackage Model = "package"
	// ModelPercentageOf applies a basis-point rate to the measure quantity
	// (the base amount, in currency minor units) plus a fixed amount.
	ModelPercentageOf Model = "percentage_of"
)

// EngineVersion identifies the declarative engine in a decision.
const EngineVersion = "declarative@v1"

var (
	ErrInvalidTariff = errors.New("pricing: invalid tariff")
	ErrNoTariff      = errors.New("pricing: no tariff in effect")
	ErrNoCharge      = errors.New("pricing: no charge matches the measure")
	ErrUnknownMetric = errors.New("pricing: unknown metric")
)

// Tier is one range of a tiered or volume model. Values are expressed in
// the metric's scaled quantity (ToValue < 0 means unbounded).
type Tier struct {
	FromValue  int64 `json:"fromValue"`
	ToValue    int64 `json:"toValue"`
	PerUnitMi  int64 `json:"perUnitMicro"`
	FlatAmount int64 `json:"flatAmountMicro,omitempty"`
}

// Charge is one priced rule of a tariff.
type Charge struct {
	Model Model `json:"model"`
	// AmountMicro is the unit price for ModelUnit and ModelPackage.
	AmountMicro int64 `json:"amountMicro,omitempty"`
	// Filter restricts the charge to dimension values; "*" matches any.
	Filter map[string][]string `json:"filter,omitempty"`
	// Tiers for ModelTiered and ModelVolume.
	Tiers []Tier `json:"tiers,omitempty"`
	// PackageSize and FreeUnits are in the metric's scaled quantity.
	PackageSize int64 `json:"packageSize,omitempty"`
	FreeUnits   int64 `json:"freeUnits,omitempty"`
	// RateBasisPoints and FixedAmountMicro for ModelPercentageOf
	// (1 basis point = 0.01 %).
	RateBasisPoints int64 `json:"rateBasisPoints,omitempty"`
	FixedAmount     int64 `json:"fixedAmountMicro,omitempty"`
}

// Tariff is a versioned rate table for one metric.
type Tariff struct {
	Version       string    `json:"version"`
	Currency      string    `json:"currency"`
	EffectiveFrom time.Time `json:"effectiveFrom"`
	Charges       []Charge  `json:"charges"`
}

// Validate checks a tariff definition.
func (t Tariff) Validate() error {
	if strings.TrimSpace(t.Version) == "" {
		return fmt.Errorf("%w: version is required", ErrInvalidTariff)
	}
	if len(t.Currency) != 3 {
		return fmt.Errorf(
			"%w: %s: currency must be a 3-letter code", ErrInvalidTariff, t.Version)
	}
	if t.EffectiveFrom.IsZero() {
		return fmt.Errorf(
			"%w: %s: effectiveFrom is required", ErrInvalidTariff, t.Version)
	}
	if len(t.Charges) == 0 {
		return fmt.Errorf(
			"%w: %s: at least one charge is required", ErrInvalidTariff, t.Version)
	}
	for i, c := range t.Charges {
		switch c.Model {
		case ModelUnit:
			if c.AmountMicro < 0 {
				return fmt.Errorf(
					"%w: %s: charges[%d]: negative amount", ErrInvalidTariff, t.Version, i)
			}
		case ModelTiered, ModelVolume:
			if len(c.Tiers) == 0 {
				return fmt.Errorf(
					"%w: %s: charges[%d]: tiers are required", ErrInvalidTariff, t.Version, i)
			}
			prevTo := int64(-1)
			for j, tier := range c.Tiers {
				if tier.FromValue < 0 || tier.PerUnitMi < 0 || tier.FlatAmount < 0 {
					return fmt.Errorf(
						"%w: %s: charges[%d].tiers[%d]: negative value",
						ErrInvalidTariff, t.Version, i, j)
				}
				if j > 0 {
					// Ranges are [from, to): the next range starts where
					// the previous one ends. A tier after an unbounded one
					// (toValue < 0) is unreachable.
					if prevTo < 0 || tier.FromValue < prevTo {
						return fmt.Errorf(
							"%w: %s: charges[%d].tiers[%d]: ranges must increase",
							ErrInvalidTariff, t.Version, i, j)
					}
				}
				if tier.ToValue >= 0 && tier.ToValue < tier.FromValue {
					return fmt.Errorf(
						"%w: %s: charges[%d].tiers[%d]: toValue < fromValue",
						ErrInvalidTariff, t.Version, i, j)
				}
				prevTo = tier.ToValue
			}
		case ModelPackage:
			if c.PackageSize <= 0 {
				return fmt.Errorf(
					"%w: %s: charges[%d]: packageSize must be > 0",
					ErrInvalidTariff, t.Version, i)
			}
		case ModelPercentageOf:
			if c.RateBasisPoints < 0 {
				return fmt.Errorf(
					"%w: %s: charges[%d]: negative rate", ErrInvalidTariff, t.Version, i)
			}
		default:
			return fmt.Errorf(
				"%w: %s: charges[%d]: unknown model %q",
				ErrInvalidTariff, t.Version, i, c.Model)
		}
	}
	return nil
}

// Registry holds metrics and their tariffs.
type Registry struct {
	metrics map[string]metering.Metric
	tariffs map[string][]Tariff
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{
		metrics: map[string]metering.Metric{},
		tariffs: map[string][]Tariff{},
	}
}

// AddMetric registers a metric (validated, normalized).
func (r *Registry) AddMetric(m metering.Metric) error {
	m = m.Normalized()
	if err := m.Validate(); err != nil {
		return err
	}
	if _, exists := r.metrics[m.Code]; exists {
		return fmt.Errorf("%w: duplicate metric %q", metering.ErrInvalidMetric, m.Code)
	}
	r.metrics[m.Code] = m
	return nil
}

// AddTariff registers a tariff version for a metric.
func (r *Registry) AddTariff(metric string, t Tariff) error {
	if _, ok := r.metrics[metric]; !ok {
		return fmt.Errorf("%w: %q", ErrUnknownMetric, metric)
	}
	if err := t.Validate(); err != nil {
		return err
	}
	for _, existing := range r.tariffs[metric] {
		if existing.Version == t.Version {
			return fmt.Errorf(
				"%w: duplicate tariff %q for %q", ErrInvalidTariff, t.Version, metric)
		}
	}
	list := append(r.tariffs[metric], t)
	sort.Slice(list, func(i, j int) bool {
		return list[i].EffectiveFrom.Before(list[j].EffectiveFrom)
	})
	r.tariffs[metric] = list
	return nil
}

// Metric returns a metric definition.
func (r *Registry) Metric(code string) (metering.Metric, bool) {
	m, ok := r.metrics[code]
	return m, ok
}

// TariffInEffect returns the newest tariff whose EffectiveFrom is <= at.
func (r *Registry) TariffInEffect(metric string, at time.Time) (Tariff, bool) {
	var found Tariff
	ok := false
	for _, t := range r.tariffs[metric] {
		if t.EffectiveFrom.After(at) {
			break
		}
		found, ok = t, true
	}
	return found, ok
}

// Rate prices one measure. It is pure: no I/O, no clock, no state.
func (r *Registry) Rate(m metering.Measure) (metering.Decision, error) {
	metric, ok := r.metrics[m.Metric]
	if !ok {
		return metering.Decision{}, fmt.Errorf(
			"%w: %q", ErrUnknownMetric, m.Metric)
	}
	if err := m.ValidateFor(metric); err != nil {
		return metering.Decision{}, err
	}
	tariff, ok := r.TariffInEffect(m.Metric, m.At)
	if !ok {
		return metering.Decision{}, fmt.Errorf(
			"%w: %s at %s", ErrNoTariff, m.Metric,
			m.At.UTC().Format(time.RFC3339))
	}
	for i, c := range tariff.Charges {
		if !chargeMatches(c, m.Dimensions) {
			continue
		}
		amount, err := amountFor(c, metric, m)
		if err != nil {
			return metering.Decision{}, err
		}
		inputs := map[string]any{
			"metric":      m.Metric,
			"quantity":    m.Quantity,
			"scale":       metric.Scale,
			"dimensions":  m.Dimensions,
			"tariff":      tariff.Version,
			"effectiveAt": tariff.EffectiveFrom.UTC().Format(time.RFC3339),
			"charge":      i,
			"model":       string(c.Model),
			"engine":      EngineVersion,
		}
		hash, err := metering.InputsHash(inputs)
		if err != nil {
			return metering.Decision{}, err
		}
		return metering.Decision{
			AmountMicro:   amount,
			Currency:      tariff.Currency,
			PriceVersion:  tariff.Version,
			EngineVersion: EngineVersion,
			InputsHash:    hash,
			Inputs:        inputs,
		}, nil
	}
	return metering.Decision{}, fmt.Errorf(
		"%w: %s (tariff %s)", ErrNoCharge, m.Metric, tariff.Version)
}

func chargeMatches(c Charge, dims map[string]string) bool {
	for name, allowed := range c.Filter {
		if len(allowed) == 0 {
			continue
		}
		value, ok := dims[name]
		if !ok {
			return false
		}
		if !matchOne(allowed, value) {
			return false
		}
	}
	return true
}

func matchOne(allowed []string, value string) bool {
	for _, a := range allowed {
		if a == "*" || a == value {
			return true
		}
	}
	return false
}

// amountFor computes the amount in micro-units. All accumulation is done
// in big.Int and rounded exactly once.
func amountFor(c Charge, metric metering.Metric, m metering.Measure) (int64, error) {
	qty := m.Quantity
	switch c.Model {
	case ModelUnit:
		if qty <= c.FreeUnits {
			return 0, nil
		}
		num := new(big.Int).Mul(
			big.NewInt(qty-c.FreeUnits), big.NewInt(c.AmountMicro))
		return roundScaled(num, metric.Scale)
	case ModelTiered:
		num := new(big.Int)
		for _, t := range c.Tiers {
			portion := overlap(qty, t.FromValue, t.ToValue)
			if portion <= 0 {
				continue
			}
			num.Add(num, new(big.Int).Mul(
				big.NewInt(portion), big.NewInt(t.PerUnitMi)))
			if t.FlatAmount > 0 {
				num.Add(num, flatNumerator(t.FlatAmount, metric.Scale))
			}
		}
		return roundScaled(num, metric.Scale)
	case ModelVolume:
		for _, t := range c.Tiers {
			if qty < t.FromValue {
				continue
			}
			if t.ToValue >= 0 && qty > t.ToValue {
				continue
			}
			num := new(big.Int).Mul(big.NewInt(qty), big.NewInt(t.PerUnitMi))
			num.Add(num, flatNumerator(t.FlatAmount, metric.Scale))
			return roundScaled(num, metric.Scale)
		}
		return 0, nil
	case ModelPackage:
		billable := qty - c.FreeUnits
		if billable <= 0 {
			return 0, nil
		}
		packages := (billable + c.PackageSize - 1) / c.PackageSize
		num := new(big.Int).Mul(
			big.NewInt(packages), big.NewInt(c.AmountMicro))
		return roundScaled(num, metric.Scale)
	case ModelPercentageOf:
		amount, err := metering.PercentRound(qty, c.RateBasisPoints)
		if err != nil {
			return 0, err
		}
		return amount + c.FixedAmount, nil
	default:
		return 0, fmt.Errorf("%w: model %q", ErrInvalidTariff, c.Model)
	}
}

func overlap(qty, from, to int64) int64 {
	if qty <= from {
		return 0
	}
	end := qty
	if to >= 0 && to < end {
		end = to
	}
	if end <= from {
		return 0
	}
	return end - from
}

// flatNumerator converts a flat amount (in micro) to the common numerator
// denominator 10^scale so it can be summed with per-unit terms.
func flatNumerator(flatMicro int64, scale int) *big.Int {
	pow, err := metering.Pow10(scale)
	if err != nil {
		return big.NewInt(flatMicro)
	}
	return new(big.Int).Mul(big.NewInt(flatMicro), big.NewInt(pow))
}

// roundScaled divides a numerator by 10^scale, rounding half-up.
func roundScaled(num *big.Int, scale int) (int64, error) {
	pow, err := metering.Pow10(scale)
	if err != nil {
		return 0, err
	}
	den := big.NewInt(pow)
	q, r := new(big.Int), new(big.Int)
	q.QuoRem(num, den, r)
	if r.Sign() > 0 {
		twice := new(big.Int).Lsh(r, 1)
		if twice.Cmp(den) >= 0 {
			q.Add(q, big.NewInt(1))
		}
	}
	if !q.IsInt64() {
		return 0, fmt.Errorf("%w: amount does not fit int64", metering.ErrOverflow)
	}
	return q.Int64(), nil
}
