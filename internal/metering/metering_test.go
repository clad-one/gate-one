package metering

import (
	"errors"
	"math"
	"testing"
	"time"
)

func testMetric() Metric {
	return Metric{
		Code:          "session.second",
		Unit:          "second",
		Scale:         ScaleMilli,
		MaxDimensions: 2,
		Dimensions: map[string]DimSpec{
			"app":    {Type: DimString, MaxLength: 64},
			"region": {Type: DimEnum, Values: []string{"eu", "us"}},
		},
		Measurement:      MeasurementPeriodic,
		HeartbeatSeconds: 60,
		Pricing:          PricingDeclarative,
	}
}

func TestMetricValidate(t *testing.T) {
	if err := testMetric().Validate(); err != nil {
		t.Fatalf("valid metric rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Metric)
	}{
		{"scale", func(m *Metric) { m.Scale = 4 }},
		{"unit", func(m *Metric) { m.Unit = " " }},
		{"code", func(m *Metric) { m.Code = "" }},
		{"maxDimensions", func(m *Metric) { m.MaxDimensions = 5 }},
		{"heartbeat low", func(m *Metric) { m.HeartbeatSeconds = 1 }},
		{"heartbeat high", func(m *Metric) { m.HeartbeatSeconds = 7200 }},
		{"enum without values", func(m *Metric) {
			m.Dimensions["region"] = DimSpec{Type: DimEnum}
		}},
		{"unknown dim type", func(m *Metric) {
			m.Dimensions["x"] = DimSpec{Type: "number"}
		}},
		{"plugin without fallback", func(m *Metric) {
			m.Pricing = PricingPlugin
		}},
		{"fallback on declarative", func(m *Metric) {
			m.Fallback = "x"
		}},
	}
	for _, c := range cases {
		m := testMetric()
		c.mutate(&m)
		if err := m.Validate(); err == nil {
			t.Errorf("%s: expected an error", c.name)
		}
	}

	m := testMetric()
	m.Pricing = PricingPlugin
	m.Fallback = "session.ceiling"
	if err := m.Validate(); err != nil {
		t.Fatalf("plugin with fallback rejected: %v", err)
	}
}

func TestMetricNormalizedDefaults(t *testing.T) {
	m := Metric{Code: "api.request", Unit: "request", Scale: 0}.Normalized()
	if m.Measurement != MeasurementEvent {
		t.Errorf("measurement = %q", m.Measurement)
	}
	if m.Pricing != PricingDeclarative {
		t.Errorf("pricing = %q", m.Pricing)
	}
	p := Metric{Code: "s", Unit: "second", Measurement: MeasurementPeriodic}.Normalized()
	if p.HeartbeatSeconds != 60 {
		t.Errorf("heartbeat = %d", p.HeartbeatSeconds)
	}
}

func TestMeasureValidate(t *testing.T) {
	metric := testMetric()
	good := Measure{
		Tenant: "company", Metric: metric.Code, Quantity: 1500,
		Dimensions:  map[string]string{"app": "ves", "region": "eu"},
		Idempotency: "req-1", At: time.Now(),
	}
	if err := good.ValidateFor(metric); err != nil {
		t.Fatalf("valid measure rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*Measure)
	}{
		{"tenant", func(m *Measure) { m.Tenant = "" }},
		{"idempotency", func(m *Measure) { m.Idempotency = "" }},
		{"at", func(m *Measure) { m.At = time.Time{} }},
		{"negative", func(m *Measure) { m.Quantity = -1 }},
		{"unknown dim", func(m *Measure) { m.Dimensions = map[string]string{"nope": "x"} }},
		{"bad enum", func(m *Measure) { m.Dimensions = map[string]string{"region": "mars"} }},
		{"too many", func(m *Measure) {
			m.Dimensions = map[string]string{"app": "a", "region": "eu", "x": "y"}
		}},
		{"too long", func(m *Measure) {
			m.Dimensions = map[string]string{"app": string(make([]byte, 65))}
		}},
	}
	for _, c := range cases {
		m := good
		c.mutate(&m)
		if err := m.ValidateFor(metric); err == nil {
			t.Errorf("%s: expected an error", c.name)
		}
	}
}

func TestMulDivRound(t *testing.T) {
	cases := []struct {
		qty, price int64
		scale      int
		up         bool
		want       int64
	}{
		{1, 1200, 0, false, 1200},
		{1500, 800, 3, false, 1200}, // 1.5 × 800
		{1, 4, 1, false, 0},         // 0.4 → 0
		{1, 5, 1, false, 1},         // 0.5 → 1 (half-up)
		{1, 4, 1, true, 1},          // ceil for holds
		{1, 1, 1, true, 1},
	}
	for _, c := range cases {
		got, err := MulDivRound(c.qty, c.price, c.scale, c.up)
		if err != nil {
			t.Fatalf("%d×%d/10^%d: %v", c.qty, c.price, c.scale, err)
		}
		if got != c.want {
			t.Errorf("%d×%d/10^%d (up=%v) = %d, want %d",
				c.qty, c.price, c.scale, c.up, got, c.want)
		}
	}
	if _, err := MulDivRound(math.MaxInt64, 1_000_000, 0, false); !errors.Is(err, ErrOverflow) {
		t.Fatalf("expected overflow, got %v", err)
	}
}

func TestPercentRound(t *testing.T) {
	got, err := PercentRound(2900, 200) // 2 % of 29,00 €
	if err != nil {
		t.Fatal(err)
	}
	if got != 58 {
		t.Fatalf("2%% of 2900 = %d, want 58", got)
	}
}

func TestInputsHashDeterministic(t *testing.T) {
	a, err := InputsHash(map[string]any{"b": 2, "a": 1})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := InputsHash(map[string]any{"a": 1, "b": 2})
	if a != b {
		t.Fatalf("hash not deterministic: %s != %s", a, b)
	}
}
