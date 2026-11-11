package pricing

import (
	"errors"
	"math"
	"testing"
	"time"

	"cladone/gate-one/internal/metering"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func registry(t *testing.T) *Registry {
	t.Helper()
	r := NewRegistry()
	metrics := []metering.Metric{
		{Code: "api.request", Unit: "request", Scale: 0, MaxDimensions: 2,
			Dimensions: map[string]metering.DimSpec{
				"route":  {Type: metering.DimString, MaxLength: 128},
				"method": {Type: metering.DimEnum, Values: []string{"GET", "POST"}},
			}},
		{Code: "session.second", Unit: "second", Scale: 3, MaxDimensions: 0,
			Measurement: metering.MeasurementPeriodic, HeartbeatSeconds: 60},
		{Code: "sale.gmv", Unit: "cent", Scale: 0, MaxDimensions: 0},
	}
	for _, m := range metrics {
		if err := r.AddMetric(m); err != nil {
			t.Fatal(err)
		}
	}
	tariffs := map[string]Tariff{
		"api.request": {
			Version: "api.request.v1", Currency: "EUR",
			EffectiveFrom: at("2026-01-01T00:00:00Z"),
			Charges:       []Charge{{Model: ModelUnit, AmountMicro: 1200}},
		},
		"session.second": {
			Version: "session.v1", Currency: "EUR",
			EffectiveFrom: at("2026-01-01T00:00:00Z"),
			Charges:       []Charge{{Model: ModelUnit, AmountMicro: 500}},
		},
		"sale.gmv": {
			Version: "sale.v1", Currency: "EUR",
			EffectiveFrom: at("2026-01-01T00:00:00Z"),
			Charges: []Charge{{
				Model: ModelPercentageOf, RateBasisPoints: 200,
				FixedAmount: 0,
			}},
		},
	}
	for metric, tf := range tariffs {
		if err := r.AddTariff(metric, tf); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func measure(metric string, qty int64, dims map[string]string) metering.Measure {
	return metering.Measure{
		Tenant: "company", Metric: metric, Quantity: qty, Dimensions: dims,
		Idempotency: "k-" + metric, At: at("2026-03-01T10:00:00Z"),
	}
}

func TestRateUnit(t *testing.T) {
	r := registry(t)
	d, err := r.Rate(measure("api.request", 1, map[string]string{"route": "/x", "method": "GET"}))
	if err != nil {
		t.Fatal(err)
	}
	if d.AmountMicro != 1200 || d.Currency != "EUR" {
		t.Fatalf("decision = %+v", d)
	}
	if d.PriceVersion != "api.request.v1" || d.EngineVersion != EngineVersion {
		t.Fatalf("versions = %+v", d)
	}
	if d.InputsHash == "" || d.Inputs["metric"] != "api.request" {
		t.Fatalf("inputs = %+v", d.Inputs)
	}
}

func TestRateScaledQuantity(t *testing.T) {
	r := registry(t)
	// 1.5 seconde × 500 µ€/s = 750 µ€
	d, err := r.Rate(measure("session.second", 1500, nil))
	if err != nil {
		t.Fatal(err)
	}
	if d.AmountMicro != 750 {
		t.Fatalf("amount = %d, want 750", d.AmountMicro)
	}
}

func TestRatePercentageOf(t *testing.T) {
	r := registry(t)
	d, err := r.Rate(measure("sale.gmv", 2900, nil)) // 29,00 €
	if err != nil {
		t.Fatal(err)
	}
	if d.AmountMicro != 58 {
		t.Fatalf("amount = %d, want 58", d.AmountMicro)
	}
}

func TestRateTiered(t *testing.T) {
	r := NewRegistry()
	if err := r.AddMetric(metering.Metric{
		Code: "storage", Unit: "gbyte_hour", Scale: 3,
	}); err != nil {
		t.Fatal(err)
	}
	err := r.AddTariff("storage", Tariff{
		Version: "tiered", Currency: "EUR",
		EffectiveFrom: at("2026-01-01T00:00:00Z"),
		Charges: []Charge{{Model: ModelTiered, Tiers: []Tier{
			{FromValue: 0, ToValue: 10_000, PerUnitMi: 100},
			{FromValue: 10_000, ToValue: -1, PerUnitMi: 50},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// 15 unités (15000 en milli) : 10 × 100 + 5 × 50 = 1250.
	d, err := r.Rate(measure("storage", 15_000, nil))
	if err != nil {
		t.Fatal(err)
	}
	if d.AmountMicro != 1250 {
		t.Fatalf("tiered = %d, want 1250", d.AmountMicro)
	}
}

func TestRateVolume(t *testing.T) {
	r := NewRegistry()
	if err := r.AddMetric(metering.Metric{
		Code: "storage", Unit: "gbyte_hour", Scale: 3,
	}); err != nil {
		t.Fatal(err)
	}
	err := r.AddTariff("storage", Tariff{
		Version: "volume", Currency: "EUR",
		EffectiveFrom: at("2026-01-01T00:00:00Z"),
		Charges: []Charge{{Model: ModelVolume, Tiers: []Tier{
			{FromValue: 0, ToValue: 10_000, PerUnitMi: 100},
			{FromValue: 10_000, ToValue: -1, PerUnitMi: 50},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// La tranche contenant le total s'applique à tout : 15 × 50 = 750.
	d, err := r.Rate(measure("storage", 15_000, nil))
	if err != nil {
		t.Fatal(err)
	}
	if d.AmountMicro != 750 {
		t.Fatalf("volume = %d, want 750", d.AmountMicro)
	}
}

func TestRatePackage(t *testing.T) {
	r := NewRegistry()
	if err := r.AddMetric(metering.Metric{Code: "mcp.call", Unit: "call", Scale: 0}); err != nil {
		t.Fatal(err)
	}
	if err := r.AddTariff("mcp.call", Tariff{
		Version: "pkg", Currency: "EUR", EffectiveFrom: at("2026-01-01T00:00:00Z"),
		Charges: []Charge{{
			Model: ModelPackage, AmountMicro: 1200,
			PackageSize: 100, FreeUnits: 10,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	// 250 appels, 10 offerts → 240 → 3 paquets à 1200.
	d, err := r.Rate(measure("mcp.call", 250, nil))
	if err != nil {
		t.Fatal(err)
	}
	if d.AmountMicro != 3600 {
		t.Fatalf("amount = %d, want 3600", d.AmountMicro)
	}
}

func TestTariffSelectionByEffectiveDate(t *testing.T) {
	r := NewRegistry()
	if err := r.AddMetric(metering.Metric{Code: "m", Unit: "u", Scale: 0}); err != nil {
		t.Fatal(err)
	}
	for _, tf := range []Tariff{
		{Version: "v1", Currency: "EUR", EffectiveFrom: at("2026-01-01T00:00:00Z"),
			Charges: []Charge{{Model: ModelUnit, AmountMicro: 100}}},
		{Version: "v2", Currency: "EUR", EffectiveFrom: at("2026-06-01T00:00:00Z"),
			Charges: []Charge{{Model: ModelUnit, AmountMicro: 200}}},
	} {
		if err := r.AddTariff("m", tf); err != nil {
			t.Fatal(err)
		}
	}
	d, err := r.Rate(measure("m", 1, nil)) // 2026-03
	if err != nil {
		t.Fatal(err)
	}
	if d.PriceVersion != "v1" {
		t.Fatalf("version = %s, want v1", d.PriceVersion)
	}
	m := measure("m", 1, nil)
	m.At = at("2026-07-01T00:00:00Z")
	d, err = r.Rate(m)
	if err != nil {
		t.Fatal(err)
	}
	if d.PriceVersion != "v2" || d.AmountMicro != 200 {
		t.Fatalf("decision = %+v", d)
	}
}

func TestChargeFilter(t *testing.T) {
	r := NewRegistry()
	if err := r.AddMetric(metering.Metric{
		Code: "llm", Unit: "token", Scale: 0, MaxDimensions: 1,
		Dimensions: map[string]metering.DimSpec{
			"model": {Type: metering.DimString, MaxLength: 32},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.AddTariff("llm", Tariff{
		Version: "llm.v1", Currency: "EUR", EffectiveFrom: at("2026-01-01T00:00:00Z"),
		Charges: []Charge{
			{Model: ModelUnit, AmountMicro: 1000,
				Filter: map[string][]string{"model": {"small"}}},
			{Model: ModelUnit, AmountMicro: 9000},
		},
	}); err != nil {
		t.Fatal(err)
	}
	d, _ := r.Rate(measure("llm", 1, map[string]string{"model": "small"}))
	if d.AmountMicro != 1000 {
		t.Fatalf("small = %d", d.AmountMicro)
	}
	d, _ = r.Rate(measure("llm", 1, map[string]string{"model": "big"}))
	if d.AmountMicro != 9000 {
		t.Fatalf("big = %d", d.AmountMicro)
	}
}

func TestRateErrors(t *testing.T) {
	r := registry(t)
	if _, err := r.Rate(measure("nope", 1, nil)); !errors.Is(err, ErrUnknownMetric) {
		t.Fatalf("unknown metric: %v", err)
	}
	m := measure("api.request", 1, map[string]string{"route": "/x", "method": "GET"})
	m.At = at("2025-01-01T00:00:00Z")
	if _, err := r.Rate(m); !errors.Is(err, ErrNoTariff) {
		t.Fatalf("no tariff: %v", err)
	}
	// Dimension non déclarée : rejet avant le calcul.
	if _, err := r.Rate(measure("api.request", 1, map[string]string{"zzz": "x"})); err == nil {
		t.Fatal("expected a dimension error")
	}
}

func TestRateOverflow(t *testing.T) {
	r := NewRegistry()
	if err := r.AddMetric(metering.Metric{Code: "m", Unit: "u", Scale: 0}); err != nil {
		t.Fatal(err)
	}
	if err := r.AddTariff("m", Tariff{
		Version: "v", Currency: "EUR", EffectiveFrom: at("2026-01-01T00:00:00Z"),
		Charges: []Charge{{Model: ModelUnit, AmountMicro: math.MaxInt64}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Rate(measure("m", math.MaxInt64, nil)); err == nil {
		t.Fatal("expected an overflow error")
	}
}

func TestTariffValidate(t *testing.T) {
	bad := []Tariff{
		{Currency: "EUR", EffectiveFrom: at("2026-01-01T00:00:00Z")},
		{Version: "v", Currency: "EURO", EffectiveFrom: at("2026-01-01T00:00:00Z")},
		{Version: "v", Currency: "EUR"},
		{Version: "v", Currency: "EUR", EffectiveFrom: at("2026-01-01T00:00:00Z")},
		{Version: "v", Currency: "EUR", EffectiveFrom: at("2026-01-01T00:00:00Z"),
			Charges: []Charge{{Model: "wat"}}},
		{Version: "v", Currency: "EUR", EffectiveFrom: at("2026-01-01T00:00:00Z"),
			Charges: []Charge{{Model: ModelTiered}}},
		{Version: "v", Currency: "EUR", EffectiveFrom: at("2026-01-01T00:00:00Z"),
			Charges: []Charge{{Model: ModelPackage, PackageSize: 0}}},
	}
	for i, tf := range bad {
		if err := tf.Validate(); err == nil {
			t.Errorf("case %d: expected an error", i)
		}
	}
}
