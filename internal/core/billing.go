package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cladone/gate-one/internal/metering"
	"cladone/gate-one/internal/pricing"
)

// UsageDimSpec declares one dimension of a metric.
type UsageDimSpec struct {
	Type      string   `json:"type"` // string | enum
	MaxLength int      `json:"maxLength,omitempty"`
	Values    []string `json:"values,omitempty"`
}

// UsageMetricConfig is one billable metric.
type UsageMetricConfig struct {
	Unit             string                  `json:"unit"`
	Scale            int                     `json:"scale"`
	MaxDimensions    int                     `json:"maxDimensions,omitempty"`
	Dimensions       map[string]UsageDimSpec `json:"dimensions,omitempty"`
	Measurement      string                  `json:"measurement,omitempty"` // event | periodic
	HeartbeatSeconds int                     `json:"heartbeatSeconds,omitempty"`
	Pricing          string                  `json:"pricing,omitempty"` // declarative | plugin
	Fallback         string                  `json:"fallback,omitempty"`
}

// UsageTierConfig is one range of a tiered or volume charge.
type UsageTierConfig struct {
	FromValue       int64 `json:"fromValue"`
	ToValue         int64 `json:"toValue"` // < 0 = unbounded
	PerUnitMicro    int64 `json:"perUnitMicro"`
	FlatAmountMicro int64 `json:"flatAmountMicro,omitempty"`
}

// UsageChargeConfig is one priced rule of a tariff.
type UsageChargeConfig struct {
	Model            string              `json:"model"` // unit | tiered | volume | package | percentage_of
	AmountMicro      int64               `json:"amountMicro,omitempty"`
	Filter           map[string][]string `json:"filter,omitempty"`
	Tiers            []UsageTierConfig   `json:"tiers,omitempty"`
	PackageSize      int64               `json:"packageSize,omitempty"`
	FreeUnits        int64               `json:"freeUnits,omitempty"`
	RateBasisPoints  int64               `json:"rateBasisPoints,omitempty"`
	FixedAmountMicro int64               `json:"fixedAmountMicro,omitempty"`
}

// UsageTariffConfig is one versioned rate table. The map key is the
// version and must equal Version.
type UsageTariffConfig struct {
	Metric        string              `json:"metric"`
	Version       string              `json:"version"`
	Currency      string              `json:"currency"`
	EffectiveFrom string              `json:"effectiveFrom"`
	Charges       []UsageChargeConfig `json:"charges"`
}

// UsageOutboxConfig bounds the local delivery buffer.
type UsageOutboxConfig struct {
	Dir        string `json:"dir,omitempty"`
	MaxAge     string `json:"maxAge,omitempty"` // duration, e.g. "6h"
	MaxBytes   int64  `json:"maxBytes,omitempty"`
	MaxRecords int64  `json:"maxRecords,omitempty"`
	OnFull     string `json:"onFull,omitempty"` // block | drop
}

// UsageSinkConfig configures the delivery of billing records.
type UsageSinkConfig struct {
	URL                string `json:"url,omitempty"`
	SecretEnv          string `json:"secretEnv,omitempty"`
	SigningKeyEnv      string `json:"signingKeyEnv,omitempty"`
	BatchRecords       int    `json:"batchRecords,omitempty"`
	BatchBytes         int    `json:"batchBytes,omitempty"`
	BatchWaitMS        int    `json:"batchWaitMs,omitempty"`
	ExportDir          string `json:"exportDir,omitempty"`
	ExportAfterSeconds int    `json:"exportAfterSeconds,omitempty"`
	// ReceiptPublicKey verifies the ingest receipts (airgap ack).
	ReceiptPublicKey string `json:"receiptPublicKey,omitempty"`
}

// resolveBilling parses and validates the metering/tariff configuration
// and stores the resulting registry on the UsageConfig.
func (u *UsageConfig) resolveBilling(baseDir string) error {
	u.Profile = strings.ToLower(strings.TrimSpace(u.Profile))
	if u.Profile == "" {
		u.Profile = "online"
	}
	switch u.Profile {
	case "online", "airgap":
	default:
		return fmt.Errorf(
			"usage.profile %q: must be online or airgap", u.Profile)
	}

	if len(u.Metrics) == 0 {
		if len(u.Tariffs) > 0 {
			return fmt.Errorf("usage.tariffs: metrics are required")
		}
		return nil
	}

	reg := pricing.NewRegistry()
	for code, mc := range u.Metrics {
		m := metering.Metric{
			Code:             code,
			Unit:             mc.Unit,
			Scale:            mc.Scale,
			MaxDimensions:    mc.MaxDimensions,
			Measurement:      metering.Measurement(mc.Measurement),
			HeartbeatSeconds: mc.HeartbeatSeconds,
			Pricing:          mc.Pricing,
			Fallback:         mc.Fallback,
		}
		if len(mc.Dimensions) > 0 {
			m.Dimensions = make(map[string]metering.DimSpec, len(mc.Dimensions))
			for name, spec := range mc.Dimensions {
				m.Dimensions[name] = metering.DimSpec{
					Type:      metering.DimType(spec.Type),
					MaxLength: spec.MaxLength,
					Values:    spec.Values,
				}
			}
		}
		if err := reg.AddMetric(m); err != nil {
			return fmt.Errorf("usage.metrics[%s]: %w", code, err)
		}
	}

	currencyOf := map[string]string{}
	for key, tc := range u.Tariffs {
		version := strings.TrimSpace(tc.Version)
		if version == "" {
			version = key
		}
		if version != key {
			return fmt.Errorf(
				"usage.tariffs[%s]: version %q does not match its key",
				key, version)
		}
		effective, err := time.Parse(time.RFC3339, strings.TrimSpace(tc.EffectiveFrom))
		if err != nil {
			return fmt.Errorf(
				"usage.tariffs[%s].effectiveFrom: %w", key, err)
		}
		tf := pricing.Tariff{
			Version:       version,
			Currency:      strings.ToUpper(strings.TrimSpace(tc.Currency)),
			EffectiveFrom: effective,
		}
		for i, cc := range tc.Charges {
			ch := pricing.Charge{
				Model:           pricing.Model(cc.Model),
				AmountMicro:     cc.AmountMicro,
				Filter:          cc.Filter,
				PackageSize:     cc.PackageSize,
				FreeUnits:       cc.FreeUnits,
				RateBasisPoints: cc.RateBasisPoints,
				FixedAmount:     cc.FixedAmountMicro,
			}
			for _, t := range cc.Tiers {
				ch.Tiers = append(ch.Tiers, pricing.Tier{
					FromValue:  t.FromValue,
					ToValue:    t.ToValue,
					PerUnitMi:  t.PerUnitMicro,
					FlatAmount: t.FlatAmountMicro,
				})
			}
			if err := validateChargeFilter(ch.Filter, i, key, tc.Metric, reg); err != nil {
				return err
			}
			tf.Charges = append(tf.Charges, ch)
		}
		if err := reg.AddTariff(tc.Metric, tf); err != nil {
			return fmt.Errorf("usage.tariffs[%s]: %w", key, err)
		}
		if cur, ok := currencyOf[tc.Metric]; ok && cur != tf.Currency {
			return fmt.Errorf(
				"usage.tariffs[%s]: metric %q mixes currencies %s and %s",
				key, tc.Metric, cur, tf.Currency)
		}
		currencyOf[tc.Metric] = tf.Currency
	}

	// A plugin metric must name an existing declarative fallback on the
	// same metric: the fallback is the price when the plugin is down.
	for code, mc := range u.Metrics {
		if mc.Pricing != metering.PricingPlugin {
			continue
		}
		ft, ok := u.Tariffs[mc.Fallback]
		if !ok {
			return fmt.Errorf(
				"usage.metrics[%s].fallback %q: unknown tariff",
				code, mc.Fallback)
		}
		if ft.Metric != code {
			return fmt.Errorf(
				"usage.metrics[%s].fallback %q: tariff is for metric %q",
				code, mc.Fallback, ft.Metric)
		}
	}

	// Resolve the signed allowance (single document, file or env).
	u.AllowanceFile = strings.TrimSpace(u.AllowanceFile)
	u.AllowanceEnv = strings.TrimSpace(u.AllowanceEnv)
	if u.AllowanceFile != "" && u.AllowanceEnv != "" {
		return fmt.Errorf(
			"usage: allowanceFile and allowanceEnv are mutually exclusive")
	}
	switch {
	case u.AllowanceFile != "":
		p := u.AllowanceFile
		if !filepath.IsAbs(p) {
			p = filepath.Join(baseDir, p)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("usage.allowanceFile: %w", err)
		}
		u.AllowanceFile = p
		u.AllowanceJSON = raw
	case u.AllowanceEnv != "":
		raw, ok := os.LookupEnv(u.AllowanceEnv)
		if !ok || strings.TrimSpace(raw) == "" {
			return fmt.Errorf(
				"usage: environment variable %s is empty", u.AllowanceEnv)
		}
		u.AllowanceJSON = []byte(raw)
	}

	// Outbox and sink.
	if u.Outbox == nil {
		u.Outbox = &UsageOutboxConfig{}
	}
	u.Outbox.Dir = strings.TrimSpace(u.Outbox.Dir)
	if u.Outbox.Dir == "" {
		u.Outbox.Dir = "usage-outbox"
	}
	if !filepath.IsAbs(u.Outbox.Dir) {
		u.Outbox.Dir = filepath.Join(baseDir, u.Outbox.Dir)
	}
	u.Outbox.OnFull = strings.TrimSpace(u.Outbox.OnFull)
	switch u.Outbox.OnFull {
	case "":
		u.Outbox.OnFull = "block"
	case "block", "drop":
	default:
		return fmt.Errorf("usage.outbox.onFull must be block or drop")
	}
	if u.Outbox.MaxAge == "" {
		u.Outbox.MaxAge = "6h"
	}
	if _, err := time.ParseDuration(u.Outbox.MaxAge); err != nil {
		return fmt.Errorf("usage.outbox.maxAge: %w", err)
	}
	if u.Outbox.MaxBytes == 0 {
		u.Outbox.MaxBytes = 512 << 20
	}
	if u.Outbox.MaxRecords == 0 {
		u.Outbox.MaxRecords = 50000
	}

	if u.Sink == nil {
		u.Sink = &UsageSinkConfig{}
	}
	u.Sink.URL = strings.TrimSpace(u.Sink.URL)
	u.Sink.ExportDir = strings.TrimSpace(u.Sink.ExportDir)
	if u.Sink.ExportDir != "" && !filepath.IsAbs(u.Sink.ExportDir) {
		u.Sink.ExportDir = filepath.Join(baseDir, u.Sink.ExportDir)
	}
	if u.Sink.SigningKeyEnv == "" {
		return fmt.Errorf("usage.sink.signingKeyEnv is required when metrics are configured")
	}
	seed, ok := os.LookupEnv(u.Sink.SigningKeyEnv)
	if !ok || strings.TrimSpace(seed) == "" {
		return fmt.Errorf(
			"usage: environment variable %s is empty", u.Sink.SigningKeyEnv)
	}
	u.SinkSigningSeed = []byte(strings.TrimSpace(seed))
	if u.Sink.SecretEnv != "" {
		v, ok := os.LookupEnv(u.Sink.SecretEnv)
		if !ok || v == "" {
			return fmt.Errorf(
				"usage: environment variable %s is empty", u.Sink.SecretEnv)
		}
		u.SinkSecret = []byte(v)
	}
	if u.Profile == "airgap" {
		if u.Sink.ExportDir == "" {
			return fmt.Errorf("usage.profile airgap requires usage.sink.exportDir")
		}
		if u.Sink.ReceiptPublicKey == "" {
			return fmt.Errorf(
				"usage.profile airgap requires usage.sink.receiptPublicKey")
		}
	} else if u.Sink.URL == "" && u.Sink.ExportDir == "" {
		return fmt.Errorf(
			"usage.sink: url or exportDir is required when metrics are configured")
	}
	if u.Sink.BatchWaitMS == 0 {
		u.Sink.BatchWaitMS = 1000
	}
	if u.Sink.ExportAfterSeconds == 0 {
		u.Sink.ExportAfterSeconds = 300
	}

	if u.Profile == "airgap" {
		if len(u.AllowanceJSON) == 0 {
			return fmt.Errorf(
				"usage.profile airgap requires usage.allowanceFile or usage.allowanceEnv")
		}
		if strings.TrimSpace(u.AllowancePublicKey) == "" {
			return fmt.Errorf(
				"usage.profile airgap requires usage.allowancePublicKey")
		}
	}

	u.Metering = reg
	return nil
}

// validateChargeFilter checks that every filter dimension is declared by
// the metric (a filter on an undeclared dimension could never match).
func validateChargeFilter(
	filter map[string][]string, index int, version, metric string,
	reg *pricing.Registry,
) error {
	if len(filter) == 0 {
		return nil
	}
	m, ok := reg.Metric(metric)
	if !ok {
		return fmt.Errorf(
			"usage.tariffs[%s].charges[%d]: unknown metric %q",
			version, index, metric)
	}
	for dim, values := range filter {
		if _, ok := m.Dimensions[dim]; !ok {
			return fmt.Errorf(
				"usage.tariffs[%s].charges[%d]: filter on undeclared dimension %q",
				version, index, dim)
		}
		if len(values) == 0 {
			return fmt.Errorf(
				"usage.tariffs[%s].charges[%d]: empty filter for %q",
				version, index, dim)
		}
	}
	return nil
}
