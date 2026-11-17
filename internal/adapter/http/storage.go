package httpadapter

import (
	"context"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/config"
	"github.com/wafio/wafio-cp-backend/shared/metrics"
)

// newStorage returns the data retention / database size service:
// the WithStorage override, else one on repo whose loop it
// starts on ctx. Nil without a database (handler tests without one).
func newStorage(ctx context.Context, cfg *config.Config, repo *repository.Repository, mail *application.MailSettings, opts []AppOption) *application.Storage {
	if s := resolveOptions(opts).storage; s != nil {
		return s
	}
	if repo == nil || repo.DB == nil || repo.Storage == nil || repo.SystemSettings == nil {
		return nil
	}
	s := &application.Storage{
		Store:        repo.Storage,
		Settings:     repo.SystemSettings,
		DatabaseHost: cfg.Database.Host,
	}
	if mail != nil {
		s.Mail = mail
	}
	go s.Run(ctx)
	return s
}

// registerStorageMetrics adds the database size and retention series.
// Values come from the last background check; the
// filesystem series is absent while free space is unknown.
func registerStorageMetrics(reg *metrics.Registry, s *application.Storage) {
	if reg == nil || s == nil {
		return
	}
	sizeVal := func(pick func(application.DBSizeStatus) float64) func() float64 {
		return func() float64 {
			st := s.LastSize()
			if st == nil {
				return 0
			}
			return pick(*st)
		}
	}
	reg.Gauge("wafio_db_size_bytes", "Size of the control-plane database (pg_database_size) at the last check.",
		sizeVal(func(st application.DBSizeStatus) float64 {
			if st.SizeBytes == nil {
				return 0
			}
			return float64(*st.SizeBytes)
		}))
	reg.Gauge("wafio_db_size_budget_bytes", "Database size budget set under Administration > Data retention (0 = none).",
		sizeVal(func(st application.DBSizeStatus) float64 {
			if st.BudgetBytes == nil {
				return 0
			}
			return float64(*st.BudgetBytes)
		}))
	reg.Gauge("wafio_db_size_alert_level", "Database size alert level: 0 none or ok, 1 warning (80 %), 2 critical (95 %) of the budget or the filesystem.",
		sizeVal(func(st application.DBSizeStatus) float64 {
			switch st.Level {
			case application.SizeLevelWarning:
				return 1
			case application.SizeLevelCritical:
				return 2
			}
			return 0
		}))
	reg.Gauge("wafio_db_growth_bytes_per_day", "Estimated net database growth per day (0 = unknown).",
		sizeVal(func(st application.DBSizeStatus) float64 {
			if st.GrowthBytesPerDay == nil {
				return 0
			}
			return *st.GrowthBytesPerDay
		}))
	reg.GaugeVec("wafio_db_filesystem_free_bytes", "Free space of the filesystem holding the database (absent while unknown).", func() []metrics.Sample {
		st := s.LastSize()
		if st == nil || !st.Filesystem.Known || st.Filesystem.FreeBytes == nil {
			return nil
		}
		return []metrics.Sample{{Value: float64(*st.Filesystem.FreeBytes)}}
	})
	reg.GaugeVec("wafio_retention_days", "Telemetry retention in days per table.", func() []metrics.Sample {
		var out []metrics.Sample
		for _, t := range s.MetricsTables() {
			out = append(out, metrics.Sample{Labels: []metrics.Label{{Name: "table", Value: t.Table}}, Value: float64(t.Days)})
		}
		return out
	})
	reg.GaugeVec("wafio_retention_active", "1 while the table's retention runs (TimescaleDB policy or control-plane pass).", func() []metrics.Sample {
		var out []metrics.Sample
		for _, t := range s.MetricsTables() {
			v := 0.0
			if t.Active {
				v = 1
			}
			out = append(out, metrics.Sample{Labels: []metrics.Label{{Name: "table", Value: t.Table}}, Value: v})
		}
		return out
	})
	reg.CounterVec("wafio_retention_deleted", "Rows (plain tables) or chunks (hypertables without policies) removed by the control-plane retention pass.", func() []metrics.Sample {
		var out []metrics.Sample
		for _, t := range s.MetricsTables() {
			out = append(out, metrics.Sample{Labels: []metrics.Label{{Name: "table", Value: t.Table}}, Value: float64(t.DeletedByPass)})
		}
		return out
	})
}
