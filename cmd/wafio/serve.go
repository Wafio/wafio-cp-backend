package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	httpadapter "github.com/wafio/wafio-cp-backend/internal/adapter/http"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/handlers"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/agentserver"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/certutil"
	"github.com/wafio/wafio-cp-backend/internal/config"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/otp"
	"github.com/wafio/wafio-cp-backend/shared/geo"
	"github.com/wafio/wafio-cp-backend/shared/metrics"

	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start API server",
	RunE:  runServe,
}

var (
	flagMigrate    bool
	migrationsPath string
)

// findGeoDB looks for dir/prefix*/filename (dated dirs e.g. GeoLite2-City_20260101/GeoLite2-City.mmdb).
// If a normalized name is provided it is checked first at dir/normalized (e.g. country.mmdb).
func findGeoDB(dir, prefix, filename, normalized string) string {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	// Check normalized filename first (produced by `wafio fetch-data`).
	if normalized != "" {
		p := filepath.Join(absDir, normalized)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// Fallback: scan for dated sub-directory.
	entries, err := os.ReadDir(absDir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !e.IsDir() || len(e.Name()) < len(prefix) {
			continue
		}
		if e.Name()[:len(prefix)] == prefix {
			p := filepath.Join(absDir, e.Name(), filename)
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

func init() {
	serveCmd.Flags().BoolVar(&flagMigrate, "migrate", false, "run migrations before starting")
	serveCmd.Flags().StringVar(&migrationsPath, "migrations", "migrations", "path to migrations directory")
}

func runServe(*cobra.Command, []string) error {
	runCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	// Halt on unusable configuration rather than starting with a broken
	// security control (a placeholder JWT secret, plaintext TOTP secrets, a
	// wildcard CORS origin with credentials). See internal/config/validate.go.
	if err := cfg.Validate(); err != nil {
		return err
	}
	// log.level: validated by cfg.Validate above.
	if level, ok := cfg.Log.SlogLevel(); ok {
		slog.SetLogLoggerLevel(level)
	}
	// WAFIO_METRICS_ADDR is checked before anything starts; it is bound once
	// the series are registered, below.
	if addr := os.Getenv(metrics.EnvAddr); addr != "" {
		if err := metrics.ValidateLoopbackAddr(addr); err != nil {
			return fmt.Errorf("%s: %w", metrics.EnvAddr, err)
		}
	}
	if addr := os.Getenv("WAFIO_PPROF_ADDR"); addr != "" {
		server, listener, err := newDiagnosticsServer(addr)
		if err != nil {
			return err
		}
		defer func() { _ = server.Close() }() // shutdown path; nothing left to report
		go func() {
			if err := server.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("diagnostics server: %v", err)
			}
		}()
	}

	if flagMigrate {
		if err := runMigrateUp(nil, nil); err != nil {
			return err
		}
	}

	ctx := context.Background()
	repo, err := repository.NewWithPool(ctx, cfg.Database.DSN(), repository.PoolOptions{
		MaxConns: cfg.Database.MaxConns,
		MinConns: cfg.Database.MinConns,
		// The database cancels a statement past this bound.
		StatementTimeout: time.Duration(cfg.Database.StatementTimeoutMs) * time.Millisecond,
	})
	if err != nil {
		// The setup wizard is gone; there is no degraded mode left to serve.
		// Bootstrap is `wafio migrate up` followed by `wafio admin create`.
		return fmt.Errorf("connect to database: %w", err)
	}
	{
		defer repo.Close()
		// Wire TOTP secret encryption-at-rest. Empty key = plaintext fallback
		// (existing 2FA keeps working) with a loud warning.
		// cfg.Validate guarantees the key is present, so a nil encryptor here
		// would silently reintroduce plaintext storage of second-factor secrets.
		totpEnc, terr := otp.NewEncryptor(cfg.TOTP.EncKey)
		if terr != nil {
			return fmt.Errorf("invalid totp.enc_key (env WAFIO_TOTP_ENC_KEY): %w", terr)
		}
		if totpEnc == nil {
			return errors.New("totp.enc_key produced no encryptor; refusing to store TOTP secrets in plaintext")
		}
		repo.User.TOTPCrypto = totpEnc

		// Correlation rules: install every project's stored rule set before
		// ingest starts, so a restart does not bring disabled built-ins back
		// or drop custom chains until the next rule edit.
		loadCorrelationRules(ctx, repo.CorrelationRules)

		// Hourly cleanup of stale login_attempts rows.
		go func() {
			la := repository.NewLoginAttemptRepo(repo.DB, cfg.Server.LoginMaxAttempts, cfg.Server.LoginLockMinutes)
			t := time.NewTicker(time.Hour)
			defer t.Stop()
			for {
				select {
				case <-runCtx.Done():
					return
				case <-t.C:
					if err := la.CleanupExpired(context.Background()); err != nil {
						log.Printf("login_attempts cleanup: %v", err)
					}
				}
			}
		}()

		// Agent certificate expiry monitor: warn (log) when agent client certs
		// or the CA are expiring or expired. Detection only — no auto-renewal.
		go func() {
			warnDays := cfg.MTLS.CertWarnBeforeDays
			if warnDays <= 0 {
				warnDays = 30
			}
			window := time.Duration(warnDays) * 24 * time.Hour
			check := func() {
				creds, err := repo.AgentGRPC.ListAllAgentCredentials(context.Background())
				if err != nil {
					log.Printf("[cert-monitor] list credentials: %v", err)
					return
				}
				now := time.Now()
				for _, c := range creds {
					na, perr := certutil.ParseNotAfter([]byte(c.ClientCertPEM))
					if perr != nil {
						log.Printf("[cert-monitor] credential %s (project %s): unparseable cert: %v", c.Name, c.ProjectID, perr)
						continue
					}
					switch {
					case !na.After(now):
						log.Printf("[cert-monitor] credential %s (project %s) EXPIRED on %s", c.Name, c.ProjectID, na.Format("2006-01-02"))
					case na.Before(now.Add(window)):
						log.Printf("[cert-monitor] credential %s (project %s) expires in %dd (%s)", c.Name, c.ProjectID, int(time.Until(na).Hours()/24), na.Format("2006-01-02"))
					}
				}
				if ca, cerr := repo.AgentGRPC.GetGlobalCA(context.Background()); cerr == nil && ca != nil {
					switch {
					case !ca.NotAfter.After(now):
						log.Printf("[cert-monitor] agent CA EXPIRED on %s", ca.NotAfter.Format("2006-01-02"))
					case ca.NotAfter.Before(now.Add(window)):
						log.Printf("[cert-monitor] agent CA expires in %dd (%s)", int(time.Until(ca.NotAfter).Hours()/24), ca.NotAfter.Format("2006-01-02"))
					}
				}
			}
			check() // run once at startup
			t := time.NewTicker(6 * time.Hour)
			defer t.Stop()
			for {
				select {
				case <-runCtx.Done():
					return
				case <-t.C:
					check()
				}
			}
		}()
	}

	if cfg.BotDefaults.UABadBotFile != "" {
		_ = os.Setenv("WAFIO_UA_BAD_BOT_FILE", cfg.BotDefaults.UABadBotFile)
	}
	if cfg.BotDefaults.JA3BlacklistFile != "" {
		_ = os.Setenv("WAFIO_JA3_BLACKLIST_FILE", cfg.BotDefaults.JA3BlacklistFile)
	}
	if cfg.BotDefaults.JA4BlacklistFile != "" {
		_ = os.Setenv("WAFIO_JA4_BLACKLIST_FILE", cfg.BotDefaults.JA4BlacklistFile)
	}
	if cfg.BotDefaults.JA4AllowlistFile != "" {
		_ = os.Setenv("WAFIO_JA4_ALLOWLIST_FILE", cfg.BotDefaults.JA4AllowlistFile)
	}

	warnDeprecatedEnvUsage("WAFIO_GEOIP_DB_PATH", "WAFIO_GEO_COUNTRY_DB_PATH")
	warnDeprecatedEnvUsage("WAFIO_GEOIP_CITY_DB_PATH", "WAFIO_GEO_CITY_DB_PATH")
	warnDeprecatedEnvUsage("WAFIO_GEOIP_ASN_DB_PATH", "WAFIO_GEO_ASN_DB_PATH")

	certValidity := time.Duration(cfg.MTLS.CertValidityDays) * 24 * time.Hour

	var onConfigUpdated httpadapter.OnConfigUpdated

	var geoEnricher handlers.GeoEnricher
	var geoLookupReloader handlers.GeoLookupReloader
	var geoRanges handlers.GeoRangeSource
	var geoEnricherReloader handlers.GeoEnricherReloader
	var secDataH *handlers.SecurityDataHandler
	var (
		decisionBroker *agentserver.DecisionBroker
		agentGRPCSrv   *agentserver.Server
		hostStore      *repository.HostEventStore
		// grpcDone is closed when the agent gRPC server has stopped; nil
		// when it never started.
		grpcDone chan struct{}
	)

	if repo != nil {
		// ── Host event store (TimescaleDB/PostgreSQL) ──
		hostStore = repository.NewHostEventStore(repo.DB)
		repo.EBPF.SetHostEventStore(hostStore)

		// GeoEnricher for dashboard geo map (city, lat, lon, ISP). Uses GeoLite2-City + GeoLite2-ASN.
		// WAFIO_GEOIP_DB_PATH is for geoblocking (Country); city/ISP need separate City and ASN DBs.
		geoEnricher = geo.NoopEnricher{}
		geoDir := filepath.Join("security-data", "geoip")
		cityPath := cfg.Geo.CityDBPath
		asnPath := cfg.Geo.ASNDBPath
		if cityPath == "" {
			cityPath = findGeoDB(geoDir, "GeoLite2-City", "GeoLite2-City.mmdb", "city.mmdb")
		}
		if asnPath == "" {
			asnPath = findGeoDB(geoDir, "GeoLite2-ASN", "GeoLite2-ASN.mmdb", "asn.mmdb")
		}
		if cityPath != "" || asnPath != "" {
			if e, err := geo.NewMaxMindEnricher(cityPath, asnPath); err != nil {
				log.Printf("GeoIP enricher init failed: %v (geo map will show country only)", err)
			} else {
				geoEnricher = e
				if closer, ok := e.(*geo.MaxMindEnricher); ok {
					geoEnricherReloader = closer
					defer func() { _ = closer.Close() }() // shutdown path; nothing left to report
				}
				if cityPath != "" {
					log.Printf("Geo map: city/lat/lon from %s", cityPath)
				}
				if asnPath != "" {
					log.Printf("Geo map: ISP from %s", asnPath)
				}
			}
		}

		// GeoLookup (country-only) for enriching WAF agent decision telemetry with country codes.
		var geoLookup domain.GeoLookup
		countryPath := cfg.Geo.CountryDBPath
		if countryPath == "" {
			countryPath = findGeoDB(geoDir, "GeoLite2-Country", "GeoLite2-Country.mmdb", "country.mmdb")
		}
		if countryPath != "" {
			if l, err := geo.NewMaxMindLookup(countryPath); err != nil {
				log.Printf("GeoIP country lookup init failed: %v (WAF agent events won't have country codes)", err)
			} else {
				geoLookup = l
				if closer, ok := l.(*geo.MaxMindLookup); ok {
					geoLookupReloader = closer
					geoRanges = closer
					defer func() { _ = closer.Close() }() // shutdown path; nothing left to report
				}
				log.Printf("GeoIP country lookup: %s", countryPath)
			}
		}

		// ── Agent gRPC mTLS control plane ──
		// One global CA (auto-generated on first boot) signs all per-agent
		// client certs. We expose a bidirectional stream on AgentGRPCAddr for
		// agents to receive bundle pushes and emit live WAF decisions.
		if cfg.Server.AgentGRPCAddr != "" {
			grpcCtx := runCtx
			grpcCA, gerr := repo.AgentGRPC.GetGlobalCA(grpcCtx)
			if errors.Is(gerr, repository.ErrAgentGRPCCANotFound) {
				caValidity := 10 * 365 * 24 * time.Hour
				caPEM, caKeyPEM, gencErr := certutil.GenerateCA(caValidity)
				if gencErr != nil {
					log.Printf("agent gRPC: generate CA failed: %v (gRPC disabled)", gencErr)
				} else {
					notAfter := time.Now().Add(caValidity)
					if grpcCA, gerr = repo.AgentGRPC.CreateGlobalCA(grpcCtx, string(caPEM), string(caKeyPEM), notAfter); gerr != nil {
						// Race: another instance inserted; re-fetch.
						grpcCA, gerr = repo.AgentGRPC.GetGlobalCA(grpcCtx)
					}
					if grpcCA != nil {
						log.Printf("agent gRPC: CA generated (id=%s, validity 10y)", grpcCA.ID)
					}
				}
			}
			if gerr == nil && grpcCA != nil {
				caPool := x509.NewCertPool()
				if !caPool.AppendCertsFromPEM([]byte(grpcCA.CertPEM)) {
					log.Printf("agent gRPC: append CA failed (gRPC disabled)")
				} else {
					serverEndpoint := cfg.Server.GRPCDomain
					if serverEndpoint == "" {
						serverEndpoint = "localhost"
					}
					srvCertPEM, srvKeyPEM, scerr := certutil.GenerateServerCert([]byte(grpcCA.CertPEM), []byte(grpcCA.KeyPEM), certValidity, serverEndpoint)
					if scerr != nil {
						log.Printf("agent gRPC: generate server cert failed: %v (gRPC disabled)", scerr)
					} else {
						srvCert, kerr := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
						if kerr != nil {
							log.Printf("agent gRPC: load server cert failed: %v (gRPC disabled)", kerr)
						} else {
							certProvider := agentserver.NewCertProvider(srvCert)

							// Auto-renew: background goroutine rotates the server cert before expiry.
							if cfg.MTLS.ServerCertAutoRenew && cfg.MTLS.ServerCertRenewBefore > 0 {
								renewBefore := time.Duration(cfg.MTLS.ServerCertRenewBefore) * 24 * time.Hour
								certNotAfter := time.Now().Add(certValidity)
								go func() {
									checkEvery := certValidity / 10
									if checkEvery > 6*time.Hour {
										checkEvery = 6 * time.Hour
									}
									if checkEvery < time.Minute {
										checkEvery = time.Minute
									}
									ticker := time.NewTicker(checkEvery)
									defer ticker.Stop()
									expiry := certNotAfter
									for {
										select {
										case <-runCtx.Done():
											return
										case <-ticker.C:
											if time.Until(expiry) > renewBefore {
												continue
											}
											log.Printf("agent gRPC: server cert expiring in %v — renewing", time.Until(expiry).Round(time.Hour))
											newPEM, newKey, err := certutil.GenerateServerCert([]byte(grpcCA.CertPEM), []byte(grpcCA.KeyPEM), certValidity, serverEndpoint)
											if err != nil {
												log.Printf("agent gRPC: server cert auto-renew failed: %v", err)
												continue
											}
											newCert, err := tls.X509KeyPair(newPEM, newKey)
											if err != nil {
												log.Printf("agent gRPC: server cert auto-renew: parse failed: %v", err)
												continue
											}
											certProvider.Set(newCert)
											expiry = time.Now().Add(certValidity)
											log.Printf("agent gRPC: server cert renewed (next expiry ~%s)", expiry.Format("2006-01-02"))
										}
									}
								}()
							}

							decisionBroker = agentserver.NewDecisionBroker()
							// Start good-bot IP fetcher: fetches Googlebot/Bingbot IP ranges and includes them in agent bundles.
							goodBotFetcher := agentserver.NewGoodBotFetcher(runCtx)
							loader := agentserver.NewProjectBundleLoaderWithGoodBot(repo, goodBotFetcher)
							agentGRPCSrv = agentserver.NewServer(repo, loader, decisionBroker)
							onConfigUpdated = func(projectID string) {
								if agentGRPCSrv != nil {
									go agentGRPCSrv.PushBundleToProject(projectID)
								}
							}
							// Decisions are queued and written in batches; the
							// writer is drained by orderedShutdown, after the
							// gRPC server has stopped.
							agentGRPCSrv.GeoLookup = geoLookup
							// Agent receive budget: per account, and the
							// process-wide total shared fairly.
							recvAccount, recvTotal := cfg.Server.AgentRecvLimits()
							agentGRPCSrv.SetRecvLimits(recvAccount, recvTotal)
							log.Printf("agent receive budget: %d MiB/s per account, %d MiB/s shared by all accounts",
								recvAccount>>20, recvTotal>>20)
							// Wire eBPF ingest so the gRPC stream stores telemetry through
							// application.HostTelemetryIngest without importing it.
							hostTelemetry := &application.HostTelemetryIngest{
								Telemetry:    repo.EBPF,
								Hosts:        repo.Host,
								Rules:        repo.DetectionRules,
								Incidents:    repo.Incident,
								FirewallHits: handlers.NewFirewallRuleHitMerger(repo),
								Policies:     agentGRPCSrv,
								// Trace forwarding filters go
								// to host agents over their gRPC streams.
								ForwardFilters: agentGRPCSrv,
							}
							// A detection rule or correlation chain write
							// sends the new filter to connected agents at
							// once, not with their next batch.
							repo.DetectionRules.SetChangeHook(hostTelemetry.RefreshTraceForwardFilters)
							application.Correlations().SetChangeHook(func(projectID string) {
								hostTelemetry.RefreshTraceForwardFilters(projectID, "")
							})
							agentGRPCSrv.EBPFIngest = hostTelemetry.IngestJSON
							agentGRPCSrv.EBPFPrepare = func(payload []byte) (agentserver.PreparedHostTelemetry, error) {
								return hostTelemetry.Prepare(payload)
							}
							tlsCfg := agentserver.BuildTLSConfig(certProvider, caPool)
							addr := cfg.Server.AgentGRPCAddr
							grpcDone = make(chan struct{})
							go func() {
								defer close(grpcDone)
								if err := agentGRPCSrv.ListenAndServe(runCtx, addr, tlsCfg); err != nil {
									log.Printf("agent gRPC server error: %v", err)
								}
							}()
						}
					}
				}
			} else if gerr != nil && !errors.Is(gerr, repository.ErrAgentGRPCCANotFound) {
				log.Printf("agent gRPC: load CA failed: %v (gRPC disabled)", gerr)
			}
		}
		secDataH = &handlers.SecurityDataHandler{
			MalwareCredentials:  &application.MalwareCredentials{Store: repo.SystemSettings, Crypto: repo.User.TOTPCrypto},
			Repo:                repo,
			Cfg:                 cfg,
			GeoLookupReloader:   geoLookupReloader,
			GeoEnricherReloader: geoEnricherReloader,
		}
		// A nil *agentserver.Server in the AgentFetcher interface would pass
		// the handler's nil check (gRPC disabled or not configured).
		if agentGRPCSrv != nil {
			secDataH.AgentSrv = agentGRPCSrv
		}
	}
	_ = agentGRPCSrv

	metricsReg := metrics.NewRegistry()
	registerControlPlaneMetrics(metricsReg, repo.DB, agentGRPCSrv, decisionBroker)
	app := httpadapter.NewFiberApp(runCtx, cfg, repo, onConfigUpdated, geoEnricher, decisionBroker, agentGRPCSrv, secDataH, Version,
		httpadapter.WithMetrics(metricsReg), httpadapter.WithGeoRanges(geoRanges))
	closeMetrics, err := startMetricsListener(metricsReg)
	if err != nil {
		return err
	}
	defer closeMetrics()
	httpErrCh := make(chan error, 1)
	go func() {
		log.Printf("Wafio: WAF engine v0.0.1")
		log.Printf("HTTP API listening on %s", cfg.Server.HTTPAddr)
		if err := app.Listen(cfg.Server.HTTPAddr); err != nil {
			select {
			case httpErrCh <- err:
			default:
			}
		}
	}()

	// Background sweeper: clears expired rotation grace windows on hosts/apps
	// and flips stale hosts to `offline` when heartbeats stop. Bound to
	// runCtx so it terminates cleanly on SIGTERM.
	if repo != nil {
		go repository.RunKeySweeper(runCtx, repo.KeySweeperDeps())
	}

	select {
	case err := <-httpErrCh:
		if err != nil && !isExpectedServerStopError(err) {
			return fmt.Errorf("http listen: %w", err)
		}
	case <-runCtx.Done():
		log.Printf("shutdown signal received, stopping services")
	}

	// runCtx may still be live when HTTP failed on its own; stop the gRPC
	// server and every runCtx-bound loop before draining.
	stop()
	var drains []func()
	if agentGRPCSrv != nil {
		drains = append(drains, agentGRPCSrv.StopDecisionWriter)
	}
	if hostStore != nil {
		drains = append(drains, hostStore.Close)
	}
	// repo.Close (deferred above) runs after this returns.
	return orderedShutdown(app.ShutdownWithContext, grpcDone, grpcShutdownWait, drains...)
}

const (
	httpShutdownTimeout = 10 * time.Second
	// grpcShutdownWait covers the gRPC server's own bounded GracefulStop
	// (agentserver.defaultGracefulStopWait) with margin.
	grpcShutdownWait = 15 * time.Second
)

// orderedShutdown stops the services in the order that keeps queued data: stop accepting
// HTTP (SSE loops end with runCtx) → wait for the
// agent gRPC server, whose GracefulStop is bounded and then forced → drain
// the writers the streams fed (decision writer, host event store). The pool
// is closed by the caller afterwards. An HTTP shutdown error is reported but
// does not skip the drains.
func orderedShutdown(stopHTTP func(context.Context) error, grpcDone <-chan struct{}, grpcWait time.Duration, drains ...func()) error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
	defer cancel()
	var httpErr error
	if err := stopHTTP(shutdownCtx); err != nil && !isExpectedServerStopError(err) {
		httpErr = fmt.Errorf("http shutdown: %w", err)
	}
	if grpcDone != nil {
		select {
		case <-grpcDone:
		case <-time.After(grpcWait):
			log.Printf("agent gRPC server did not stop within %v; draining writers anyway", grpcWait)
		}
	}
	for _, drain := range drains {
		drain()
	}
	return httpErr
}

func warnDeprecatedEnvUsage(legacyKey, replacementKey string) {
	if legacyKey == "" || replacementKey == "" {
		return
	}
	legacyVal := os.Getenv(legacyKey)
	if legacyVal == "" {
		return
	}
	if os.Getenv(replacementKey) != "" {
		return
	}
	log.Printf("deprecated env %s is in use; please migrate to %s", legacyKey, replacementKey)
}

func isExpectedServerStopError(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "server closed") ||
		strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "server is not running")
}
