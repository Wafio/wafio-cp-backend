package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/config"
	"github.com/wafio/wafio-cp-backend/internal/otp"
	"github.com/wafio/wafio-cp-backend/internal/setup"
)

var fetchDataCmd = &cobra.Command{
	Use:   "fetch-data",
	Short: "Download external security data (GeoIP, Firehol, JA4, Bot UA, Malware)",
	Long: `Download all required third-party security data into the security-data/ directory.

These files are NOT stored in the repository and must be downloaded once after
installation and periodically to stay up-to-date.

Components:
  geoip    MaxMind GeoLite2 or DB-IP MMDB databases (Country, City, ASN)
  firehol  FireHOL IP reputation blocklists (level1=block, level2=challenge)
  ja4      JA4 TLS bot fingerprints and browser allowlist
  ja3      Salesforce / abuse.ch JA3 TLS fingerprint list (legacy)
  ua       Bad bot user-agent blocklist
  malware  MalwareBazaar exact SHA-256 corpus (auth key: WAFIO_MALWARE_AUTH_KEY, else the
           key saved under Administration › Security data; without one a
           --profile run skips it and keeps the current database)

GeoIP provider selection:
  • If geo.maxmind_license_key is set in config.yaml: MaxMind GeoLite2
  • Otherwise (default): DB-IP free databases — no account required

Malware updates retain the previous valid corpus on errors. Recent exports are merged
with local history. WAFIO_MALWARE_FEED_URL can select a provider-issued HTTPS text export.
The malware corpus refreshes after one hour, or immediately with --force.

Use --force to re-download data that already exists.
Use --only to refresh a single component (e.g. --only geoip).`,
	RunE: runFetchData,
}

var (
	fetchDataDir        string
	fetchDataMaxMindKey string
	fetchDataForce      bool
	fetchDataOnly       string
	fetchDataProfile    string
)

func init() {
	fetchDataCmd.Flags().StringVar(&fetchDataDir, "dir", "security-data", "Base directory for security data")
	fetchDataCmd.Flags().StringVar(&fetchDataMaxMindKey, "maxmind-key", "", "MaxMind GeoLite2 license key (overrides config)")
	fetchDataCmd.Flags().BoolVar(&fetchDataForce, "force", false, "Re-download even if files already exist")
	fetchDataCmd.Flags().StringVar(&fetchDataOnly, "only", "", "Comma-separated components: geoip,geoip-country,geoip-city,geoip-asn,firehol,ja4,ja3,ua,malware,malware-hashes")
	fetchDataCmd.Flags().StringVar(&fetchDataProfile, "profile", "all", `Preset component set: "all", "control-plane", "agent"`)
}

func runFetchData(_ *cobra.Command, _ []string) error {
	fmt.Println("WAFio Security Data Fetcher")
	fmt.Println(strings.Repeat("─", 52))

	// Resolve MaxMind key: CLI flag → config file.
	mmKey := fetchDataMaxMindKey
	if mmKey == "" {
		if cfg, err := config.Load(); err == nil {
			mmKey = cfg.Geo.MaxMindLicenseKey
		}
	}

	// --profile sets a predefined component list unless --only overrides it.
	var only []string
	if fetchDataOnly != "" {
		for _, s := range strings.Split(fetchDataOnly, ",") {
			if t := strings.TrimSpace(s); t != "" {
				only = append(only, t)
			}
		}
	} else {
		only = setup.ProfileComponents(setup.Profile(fetchDataProfile))
		if fetchDataProfile != "" && fetchDataProfile != "all" {
			fmt.Printf("  Profile: %s → %s\n\n", fetchDataProfile, strings.Join(only, ", "))
		}
	}

	ctx := context.Background()
	// MalwareBazaar needs an auth key: the one the control plane uses
	// (environment, else the key saved under Administration › Security data).
	// Without one, a profile run leaves the malware database as it is
	// instead of failing; an explicit --only malware still reports the error.
	var malwareKey string
	if setup.IncludesMalware(only) {
		var source string
		malwareKey, source = controlPlaneMalwareKey(ctx)
		switch {
		case malwareKey != "":
			fmt.Printf("  Malware: MalwareBazaar auth key from %s\n\n", source)
		case fetchDataOnly == "":
			only = setup.WithoutMalware(only)
			fmt.Println("  Malware: skipped — no MalwareBazaar auth key (WAFIO_MALWARE_AUTH_KEY, or save one under")
			fmt.Println("           Administration › Security data); the current malware database is kept.")
			fmt.Println()
		}
	}

	cfg := setup.FetchConfig{
		Dir:               fetchDataDir,
		MaxMindLicenseKey: mmKey,
		MalwareAuthKey:    malwareKey,
		Force:             fetchDataForce,
		Only:              only,
		Log: func(format string, args ...any) {
			fmt.Printf(format+"\n", args...)
		},
	}

	start := time.Now()
	results := setup.FetchAll(ctx, cfg)

	fmt.Printf("\n%s\n", strings.Repeat("─", 52))

	failed := 0
	for _, r := range results {
		if r.Err != nil {
			failed++
		}
	}

	elapsed := time.Since(start).Round(time.Millisecond)
	if failed == 0 {
		fmt.Printf("✅  All security data fetched successfully (%v)\n", elapsed)
		fmt.Println("\nNext step: wafio serve")
	} else {
		fmt.Printf("⚠️   Completed with %d error(s) (%v)\n", failed, elapsed)
		for _, r := range results {
			if r.Err != nil {
				fmt.Fprintf(os.Stderr, "  ERROR [%s]: %v\n", r.Component, r.Err)
			}
		}
		return fmt.Errorf("%d component(s) failed to download", failed)
	}
	return nil
}

// controlPlaneMalwareKey returns the MalwareBazaar auth key the control plane
// would use and where it came from: WAFIO_MALWARE_AUTH_KEY, else the key saved
// in the dashboard (system_settings, decrypted with totp.enc_key, read with
// the database settings of config.yaml). "" when none is available — no
// config or database yet (a fresh install fetches before it writes the
// config), or nothing saved. The key is never printed.
func controlPlaneMalwareKey(ctx context.Context) (key, source string) {
	if k := strings.TrimSpace(os.Getenv("WAFIO_MALWARE_AUTH_KEY")); k != "" {
		return k, "the environment"
	}
	cfg, err := config.Load()
	if err != nil || cfg.Validate() != nil {
		return "", ""
	}
	enc, err := otp.NewEncryptor(cfg.TOTP.EncKey)
	if err != nil || enc == nil {
		return "", ""
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	repo, err := repository.New(ctx, cfg.Database.DSN())
	if err != nil {
		return "", ""
	}
	defer repo.Close()
	k, err := (&application.MalwareCredentials{Store: repo.SystemSettings, Crypto: enc}).Resolve(ctx)
	if err != nil || k == "" {
		return "", ""
	}
	return k, "the dashboard (Administration › Security data)"
}
