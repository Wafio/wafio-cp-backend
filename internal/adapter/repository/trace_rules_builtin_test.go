package repository

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

func TestBuiltinRulePredicates(t *testing.T) {
	migration, err := os.ReadFile("../../../migrations/000079_runtime_rule_predicates.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	guardMigration, err := os.ReadFile("../../../migrations/000080_runtime_noise_guard.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	migration = append(migration, guardMigration...)
	fpMigration, err := os.ReadFile("../../../migrations/000082_runtime_fp_calibration.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	migration = append(migration, fpMigration...)
	identityMigration, err := os.ReadFile("../../../migrations/000093_runtime_identity_hardening.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	migration = append(migration, identityMigration...)
	authMigration, err := os.ReadFile("../../../migrations/000106_runtime_auth_session_noise.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	migration = append(migration, authMigration...)
	systemMigration, err := os.ReadFile("../../../migrations/000111_runtime_system_service_noise.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	migration = append(migration, systemMigration...)
	jitMigration, err := os.ReadFile("../../../migrations/000113_runtime_jit_rwx_noise.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	migration = append(migration, jitMigration...)
	rootMigration, err := os.ReadFile("../../../migrations/000114_runtime_already_root_setid.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	migration = append(migration, rootMigration...)
	noiseMigration, err := os.ReadFile("../../../migrations/000118_runtime_noise_calibration.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	migration = append(migration, noiseMigration...)
	tlsKeyMigration, err := os.ReadFile("../../../migrations/000121_waf_agent_tls_key_reads.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	migration = append(migration, tlsKeyMigration...)
	for _, rule := range builtinRules("project", "host") {
		if err := rule.Validate(); err != nil {
			t.Errorf("%s: %v", rule.Name, err)
		}
		if rule.ProjectID != "project" || rule.HostID != "host" {
			t.Errorf("missing tenancy on %s", rule.Name)
		}
		// Credential-change evidence must never be dropped: Tag and Downgrade
		// both keep the event stored (marked), only Suppress deletes it. The
		// credential-change tag keeps the evidence searchable either way.
		if strings.Contains(rule.Name, "credential change") || strings.HasPrefix(rule.Name, "Tag container runtime set") {
			if rule.Action == domain.RuleActionSuppress {
				t.Errorf("%s must not drop credential evidence", rule.Name)
			}
			if !strings.Contains(string(migration), "name = '"+rule.Name+"'") {
				t.Errorf("%s must retain credential evidence in new and existing hosts", rule.Name)
			}
			hasCredTag := false
			for _, tag := range rule.Tags {
				if tag == "credential-change" {
					hasCredTag = true
				}
			}
			if !hasCredTag {
				t.Errorf("%s must keep the credential-change tag searchable", rule.Name)
			}
		}
		// Downgrades are for observation-shaped events. Any downgrade that
		// touches file reads/writes must carry the read-only flags guard so a
		// file WRITE can never be hidden by severity adjustment.
		if rule.Action == domain.RuleActionDowngrade {
			touchesFiles := false
			otherEvent := false
			for _, c := range rule.Conditions {
				if c.Field == "filename" || (c.Field == "event_name" && c.Op == "eq" && c.Value == "openat") {
					touchesFiles = true
				}
				// filename of a mount (device) or chown (owned file) event
				// is not an opened file: no open flags to guard.
				if c.Field == "event_name" && c.Op == "eq" && c.Value != "openat" {
					otherEvent = true
				}
				if names, ok := c.Value.([]string); ok && c.Field == "event_name" && c.Op == "in" && !slices.Contains(names, "openat") {
					otherEvent = true
				}
			}
			touchesFiles = touchesFiles && !otherEvent
			if touchesFiles {
				found := false
				for _, c := range rule.Conditions {
					if c.Field == "flags" && c.Op == "bit_none" && c.Value == 579 {
						found = true
					}
				}
				if !found {
					t.Errorf("%s can downgrade writes", rule.Name)
				}
			}
		}
		if rule.Name == "Tag unknown binary root UID request" || rule.Name == "Tag AF_RXRPC socket creation" || rule.Name == "Tag raw ESP socket creation" || rule.Name == "Tag pg_isready shadow access" {
			if rule.Action != domain.RuleActionTag || rule.SeverityOverride != nil {
				t.Errorf("%s changes severity", rule.Name)
			}
		}
		if rule.Name == "Tag unknown binary root UID request" || rule.Name == "Tag crontab modification" || rule.Action == domain.RuleActionDowngrade || rule.Name == "Tag pg_isready shadow access" || rule.Name == "Tag AF_RXRPC socket creation" || rule.Name == "Tag raw ESP socket creation" {
			encoded, _ := json.Marshal(rule.Conditions)
			escaped := strings.ReplaceAll(string(encoded), "'", "''")
			if !strings.Contains(string(migration), escaped) {
				t.Errorf("migration omits %s predicates", rule.Name)
			}
		}
	}
}
