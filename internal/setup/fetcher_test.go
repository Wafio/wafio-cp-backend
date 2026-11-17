package setup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestProfileComponents_JA4(t *testing.T) {
	cp := ProfileComponents(ProfileControlPlane)
	hasJA4 := false
	for _, c := range cp {
		if c == "ja4" {
			hasJA4 = true
			break
		}
	}
	if !hasJA4 {
		t.Errorf("ProfileControlPlane expected ja4, got: %v", cp)
	}

	agent := ProfileComponents(ProfileAgent)
	hasJA4 = false
	hasMalware := false
	for _, c := range agent {
		if c == "ja4" {
			hasJA4 = true
		}
		if c == "malware" {
			hasMalware = true
		}
	}
	if !hasJA4 {
		t.Errorf("ProfileAgent expected ja4, got: %v", agent)
	}
	if !hasMalware {
		t.Errorf("ProfileAgent expected malware, got: %v", agent)
	}
}

func TestFetchAll_Malware(t *testing.T) {
	stubMalwareFeed(t, 200, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	tmpDir := t.TempDir()

	cfg := FetchConfig{
		Dir:   tmpDir,
		Only:  []string{"malware"},
		Force: false,
		Log:   func(format string, args ...any) {},
	}

	results := FetchAll(context.Background(), cfg)
	if len(results) != 2 {
		t.Fatalf("expected 2 results (bloom + hashes), got %d", len(results))
	}
	for _, r := range results {
		if r.Err != nil {
			t.Fatalf("component %s unexpected error: %v", r.Component, r.Err)
		}
		if r.Skipped {
			t.Fatalf("component %s expected not skipped on initial fetch", r.Component)
		}
	}

	bloomPath := filepath.Join(tmpDir, "malware", "malware_bloom.bin")
	hashesPath := filepath.Join(tmpDir, "malware", "malware_hashes.txt")

	if fi, err := os.Stat(bloomPath); err != nil || fi.Size() == 0 {
		t.Fatalf("expected malware_bloom.bin to exist and be non-empty")
	}
	if fi, err := os.Stat(hashesPath); err != nil || fi.Size() == 0 {
		t.Fatalf("expected malware_hashes.txt to exist and be non-empty")
	}

	// Fetch again without force -> should skip
	results2 := FetchAll(context.Background(), cfg)
	if len(results2) != 2 || !results2[0].Skipped || !results2[1].Skipped {
		t.Fatalf("expected second fetch to be skipped, got: %+v", results2)
	}

	// Fetch with force -> should not skip
	cfg.Force = true
	results3 := FetchAll(context.Background(), cfg)
	if len(results3) != 2 || results3[0].Skipped || results3[1].Skipped {
		t.Fatalf("expected forced fetch not to be skipped, got: %+v", results3)
	}
}

func TestFetchAll_JA4(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := FetchConfig{
		Dir:   tmpDir,
		Only:  []string{"ja4"},
		Force: false,
		Log:   func(format string, args ...any) {},
	}

	results := FetchAll(context.Background(), cfg)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Err != nil {
		t.Fatalf("unexpected error: %v", results[0].Err)
	}
	if results[0].Skipped {
		t.Fatalf("expected first fetch not to be skipped")
	}

	ja4Path := filepath.Join(tmpDir, "ja4", "ja4.txt")
	ja4AllowPath := filepath.Join(tmpDir, "ja4", "ja4_allowlist.txt")

	if fi, err := os.Stat(ja4Path); err != nil || fi.Size() == 0 {
		t.Fatalf("expected ja4.txt to exist and be non-empty")
	}
	if fi, err := os.Stat(ja4AllowPath); err != nil || fi.Size() == 0 {
		t.Fatalf("expected ja4_allowlist.txt to exist and be non-empty")
	}

	// Fetch again without force -> should skip
	results2 := FetchAll(context.Background(), cfg)
	if len(results2) != 1 || !results2[0].Skipped {
		t.Fatalf("expected second fetch to be skipped, got: %+v", results2)
	}

	// Fetch with force -> should not skip
	cfg.Force = true
	results3 := FetchAll(context.Background(), cfg)
	if len(results3) != 1 || results3[0].Skipped {
		t.Fatalf("expected forced fetch not to be skipped, got: %+v", results3)
	}
}
