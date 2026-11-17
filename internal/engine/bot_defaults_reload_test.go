package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReloadDefaultJA4(t *testing.T) {
	tmpDir := t.TempDir()
	blockFile := filepath.Join(tmpDir, "ja4.txt")
	allowFile := filepath.Join(tmpDir, "ja4_allowlist.txt")

	err := os.WriteFile(blockFile, []byte("t13d1516h2_custom_test1 custom bot\n"), 0o644)
	if err != nil {
		t.Fatalf("write blockFile: %v", err)
	}
	err = os.WriteFile(allowFile, []byte("t13d1516h2_custom_allow1 custom browser\n"), 0o644)
	if err != nil {
		t.Fatalf("write allowFile: %v", err)
	}

	t.Setenv("WAFIO_JA4_BLACKLIST_FILE", blockFile)
	t.Setenv("WAFIO_JA4_ALLOWLIST_FILE", allowFile)

	ReloadDefaultJA4()

	blocks := DefaultJA4Blocklist()
	allows := DefaultJA4Allowlist()

	if len(blocks) != 1 || blocks[0] != "t13d1516h2_custom_test1" {
		t.Fatalf("expected 1 custom block, got: %v", blocks)
	}
	if len(allows) != 1 || allows[0] != "t13d1516h2_custom_allow1" {
		t.Fatalf("expected 1 custom allow, got: %v", allows)
	}

	// Update files and reload
	_ = os.WriteFile(blockFile, []byte("t13d1516h2_custom_test2 updated bot\n"), 0o644)
	ReloadDefaultJA4()

	blocks2 := DefaultJA4Blocklist()
	if len(blocks2) != 1 || blocks2[0] != "t13d1516h2_custom_test2" {
		t.Fatalf("expected updated block, got: %v", blocks2)
	}
}

func TestReloadDefaultBadBotUA(t *testing.T) {
	tmpDir := t.TempDir()
	uaFile := filepath.Join(tmpDir, "bot.txt")

	err := os.WriteFile(uaFile, []byte("^badbot_v1.*\n"), 0o644)
	if err != nil {
		t.Fatalf("write uaFile: %v", err)
	}

	t.Setenv("WAFIO_UA_BAD_BOT_FILE", uaFile)

	ReloadDefaultBadBotUA()

	list := DefaultBadBotUABlocklist()
	if len(list) != 1 || list[0] != "^badbot_v1.*" {
		t.Fatalf("expected ^badbot_v1.*, got: %v", list)
	}

	// Update and reload
	_ = os.WriteFile(uaFile, []byte("^badbot_v2.*\n^badbot_v3.*\n"), 0o644)
	ReloadDefaultBadBotUA()

	list2 := DefaultBadBotUABlocklist()
	if len(list2) != 2 || list2[0] != "^badbot_v2.*" {
		t.Fatalf("expected updated UA list, got: %v", list2)
	}
}
