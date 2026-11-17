package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReloadDefaultJA4(t *testing.T) {
	tmpDir := t.TempDir()
	blockFile := filepath.Join(tmpDir, "ja4.txt")

	err := os.WriteFile(blockFile, []byte("t13d1516h2_custom_test1 custom bot\n"), 0o644)
	if err != nil {
		t.Fatalf("write blockFile: %v", err)
	}

	t.Setenv("WAFIO_JA4_BLACKLIST_FILE", blockFile)

	ReloadDefaultJA4()

	blocks := DefaultJA4Blocklist()

	if len(blocks) != 1 || blocks[0] != "t13d1516h2_custom_test1" {
		t.Fatalf("expected 1 custom block, got: %v", blocks)
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
