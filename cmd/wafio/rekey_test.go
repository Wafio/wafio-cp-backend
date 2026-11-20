package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

const (
	rekeyOldHex = "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"
	rekeyNewHex = "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b"
)

func TestRekeyKeysAcceptsTwoDifferentKeys(t *testing.T) {
	oldKey, newKey, err := rekeyKeys(rekeyOldHex, rekeyNewHex)
	if err != nil || oldKey == nil || newKey == nil || oldKey.KeyID() == newKey.KeyID() {
		t.Fatalf("%v %v %v", oldKey, newKey, err)
	}
	// The new key may be base64 and the old one hex, and white space around a key is ignored.
	raw, _ := hex.DecodeString(rekeyNewHex)
	if _, _, err := rekeyKeys(" "+rekeyOldHex+"\n", base64.StdEncoding.EncodeToString(raw)); err != nil {
		t.Fatalf("base64 key: %v", err)
	}
}

func TestRekeyKeysRefuses(t *testing.T) {
	raw, _ := hex.DecodeString(rekeyOldHex)
	oldAsBase64 := base64.StdEncoding.EncodeToString(raw)
	for name, c := range map[string]struct {
		old, new string
		want     string
	}{
		"no old key":               {"", rekeyNewHex, oldKeyEnv},
		"a blank old key":          {"  \n", rekeyNewHex, oldKeyEnv},
		"no new key":               {rekeyOldHex, "", "totp.enc_key is not set"},
		"a blank new key":          {rekeyOldHex, " ", "totp.enc_key is not set"},
		"neither":                  {"", "", oldKeyEnv},
		"the same key":             {rekeyOldHex, rekeyOldHex, "the same key"},
		"the same key, base64":     {rekeyOldHex, oldAsBase64, "the same key"},
		"the same key, base64 old": {oldAsBase64, rekeyOldHex, "the same key"},
		"an old key too short":     {"abcd", rekeyNewHex, oldKeyEnv + " is not a valid key"},
		"an old key, not a key":    {"not a key at all!", rekeyNewHex, oldKeyEnv + " is not a valid key"},
		"a new key too short":      {rekeyOldHex, "abcd", "totp.enc_key is not a valid key"},
	} {
		oldKey, newKey, err := rekeyKeys(c.old, c.new)
		if err == nil || oldKey != nil || newKey != nil {
			t.Errorf("%s: accepted (%v)", name, err)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q lacks %q", name, err, c.want)
		}
		// An error names the variable or the setting, never a key.
		for _, secret := range []string{rekeyOldHex, rekeyNewHex, oldAsBase64, "not a key at all"} {
			if secret != "" && strings.Contains(err.Error(), secret) {
				t.Errorf("%s: the error prints a key: %q", name, err)
			}
		}
	}
}

// The command checks its keys before it opens a connection: the database below does not exist, and
// no refusal mentions it.
func TestRekeyCommandRefusesBeforeTheDatabase(t *testing.T) {
	t.Setenv("WAFIO_DATABASE_HOST", "127.0.0.1")
	t.Setenv("WAFIO_DATABASE_PORT", "1")
	t.Setenv("WAFIO_DATABASE_NAME", "none")
	for name, c := range map[string]struct{ old, new, want string }{
		"no old key":     {"", rekeyNewHex, oldKeyEnv + " is not set"},
		"no new key":     {rekeyOldHex, "", "totp.enc_key is not set"},
		"the same key":   {rekeyOldHex, rekeyOldHex, "the same key"},
		"an invalid key": {"zz", rekeyNewHex, "not a valid key"},
	} {
		t.Setenv(oldKeyEnv, c.old)
		t.Setenv("WAFIO_TOTP_ENC_KEY", c.new)
		var out bytes.Buffer
		rekeyCmd.SetOut(&out)
		err := runRekey(rekeyCmd, nil)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q, want one with %q", name, err, c.want)
		}
		if strings.Contains(err.Error(), "connect") || out.Len() != 0 {
			t.Errorf("%s: went on to the database (%v, output %q)", name, err, out.String())
		}
		// The old key is out of the environment once it has been read, refusal or not.
		if v, set := os.LookupEnv(oldKeyEnv); set || v != "" {
			t.Errorf("%s: %s is still in the environment", name, oldKeyEnv)
		}
	}
}

func TestRekeyCommandIsADryRunByDefault(t *testing.T) {
	flag := rekeyCmd.Flags().Lookup("apply")
	if flag == nil || flag.DefValue != "false" || flag.Value.Type() != "bool" {
		t.Fatalf("the apply flag: %+v", flag)
	}
	if rekeyCmd.Args == nil || rekeyCmd.Args(rekeyCmd, []string{"extra"}) == nil {
		t.Error("the command takes an argument")
	}
	found := false
	for _, c := range rootCmd.Commands() {
		if c == rekeyCmd {
			found = true
		}
	}
	if !found {
		t.Error("rekey is not a command of wafio")
	}
}

func rekeyReportFixture() repository.RekeyReport {
	return repository.RekeyReport{Counts: []repository.RekeyCount{
		{Kind: repository.RekeyKindTOTPSecret, ToRewrite: 12, AlreadyNew: 1, NotSealed: 2},
		{Kind: repository.RekeyKindTOTPPending},
		{Kind: repository.RekeyKindSMTPPassword, ToRewrite: 1},
		{Kind: repository.RekeyKindMalwareKey},
		{Kind: repository.RekeyKindCertificateKey, ToRewrite: 4},
	}}
}

func TestPrintRekeyReportDryRun(t *testing.T) {
	var out bytes.Buffer
	printRekeyReport(&out, rekeyReportFixture(), false, nil)
	text := out.String()
	for _, want := range []string{
		"dry run, nothing is changed", "TO REWRITE", "ALREADY NEW KEY", "PLAIN TEXT", "UNREADABLE",
		"TOTP secrets of users", "certificate private keys",
		"Dry run: 17 values would be rewritten. Run again with --apply to do it.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Rewrote") {
		t.Errorf("a dry run says it rewrote:\n%s", text)
	}
	if strings.Contains(text, "\u2014") {
		t.Error("an em dash in the output")
	}

	out.Reset()
	printRekeyReport(&out, repository.RekeyReport{Counts: []repository.RekeyCount{{Kind: repository.RekeyKindTOTPSecret, AlreadyNew: 3}}}, false, nil)
	if !strings.Contains(out.String(), "Dry run: nothing to rewrite.") {
		t.Errorf("output:\n%s", out.String())
	}
}

func TestPrintRekeyReportApplied(t *testing.T) {
	r := rekeyReportFixture()
	r.Applied = true
	var out bytes.Buffer
	printRekeyReport(&out, r, true, nil)
	text := out.String()
	if !strings.Contains(text, "(apply)") || !strings.Contains(text, "Rewrote 17 values in one transaction. Start the control plane with the new totp.enc_key.") {
		t.Errorf("output:\n%s", text)
	}
	if strings.Contains(text, "Dry run") {
		t.Errorf("an applied run says dry run:\n%s", text)
	}
}

func TestPrintRekeyReportNamesUnreadableRows(t *testing.T) {
	r := rekeyReportFixture()
	r.Counts[0].Unreadable = 3
	r.Counts[0].UnreadableRows = []string{"user 5d3c0000-0000-4000-8000-000000000001"}
	r.Counts[4].Unreadable = 1
	r.Counts[4].UnreadableRows = []string{"certificate 7a7a0000-0000-4000-8000-000000000002"}
	var out bytes.Buffer
	printRekeyReport(&out, r, true, repository.ErrRekeyUnreadable)
	text := out.String()
	for _, want := range []string{
		"Opens with neither key: user 5d3c0000-0000-4000-8000-000000000001 (totp_secret)",
		"... and 2 more of totp_secret",
		"Opens with neither key: certificate 7a7a0000-0000-4000-8000-000000000002 (certificate_key)",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Rewrote") || strings.Contains(text, "would be rewritten") {
		t.Errorf("a refused run reports a rewrite:\n%s", text)
	}
}

func TestPrintRekeyReportWithoutCountsPrintsNothing(t *testing.T) {
	var out bytes.Buffer
	printRekeyReport(&out, repository.RekeyReport{}, true, errors.New("connection refused"))
	if out.Len() != 0 {
		t.Errorf("output %q", out.String())
	}
}
