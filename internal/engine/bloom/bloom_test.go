package bloom

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestBloomRejectsInvalidGeometry(t *testing.T) {
	var buf bytes.Buffer
	_, err := NewFilter(10, .01).WriteTo(&buf)
	if err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	binary.LittleEndian.PutUint64(data[16:24], 0)
	if _, err := ReadFrom(bytes.NewReader(data)); err == nil {
		t.Fatal("zero modulus accepted")
	}
}

func TestLegacyUnverifiedSeedMigration(t *testing.T) {
	hash := "5443a5160ddfe2eb7c34d3cb38e0787fa3f1396b7ff036c04f494f6f89efec69"
	e := NewMalwareHashEngine(10, .01)
	text := hash + " Webshell.PHP.ChinaChopper.v1\n275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f EICAR.Standard.Antivirus.Test\n"
	if count, err := e.LoadFromTextReader(strings.NewReader(text)); err != nil || count != 1 {
		t.Fatalf("legacy unverified seed not retired: count=%d err=%v", count, err)
	}
	// An independently sourced feed entry is allowed to establish the same hash again.
	if count, err := e.LoadFromTextReader(strings.NewReader(hash + " Malware.MalwareBazaar\n")); err != nil || count != 1 {
		t.Fatal("feed-sourced hash was discarded")
	}
}
