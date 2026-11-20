package agentv1

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// An agent or control plane built before the certificate messages sees them as
// an unknown oneof field: it decodes the frame with no kind set and keeps the
// stream. Field 7 of ServerMessage and field 5 of AgentMessage were never used
// before, so an older reader cannot mistake them for another message.
func TestCertificateMessagesAreUnknownToOlderReaders(t *testing.T) {
	server, err := proto.Marshal(&ServerMessage{Kind: &ServerMessage_CertificateInstall{CertificateInstall: &CertificateInstall{
		CommandId: "c1", AppId: "a1", CertificateId: "k1", ChainPem: []byte("chain"), KeyPem: []byte("key"), LeafSha256: "00",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := proto.Marshal(&AgentMessage{Kind: &AgentMessage_CertificateStatus{CertificateStatus: &CertificateStatus{
		AppId: "a1", Source: "acme", State: "active", ChainPem: []byte("chain"), LeafSha256: "00", UnixTime: 1,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		frame []byte
		field protowire.Number
		known []protowire.Number // the oneof numbers of shared/v0.1.0
	}{
		{"ServerMessage", server, 7, []protowire.Number{1, 2, 3, 4, 5}},
		{"AgentMessage", agent, 5, []protowire.Number{1, 2, 3, 4}},
	} {
		num, _, n := protowire.ConsumeTag(tc.frame)
		if n < 0 || num != tc.field {
			t.Fatalf("%s: first field %d, want %d", tc.name, num, tc.field)
		}
		for _, k := range tc.known {
			if num == k {
				t.Fatalf("%s: field %d was already in use in shared/v0.1.0", tc.name, num)
			}
		}
		if l := protowire.ConsumeFieldValue(num, protowire.BytesType, tc.frame[n:]); n+l != len(tc.frame) {
			t.Fatalf("%s: frame holds more than the one field", tc.name)
		}
	}
	// The current reader decodes both back.
	var s ServerMessage
	if err := proto.Unmarshal(server, &s); err != nil || string(s.GetCertificateInstall().GetKeyPem()) != "key" {
		t.Fatalf("ServerMessage round trip: %v", err)
	}
	var a AgentMessage
	if err := proto.Unmarshal(agent, &a); err != nil || a.GetCertificateStatus().GetState() != "active" {
		t.Fatalf("AgentMessage round trip: %v", err)
	}
}

// The certificate messages carry key material in exactly one field.
func TestOnlyCertificateInstallCarriesAKey(t *testing.T) {
	var keyFields []string
	msgs := File_agent_v1_agent_control_proto.Messages()
	for i := 0; i < msgs.Len(); i++ {
		m := msgs.Get(i)
		for j := 0; j < m.Fields().Len(); j++ {
			if f := m.Fields().Get(j); strings.Contains(string(f.Name()), "key_pem") {
				keyFields = append(keyFields, string(f.FullName()))
			}
		}
	}
	if len(keyFields) != 1 || keyFields[0] != "wafio.agent.v1.CertificateInstall.key_pem" {
		t.Fatalf("fields that carry a private key: %v", keyFields)
	}
}
