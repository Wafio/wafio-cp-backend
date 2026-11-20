package agentv1

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// olderSchema returns the descriptor of msg as a reader built before the
// certificate messages has it: the current file without the oneof member
// numbered drop.
func olderSchema(t *testing.T, msg protoreflect.Name, drop int32) protoreflect.MessageDescriptor {
	t.Helper()
	fdp := protodesc.ToFileDescriptorProto(File_agent_v1_agent_control_proto)
	for _, m := range fdp.MessageType {
		if m.GetName() != string(msg) {
			continue
		}
		kept := m.Field[:0]
		for _, f := range m.Field {
			if f.GetNumber() != drop {
				kept = append(kept, f)
			}
		}
		m.Field = kept
	}
	fd, err := protodesc.NewFile(fdp, nil)
	if err != nil {
		t.Fatal(err)
	}
	return fd.Messages().ByName(msg)
}

// A reader built before the certificate messages decodes a frame that holds
// one without an error, with no member of the kind oneof set and the bytes
// kept as an unknown field. The receive loops of the WAF agent, the host
// agent and the server all skip a frame with no known kind.
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
	ping, err := proto.Marshal(&ServerMessage{Kind: &ServerMessage_Ping{Ping: &Ping{Nonce: 7}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		msg   protoreflect.Name
		drop  int32
		frame []byte
	}{
		{"CertificateInstall", "ServerMessage", 7, server},
		{"CertificateStatus", "AgentMessage", 5, agent},
	} {
		desc := olderSchema(t, tc.msg, tc.drop)
		old := dynamicpb.NewMessage(desc)
		if err := proto.Unmarshal(tc.frame, old); err != nil {
			t.Fatalf("%s: an older reader fails to decode it: %v", tc.name, err)
		}
		if f := old.WhichOneof(desc.Oneofs().ByName("kind")); f != nil {
			t.Fatalf("%s: an older reader sees it as %s", tc.name, f.Name())
		}
		if len(old.GetUnknown()) == 0 {
			t.Fatalf("%s: an older reader did not keep it as an unknown field", tc.name)
		}
	}
	// The older schema still decodes a message it knows.
	desc := olderSchema(t, "ServerMessage", 7)
	old := dynamicpb.NewMessage(desc)
	if err := proto.Unmarshal(ping, old); err != nil {
		t.Fatal(err)
	}
	if f := old.WhichOneof(desc.Oneofs().ByName("kind")); f == nil || f.Name() != "ping" {
		t.Fatalf("older schema on a Ping: %v", f)
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

// The private key field carries debug_redact, so a formatter that honours the
// option leaves it out.
func TestCertificateKeyIsMarkedRedacted(t *testing.T) {
	f := (&CertificateInstall{}).ProtoReflect().Descriptor().Fields().ByName("key_pem")
	if f == nil || !protodesc.ToFieldDescriptorProto(f).GetOptions().GetDebugRedact() {
		t.Fatal("CertificateInstall.key_pem is not marked debug_redact")
	}
}
