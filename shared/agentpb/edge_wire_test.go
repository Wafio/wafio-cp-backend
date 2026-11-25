package agentv1

import (
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// A reader of shared/v0.3.0 has the certificate messages and not the edge
// ones. It decodes a frame that holds EdgeStatus or CachePurge without an
// error, with no member of the kind oneof set and the bytes kept as an unknown
// field, which the receive loops of the agents and the server skip.
func TestEdgeMessagesAreUnknownToOlderReaders(t *testing.T) {
	agent, err := proto.Marshal(&AgentMessage{Kind: &AgentMessage_EdgeStatus{EdgeStatus: &EdgeStatus{
		AppId: "a1", Generation: 7, UnixTime: 1,
		Features: []*EdgeFeatureState{{Feature: "cache", State: "refused", Code: "cache_dir_unusable", Detail: "/var/cache/wafio-waf"}},
		Cache:    &EdgeCacheCounters{Requests: 10, HitsMemory: 4, DiskBytes: 1 << 20},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	server, err := proto.Marshal(&ServerMessage{Kind: &ServerMessage_CachePurge{CachePurge: &CachePurge{
		CommandId: "c1", AppId: "a1", Scope: "prefix", Url: "/assets/",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := proto.Marshal(&AgentMessage{Kind: &AgentMessage_CertificateStatus{CertificateStatus: &CertificateStatus{AppId: "a1", State: "active"}}})
	if err != nil {
		t.Fatal(err)
	}
	install, err := proto.Marshal(&ServerMessage{Kind: &ServerMessage_CertificateInstall{CertificateInstall: &CertificateInstall{CommandId: "c2", AppId: "a1"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		msg   protoreflect.Name
		drop  int32
		frame []byte
	}{
		{"EdgeStatus", "AgentMessage", 6, agent},
		{"CachePurge", "ServerMessage", 8, server},
	} {
		desc := olderSchema(t, tc.msg, tc.drop)
		old := dynamicpb.NewMessage(desc)
		if err := proto.Unmarshal(tc.frame, old); err != nil {
			t.Fatalf("%s: a v0.3.0 reader fails to decode it: %v", tc.name, err)
		}
		if f := old.WhichOneof(desc.Oneofs().ByName("kind")); f != nil {
			t.Fatalf("%s: a v0.3.0 reader sees it as %s", tc.name, f.Name())
		}
		if len(old.GetUnknown()) == 0 {
			t.Fatalf("%s: a v0.3.0 reader did not keep it as an unknown field", tc.name)
		}
	}
	// The v0.3.0 schema still reads the messages it knows.
	for _, tc := range []struct {
		msg   protoreflect.Name
		drop  int32
		frame []byte
		want  protoreflect.Name
	}{
		{"AgentMessage", 6, cert, "certificate_status"},
		{"ServerMessage", 8, install, "certificate_install"},
	} {
		desc := olderSchema(t, tc.msg, tc.drop)
		old := dynamicpb.NewMessage(desc)
		if err := proto.Unmarshal(tc.frame, old); err != nil {
			t.Fatal(err)
		}
		if f := old.WhichOneof(desc.Oneofs().ByName("kind")); f == nil || f.Name() != tc.want {
			t.Fatalf("v0.3.0 schema on %s: %v", tc.want, f)
		}
	}
	// The current reader decodes both back.
	var a AgentMessage
	if err := proto.Unmarshal(agent, &a); err != nil {
		t.Fatal(err)
	}
	es := a.GetEdgeStatus()
	if es.GetAppId() != "a1" || es.GetGeneration() != 7 || es.GetUnixTime() != 1 ||
		len(es.GetFeatures()) != 1 || es.GetFeatures()[0].GetCode() != "cache_dir_unusable" ||
		es.GetCache().GetHitsMemory() != 4 || es.GetCache().GetDiskBytes() != 1<<20 || es.GetCompression() != nil {
		t.Fatalf("EdgeStatus round trip: %v", es)
	}
	var s ServerMessage
	if err := proto.Unmarshal(server, &s); err != nil {
		t.Fatal(err)
	}
	if p := s.GetCachePurge(); p.GetCommandId() != "c1" || p.GetAppId() != "a1" || p.GetScope() != "prefix" || p.GetUrl() != "/assets/" {
		t.Fatalf("CachePurge round trip: %v", p)
	}
}
