package agentserver

import (
	"context"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// An agent name with a terminal escape, a C1
// control or a bidi/format character (or longer than agents.name) is refused
// before any lookup, so it is never registered. The repository is empty: the
// check runs before it is used.
func TestValidateHelloRefusesUnsafeAgentName(t *testing.T) {
	s := &Server{Repo: &repository.Repository{}}
	for _, name := range []string{
		"\x1b]0;pwn\x07", "web\x1b[2J", "c1\u009b31m", "rtl\u202ex", "zw\u200bx", strings.Repeat("a", 256),
	} {
		hello := &agentv1.Hello{AgentName: name, AgentKind: "waf"}
		_, _, _, err := s.validateHello(context.Background(), "p1", hello)
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("agent_name %q: err=%v, want InvalidArgument", name, err)
		}
	}
	// An empty name falls back to <hostname>@ebpf, held to the same rule.
	hello := &agentv1.Hello{Hostname: "evil\x1b]52;c;eA==\x07", AgentKind: "host"}
	if _, _, _, err := s.validateHello(context.Background(), "p1", hello); status.Code(err) != codes.InvalidArgument {
		t.Errorf("hostname fallback: err=%v, want InvalidArgument", err)
	}
}
