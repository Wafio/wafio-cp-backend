package agentv1

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/wire_fields.golden from the proto")

// wireFields lists every field of the agent protocol by number, kind and
// oneof, and every reserved number and name, one line each.
func wireFields() []string {
	var lines []string
	msgs := File_agent_v1_agent_control_proto.Messages()
	for i := 0; i < msgs.Len(); i++ {
		m := msgs.Get(i)
		fields := m.Fields()
		for j := 0; j < fields.Len(); j++ {
			f := fields.Get(j)
			line := fmt.Sprintf("%s %d %s %s %s", m.FullName(), f.Number(), f.Name(), f.Cardinality(), f.Kind())
			if f.Kind() == protoreflect.MessageKind {
				line += " " + string(f.Message().FullName())
			}
			if o := f.ContainingOneof(); o != nil && !o.IsSynthetic() {
				line += " oneof=" + string(o.Name())
			}
			if f.HasPresence() && f.ContainingOneof() != nil && f.ContainingOneof().IsSynthetic() {
				line += " optional"
			}
			lines = append(lines, line)
		}
		ranges := m.ReservedRanges()
		for j := 0; j < ranges.Len(); j++ {
			r := ranges.Get(j)
			lines = append(lines, fmt.Sprintf("%s reserved %d-%d", m.FullName(), r[0], r[1]-1))
		}
		names := m.ReservedNames()
		for j := 0; j < names.Len(); j++ {
			lines = append(lines, fmt.Sprintf("%s reserved %q", m.FullName(), names.Get(j)))
		}
	}
	sort.Strings(lines)
	return lines
}

// An agent and a control plane of different releases share this stream, so a
// field keeps its number, name, kind and oneof for ever, and a removed number
// stays reserved. testdata/wire_fields.golden is the record. A new field adds
// lines to it; a changed or missing line breaks an agent that is already
// installed, so it fails here instead.
func TestWireFieldsKeepTheirNumbers(t *testing.T) {
	if *updateGolden {
		if err := os.WriteFile("testdata/wire_fields.golden", []byte(strings.Join(wireFields(), "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile("testdata/wire_fields.golden")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		want[l] = true
	}
	got := map[string]bool{}
	for _, l := range wireFields() {
		got[l] = true
		if !want[l] {
			t.Errorf("not in testdata/wire_fields.golden (a new field: add the line): %s", l)
		}
	}
	for l := range want {
		if !got[l] {
			t.Errorf("in testdata/wire_fields.golden but gone from the proto (an installed agent depends on it): %s", l)
		}
	}
}
