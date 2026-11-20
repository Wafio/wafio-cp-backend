package agentv1

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

var updateGolden = flag.Bool("update", false, "add the new lines of the proto to testdata/wire_fields.golden")

const wireFieldsGolden = "testdata/wire_fields.golden"

// wireFields lists every field of the agent protocol, nested messages
// included, by number, kind and oneof, and every reserved number and name,
// one line each.
func wireFields() []string {
	var lines []string
	var walk func(protoreflect.MessageDescriptors)
	walk = func(msgs protoreflect.MessageDescriptors) {
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
			walk(m.Messages())
		}
	}
	walk(File_agent_v1_agent_control_proto.Messages())
	sort.Strings(lines)
	return lines
}

func readWireFieldsGolden(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(wireFieldsGolden)
	if errors.Is(err, fs.ErrNotExist) && *updateGolden {
		return map[string]bool{}
	}
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		want[l] = true
	}
	return want
}

// An agent and a control plane of different releases share this stream, so a
// field keeps its number, name, kind and oneof for ever, and a removed number
// stays reserved. testdata/wire_fields.golden is the record. A new field adds
// lines to it; a changed or missing line breaks an agent that is already
// installed, so it fails here, also under -update, which only adds lines.
func TestWireFieldsKeepTheirNumbers(t *testing.T) {
	want := readWireFieldsGolden(t)
	current := wireFields()
	got := map[string]bool{}
	for _, l := range current {
		got[l] = true
		if !want[l] && !*updateGolden {
			t.Errorf("not in %s (a new field: run with -update to add the line): %s", wireFieldsGolden, l)
		}
	}
	for l := range want {
		if !got[l] {
			t.Errorf("in %s but gone from the proto (an installed agent depends on it): %s", wireFieldsGolden, l)
		}
	}
	if *updateGolden && !t.Failed() {
		if err := os.WriteFile(wireFieldsGolden, []byte(strings.Join(current, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
