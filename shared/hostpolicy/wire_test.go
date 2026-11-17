package hostpolicy

import (
	"reflect"
	"slices"
	"sort"
	"testing"
)

// wireKeys lists the JSON keys, with their tag options, that a value of the struct type of v
// marshals: exported fields without a json:"-" tag, sorted.
func wireKeys(v any) []string {
	t := reflect.TypeOf(v)
	var keys []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag, ok := f.Tag.Lookup("json")
		if !f.IsExported() || tag == "-" {
			continue
		}
		if !ok {
			tag = f.Name
		}
		keys = append(keys, tag)
	}
	sort.Strings(keys)
	return keys
}

// The lists below were printed by the same function on the commit before these types moved out of
// internal/ebpf. They are what trace events and enforcement policies look like on the wire, so a
// field exported here for the alias (QueuedClass, ConnectBlockAvailable) must stay json:"-", and the
// forward filter digest and the bundle JSON must not change.
func TestWireKeysUnchanged(t *testing.T) {
	for name, tc := range map[string]struct {
		got  []string
		want []string
	}{
		"TraceEvent": {wireKeys(TraceEvent{}), []string{
			"action",
			"action_name",
			"activity_outcome",
			"addr,omitempty",
			"addr_family,omitempty",
			"args,omitempty",
			"args_unreadable,omitempty",
			"category",
			"cgroup_id",
			"comm",
			"container_id,omitempty",
			"container_image,omitempty",
			"container_name,omitempty",
			"cwd,omitempty",
			"description,omitempty",
			"detail,omitempty",
			"event_id,omitempty",
			"event_name",
			"event_type",
			"exe_verified,omitempty",
			"filename,omitempty",
			"flags,omitempty",
			"gid",
			"grandparent_comm,omitempty",
			"is_container,omitempty",
			"is_privileged,omitempty",
			"k8s_namespace,omitempty",
			"k8s_pod,omitempty",
			"k8s_service_account,omitempty",
			"outcome_update,omitempty",
			"parent_comm,omitempty",
			"path_unresolved,omitempty",
			"pid",
			"policy_id,omitempty",
			"port,omitempty",
			"ppid",
			"process_start_ns,omitempty,string",
			"ret_val,omitempty",
			"severity",
			"severity_name",
			"signal_error,omitempty",
			"signal_outcome,omitempty",
			"tid",
			"timestamp",
			"timestamp_ns",
			"uid",
		}},
		"EnforcementPolicy": {wireKeys(EnforcementPolicy{}), []string{
			"action",
			"auto_downgraded",
			"created_at",
			"description",
			"enabled",
			"enforcement_mode",
			"event_types",
			"hit_count",
			"id",
			"kernel_enforce",
			"kernel_enforce_requested",
			"kill_acknowledged,omitempty",
			"match_comm",
			"match_comm_mode",
			"match_dest_ip,omitempty",
			"match_dest_port",
			"match_filename",
			"match_uid",
			"min_severity",
			"mitre_tactic,omitempty",
			"mitre_technique_id,omitempty",
			"mitre_technique_name,omitempty",
			"name",
			"severity,omitempty",
			"tags,omitempty",
			"updated_at",
		}},
	} {
		if !slices.Equal(tc.got, tc.want) {
			t.Errorf("%s wire keys changed:\n got  %q\n want %q", name, tc.got, tc.want)
		}
	}
}
