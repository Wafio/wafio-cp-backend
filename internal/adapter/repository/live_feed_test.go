package repository

import (
	"testing"
	"time"
)

// The live host stream resumes by arrival sequence. A row that arrives
// after a poll is returned by the next one even when the agent recorded it
// in the same second as the poll, or earlier (late batch, clock behind).
func TestLiveFeedsReturnLateRowsByArrival(t *testing.T) {
	var fw fwRingBuffer
	fw.add([]fwEventInMem{{Ts: 100, SrcIP: "first"}})
	got, cur := fw.afterSeq(0, 0)
	if len(got) != 1 || cur != 1 {
		t.Fatalf("first poll: %d rows cursor %d", len(got), cur)
	}
	// Arrives after the poll, stamped earlier than the first event.
	fw.add([]fwEventInMem{{Ts: 99, SrcIP: "late"}, {Ts: 100, SrcIP: "same-second"}})
	got, cur = fw.afterSeq(cur, 0)
	if len(got) != 2 || got[0].SrcIP != "same-second" || got[1].SrcIP != "late" || cur != 3 {
		t.Fatalf("second poll: %+v cursor %d, want both late rows newest first", got, cur)
	}
	if got, _ := fw.afterSeq(cur, 0); len(got) != 0 {
		t.Fatalf("third poll re-sent %d rows", len(got))
	}

	c := newTraceEventCache()
	base := time.Unix(1000, 0)
	c.push(liveTenant{}, "a", []TraceEventRow{{EventTime: base, Comm: "one"}})
	rows, tcur := c.afterSeq("a", c.cursor("a")-1, 0)
	if len(rows) != 1 || tcur != 1 {
		t.Fatalf("trace first poll: %d rows cursor %d", len(rows), tcur)
	}
	c.push(liveTenant{}, "a", []TraceEventRow{{EventTime: base.Add(-5 * time.Second), Comm: "late"}})
	rows, tcur = c.afterSeq("a", tcur, 0)
	if len(rows) != 1 || rows[0].Comm != "late" || tcur != 2 {
		t.Fatalf("trace second poll: %+v cursor %d", rows, tcur)
	}
	// An outcome update changes a row in place and is not a new arrival.
	c.push(liveTenant{}, "a", []TraceEventRow{{EventTime: base, Comm: "one", OutcomeUpdate: true}})
	if rows, _ := c.afterSeq("a", tcur, 0); len(rows) != 0 {
		t.Fatalf("outcome update re-sent as %d new rows", len(rows))
	}

	var enf liveFeed[EnforcementLogRow]
	enf.size = 3
	enf.push(liveTenant{}, "a", []EnforcementLogRow{{PolicyName: "p1"}}, nil)
	rowsE, ecur := enf.after("a", 0, 0)
	if len(rowsE) != 1 || ecur != 1 {
		t.Fatalf("enforcement first poll: %d rows cursor %d", len(rowsE), ecur)
	}
	enf.push(liveTenant{}, "a", []EnforcementLogRow{{PolicyName: "p2"}, {PolicyName: "p3"}, {PolicyName: "p4"}}, nil)
	rowsE, ecur = enf.after("a", ecur, 2)
	if len(rowsE) != 2 || rowsE[0].PolicyName != "p4" || rowsE[1].PolicyName != "p3" || ecur != 4 {
		t.Fatalf("enforcement second poll (limit 2): %+v cursor %d", rowsE, ecur)
	}
	if rowsE, _ := enf.after("a", 0, 0); len(rowsE) != 3 {
		t.Fatalf("ring holds %d rows, want the size cap 3", len(rowsE))
	}
	if rowsE, c := enf.after("unknown", 7, 0); rowsE != nil || c != 7 {
		t.Fatal("unknown agent must keep the cursor")
	}
}

// The enforcement live feed is bounded in agents and bytes. Agent
// rows are agent-supplied, so one tenant cycling agent names, or sending
// huge rows, used to pin memory without limit.
func TestLiveFeedBounded(t *testing.T) {
	f := liveFeed[EnforcementLogRow]{maxRings: 4, maxBytes: 4096}
	big := EnforcementLogRow{EventData: make([]byte, 8192)}
	mid := EnforcementLogRow{EventData: make([]byte, 1500)}
	cur := f.cursor("victim")
	f.push(liveTenant{}, "victim", []EnforcementLogRow{{PolicyName: "v1"}}, enforcementRowBytes)
	for i := range 100 {
		f.push(liveTenant{}, "flood-"+string(rune('a'+i%26))+string(rune('a'+i/26)), []EnforcementLogRow{mid}, enforcementRowBytes)
	}
	if f.rings.len() != 4 {
		t.Fatalf("feed holds %d agents, want the cap 4", f.rings.len())
	}
	// The victim's ring was evicted; when it comes back its rows still sort
	// after the cursor it was handed before.
	f.push(liveTenant{}, "victim", []EnforcementLogRow{{PolicyName: "v2"}}, enforcementRowBytes)
	if rows, _ := f.after("victim", cur, 0); len(rows) != 1 || rows[0].PolicyName != "v2" {
		t.Fatalf("after re-creation: %+v", rows)
	}
	// Byte budget: a row over the budget is not kept; rows are trimmed to it.
	f.push(liveTenant{}, "x", []EnforcementLogRow{big, mid, mid, mid, mid}, enforcementRowBytes)
	rows, _ := f.after("x", 0, 0)
	if len(rows) != 2 {
		t.Fatalf("budget kept %d rows of ~1.6 KiB in 4 KiB, want 2", len(rows))
	}
	if f.rings.get("x").bytes > 4096 {
		t.Fatal("ring over its byte budget")
	}
}
