package repository

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"testing"
)

func TestFirewallEvidenceCountersSurviveColdMetricsAndAggregation(t *testing.T) {
	_, pool, project := incidentTestSetup(t)
	defer pool.Close()
	ctx := context.Background()
	var user string
	if err := pool.QueryRow(ctx, `SELECT user_id FROM projects WHERE id=$1`, project).Scan(&user); err != nil {
		t.Fatal(err)
	}
	agent := uuid.NewString()
	payload, err := json.Marshal(EBPFMetricsRow{WouldDropPackets: 19, WouldDropBytes: 200, StateTableFull: 3, PacketParseFailures: 4, DroppedPackets: 2})
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO agents(id,user_id,project_id,name,kind,last_metrics_json) VALUES($1,$2,$3,$4,'host',$5)`, agent, user, project, agent, payload)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = pool.Exec(ctx, `DELETE FROM agents WHERE id=$1`, agent) }()
	repo := &EBPFRepo{pool: pool}
	for _, aggregate := range []bool{false, true} {
		var row *EBPFMetricsRow
		if aggregate {
			row, err = repo.AggregateMetrics(ctx, []string{agent})
		} else {
			row, err = repo.LatestMetrics(ctx, agent)
		}
		if err != nil {
			t.Fatal(err)
		}
		if row.WouldDropPackets != 19 || row.WouldDropBytes != 200 || row.StateTableFull != 3 || row.PacketParseFailures != 4 || row.DroppedPackets != 2 {
			t.Fatalf("counter evidence lost: %+v", row)
		}
	}
}
