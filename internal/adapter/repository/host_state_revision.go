package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/jackc/pgx/v5"
)

var ErrDesiredStateConflict = errors.New("desired state changed concurrently")

// DesiredStateRevision parses the integer token without float64 conversion.
func DesiredStateRevision(raw json.RawMessage) (int64, error) {
	var state map[string]json.RawMessage
	if err := json.Unmarshal(raw, &state); err != nil {
		return 0, err
	}
	token := state["_revision"]
	if len(token) == 0 {
		return 0, nil
	}
	var text string
	if token[0] == '"' {
		if err := json.Unmarshal(token, &text); err != nil {
			return 0, err
		}
	} else {
		text = string(token)
	}
	rev, err := strconv.ParseInt(text, 10, 64)
	if err != nil || rev < 0 {
		return 0, fmt.Errorf("invalid desired state revision")
	}
	return rev, nil
}

// CompareAndSwapDesiredState commits the revision and complete state together.
// The DB clock supplies the legacy-compatible epoch scale; previous+1 remains
// monotonic across clock regressions and concurrent control-plane instances.
func (r *EBPFRepo) CompareAndSwapDesiredState(ctx context.Context, projectID, agentID string, expected int64, state json.RawMessage) (json.RawMessage, error) {
	var stored json.RawMessage
	err := r.pool.QueryRow(ctx, `UPDATE agents SET desired_state=jsonb_set($1::jsonb,'{_revision}',to_jsonb(GREATEST(COALESCE((desired_state->>'_revision')::bigint,0)+1,(extract(epoch from clock_timestamp())*1000000000)::bigint)::text))
 WHERE deleted_at IS NULL AND id=$2 AND project_id=$3 AND COALESCE((desired_state->>'_revision')::bigint,0)=$4 RETURNING desired_state`, state, agentID, projectID, expected).Scan(&stored)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDesiredStateConflict
	}
	return stored, err
}
