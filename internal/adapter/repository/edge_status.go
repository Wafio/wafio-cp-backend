package repository

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// EdgeFeatureState is one part of an EdgeStatus as the server stores and shows it. The values were
// checked against fixed lists before they got here.
type EdgeFeatureState struct {
	Feature         string `json:"feature"`
	State           string `json:"state"`
	Code            string `json:"code"`
	Detail          string `json:"detail"`
	RunningPrevious bool   `json:"running_previous"`
}

// EdgeStatusReport is what an agent reported for one application, after the checks of the agent
// server. Cache and Compression are JSON objects of counters, nil when the agent sent none.
type EdgeStatusReport struct {
	ProjectID, AgentID, AppID string
	Generation                int64
	Features                  []EdgeFeatureState
	Cache, Compression        json.RawMessage
}

// UpsertEdgeStatus replaces the stored report of the application. It stores nothing, and reports
// false, unless the application is in the project and has an enabled assignment to this agent, and
// unless the report is not older than the stored one from the same agent (a lower generation).
func (r *EdgeRepo) UpsertEdgeStatus(ctx context.Context, rep EdgeStatusReport) (bool, error) {
	feats, err := json.Marshal(rep.Features)
	if err != nil {
		return false, err
	}
	var cache, comp any
	if len(rep.Cache) > 0 {
		cache = string(rep.Cache)
	}
	if len(rep.Compression) > 0 {
		comp = string(rep.Compression)
	}
	tag, err := r.pool.Exec(ctx, `INSERT INTO app_edge_status (app_id, project_id, agent_id, generation, features, cache, compression, received_at)
		SELECT a.id, a.project_id, ag.id, $4, $5::jsonb, $6::jsonb, $7::jsonb, NOW()
		FROM apps a
		JOIN waf_agent_apps waa ON waa.app_id = a.id AND waa.enabled = TRUE
		JOIN agents ag ON ag.id = waa.agent_id AND ag.project_id = a.project_id AND ag.kind = 'waf' AND ag.deleted_at IS NULL
		WHERE a.id = $1 AND a.project_id = $2 AND ag.id = $3
		ON CONFLICT (app_id) DO UPDATE SET agent_id = EXCLUDED.agent_id, generation = EXCLUDED.generation, features = EXCLUDED.features,
			cache = EXCLUDED.cache, compression = EXCLUDED.compression, received_at = NOW()
		WHERE app_edge_status.agent_id <> EXCLUDED.agent_id OR app_edge_status.generation <= EXCLUDED.generation`,
		rep.AppID, rep.ProjectID, rep.AgentID, rep.Generation, string(feats), cache, comp)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// EdgeStatus is a stored report.
type EdgeStatus struct {
	AgentID            string
	Generation         int64
	Features           []EdgeFeatureState
	Cache, Compression json.RawMessage
	ReceivedAt         time.Time
}

// GetEdgeStatus returns the report of the application that the given agent made, nil when there is
// none: a report of an agent the application has left is not shown.
func (r *EdgeRepo) GetEdgeStatus(ctx context.Context, projectID, appID, agentID string) (*EdgeStatus, error) {
	if !canonicalIDs(&projectID, &appID, &agentID) {
		return nil, nil
	}
	s := EdgeStatus{AgentID: agentID}
	var feats []byte
	err := r.pool.QueryRow(ctx, `SELECT generation, features, cache, compression, received_at FROM app_edge_status
		WHERE app_id = $1 AND project_id = $2 AND agent_id = $3`, appID, projectID, agentID).
		Scan(&s.Generation, &feats, &s.Cache, &s.Compression, &s.ReceivedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(feats, &s.Features); err != nil {
		return nil, err
	}
	return &s, nil
}

// BundleGeneration returns the bundle generation of the agent, 0 when it has none.
func (r *EdgeRepo) BundleGeneration(ctx context.Context, agentID string) (int64, error) {
	var gen int64
	err := r.pool.QueryRow(ctx, `SELECT generation FROM waf_agent_bundles WHERE agent_id = $1`, agentID).Scan(&gen)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return gen, err
}
