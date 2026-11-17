package repository

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"time"
)

func (r *WAFRepo) AddDecisionFeedback(ctx context.Context, feedback domain.WAFDecisionFeedback) (*domain.WAFDecisionFeedback, error) {
	err := r.pool.QueryRow(ctx, `
 INSERT INTO waf_decision_feedback(project_id,app_id,decision_id,decision_recorded_at,actor_user_id,verdict,note)
 SELECT a.project_id,d.app_id,d.id,d.recorded_at,$5,$6,$7
 FROM waf_decisions d JOIN agents a ON a.id=d.agent_id AND a.deleted_at IS NULL
 WHERE a.project_id=$1 AND d.app_id=$2 AND d.id=$3 AND d.recorded_at=$4
 RETURNING id,created_at`, feedback.ProjectID, feedback.AppID, feedback.DecisionID, feedback.DecisionRecordedAt, feedback.ActorUserID, feedback.Verdict, sanitizeStoredText(feedback.Note)).Scan(&feedback.ID, &feedback.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &feedback, nil
}

func (r *WAFRepo) ListDecisionFeedback(ctx context.Context, projectID, appID string, decisionID int64, recordedAt time.Time, limit, offset int) ([]domain.WAFDecisionFeedback, int, error) {
	var exists bool
	err := r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM waf_decisions d JOIN agents a ON a.id=d.agent_id AND a.deleted_at IS NULL WHERE a.project_id=$1 AND d.app_id=$2 AND d.id=$3 AND d.recorded_at=$4)`, projectID, appID, decisionID, recordedAt).Scan(&exists)
	if err != nil {
		return nil, 0, err
	}
	if !exists {
		return nil, 0, pgx.ErrNoRows
	}
	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM waf_decision_feedback WHERE project_id=$1 AND app_id=$2 AND decision_id=$3 AND decision_recorded_at=$4`, projectID, appID, decisionID, recordedAt).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.pool.Query(ctx, `SELECT id,actor_user_id,verdict,note,created_at FROM waf_decision_feedback WHERE project_id=$1 AND app_id=$2 AND decision_id=$3 AND decision_recorded_at=$4 ORDER BY created_at DESC,id DESC LIMIT $5 OFFSET $6`, projectID, appID, decisionID, recordedAt, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	result := []domain.WAFDecisionFeedback{}
	for rows.Next() {
		f := domain.WAFDecisionFeedback{ProjectID: projectID, AppID: appID, DecisionID: decisionID, DecisionRecordedAt: recordedAt}
		if err := rows.Scan(&f.ID, &f.ActorUserID, &f.Verdict, &f.Note, &f.CreatedAt); err != nil {
			return nil, 0, err
		}
		result = append(result, f)
	}
	return result, total, rows.Err()
}

// AppInProject reports whether appID is an app of projectID.
func (r *WAFRepo) AppInProject(ctx context.Context, projectID, appID string) (bool, error) {
	var found bool
	err := r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM apps WHERE id=$1::uuid AND project_id=$2::uuid)`, appID, projectID).Scan(&found)
	return found, err
}

// feedbackSummarySQL aggregates the feedback summary in one pass. Two row
// sets are counted together: "flagged" (block/log/monitor decisions in the
// window, verdict NULL) feeds blocks/logs; "reviewed" (the latest feedback
// row of each decision in the window, joined back to its decision for the
// action and breakdown keys) feeds the verdict counters. Both reach
// waf_decisions through agents so tenancy never trusts the feedback
// row alone, and both bound recorded_at so TimescaleDB excludes chunks
// outside the window. Category is the decision's first category (there is
// no stored primary category column); "" or none → "uncategorized".
// analyze_method NULL or "" → "unknown"; rule_based and hybrid (an older
// agent) count as semantic.
const feedbackSummarySQL = `
WITH flagged AS (
    SELECT d.app_id,
           COALESCE(NULLIF(d.categories[1], ''), 'uncategorized') AS category,
           COALESCE(NULLIF(CASE WHEN d.analyze_method IN ('rule_based', 'hybrid') THEN 'semantic' ELSE d.analyze_method END, ''), 'unknown') AS method,
           d.action,
           NULL::text AS verdict
      FROM waf_decisions d
      JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
     WHERE a.project_id = $1::uuid
       AND d.recorded_at >= $2 AND d.recorded_at < $3
       AND d.action IN ('block', 'log', 'monitor')
       AND ($4::uuid IS NULL OR d.app_id = $4::uuid)
), latest AS (
    SELECT DISTINCT ON (f.decision_id, f.decision_recorded_at)
           f.decision_id, f.decision_recorded_at, f.verdict
      FROM waf_decision_feedback f
     WHERE f.project_id = $1::uuid
       AND f.decision_recorded_at >= $2 AND f.decision_recorded_at < $3
       AND ($4::uuid IS NULL OR f.app_id = $4::uuid)
     ORDER BY f.decision_id, f.decision_recorded_at, f.created_at DESC, f.id DESC
), reviewed AS (
    SELECT d.app_id,
           COALESCE(NULLIF(d.categories[1], ''), 'uncategorized') AS category,
           COALESCE(NULLIF(CASE WHEN d.analyze_method IN ('rule_based', 'hybrid') THEN 'semantic' ELSE d.analyze_method END, ''), 'unknown') AS method,
           d.action,
           l.verdict
      FROM latest l
      JOIN waf_decisions d ON d.id = l.decision_id AND d.recorded_at = l.decision_recorded_at
      JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
     WHERE a.project_id = $1::uuid
       AND d.recorded_at >= $2 AND d.recorded_at < $3
       AND ($4::uuid IS NULL OR d.app_id = $4::uuid)
), counted AS (
    SELECT * FROM flagged
    UNION ALL
    SELECT * FROM reviewed
), summary AS (
    SELECT GROUPING(app_id) AS g_app, GROUPING(category) AS g_cat, GROUPING(method) AS g_method,
           app_id, category, method,
           COUNT(*) FILTER (WHERE verdict IS NULL AND action = 'block')                 AS blocks,
           COUNT(*) FILTER (WHERE verdict IS NULL AND action IN ('log', 'monitor'))     AS logs,
           COUNT(*) FILTER (WHERE verdict IS NOT NULL)                                  AS reviewed,
           COUNT(*) FILTER (WHERE verdict = 'true_positive')                            AS true_positive,
           COUNT(*) FILTER (WHERE verdict = 'false_positive')                           AS false_positive,
           COUNT(*) FILTER (WHERE verdict = 'unsure')                                   AS unsure,
           COUNT(*) FILTER (WHERE verdict IN ('true_positive', 'false_positive') AND action = 'block') AS reviewed_blocks,
           COUNT(*) FILTER (WHERE verdict = 'false_positive' AND action = 'block')      AS false_positive_blocks
      FROM counted
     GROUP BY GROUPING SETS ((), (app_id), (category), (method))
)
SELECT s.g_app, s.g_cat, s.g_method, COALESCE(s.app_id::text, ''), COALESCE(ap.name, ''),
       COALESCE(s.category, ''), COALESCE(s.method, ''),
       s.blocks, s.logs, s.reviewed, s.true_positive, s.false_positive, s.unsure,
       s.reviewed_blocks, s.false_positive_blocks
  FROM summary s
  LEFT JOIN apps ap ON ap.id = s.app_id AND ap.project_id = $1::uuid`

// FeedbackSummary implements domain.FeedbackSummaryStore. The total row is
// always returned (zero counters when nothing matches).
func (r *WAFRepo) FeedbackSummary(ctx context.Context, projectID, appID string, from, to time.Time) ([]domain.FeedbackSummaryRow, error) {
	var app *string
	if appID != "" {
		app = &appID
	}
	rows, err := r.pool.Query(ctx, feedbackSummarySQL, projectID, from, to, app)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.FeedbackSummaryRow{}
	for rows.Next() {
		var (
			gApp, gCat, gMethod int
			appKey, appName     string
			category, method    string
			row                 domain.FeedbackSummaryRow
		)
		c := &row.FeedbackCounters
		if err := rows.Scan(&gApp, &gCat, &gMethod, &appKey, &appName, &category, &method,
			&c.Blocks, &c.Logs, &c.Reviewed, &c.TruePositive, &c.FalsePositive, &c.Unsure,
			&c.ReviewedBlocks, &c.FalsePositiveBlocks); err != nil {
			return nil, err
		}
		switch {
		case gApp == 0:
			row.Dim, row.Key, row.Label = domain.FeedbackDimApp, appKey, appName
		case gCat == 0:
			row.Dim, row.Key, row.Label = domain.FeedbackDimCategory, category, category
		case gMethod == 0:
			row.Dim, row.Key, row.Label = domain.FeedbackDimMethod, method, method
		default:
			row.Dim = domain.FeedbackDimTotal
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
