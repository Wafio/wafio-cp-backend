package domain

import (
	"context"
	"time"
)

// WAFDecisionFeedback records a human assessment; it never changes enforcement.
type WAFDecisionFeedback struct {
	ID                 string    `json:"id"`
	ProjectID          string    `json:"project_id"`
	AppID              string    `json:"app_id"`
	DecisionID         int64     `json:"decision_id"`
	DecisionRecordedAt time.Time `json:"decision_recorded_at"`
	ActorUserID        string    `json:"actor_user_id"`
	Verdict            string    `json:"verdict"`
	Note               string    `json:"note"`
	CreatedAt          time.Time `json:"created_at"`
}

func ValidFeedbackVerdict(verdict string) bool {
	return verdict == "true_positive" || verdict == "false_positive" || verdict == "unsure"
}

// FeedbackCounters are the false-positive feedback counters of one scope of a
// feedback summary. Blocks and Logs count the WAF
// decisions recorded in the window; the reviewed counters count decisions in
// the window that have feedback, each by its latest verdict.
type FeedbackCounters struct {
	Blocks              int64 `json:"blocks"`
	Logs                int64 `json:"logs"`
	Reviewed            int64 `json:"reviewed"`
	TruePositive        int64 `json:"true_positive"`
	FalsePositive       int64 `json:"false_positive"`
	Unsure              int64 `json:"unsure"`
	ReviewedBlocks      int64 `json:"reviewed_blocks"`
	FalsePositiveBlocks int64 `json:"false_positive_blocks"`
	// FPBlockRate is FalsePositiveBlocks / ReviewedBlocks; nil when no
	// block has a true_positive or false_positive verdict.
	FPBlockRate *float64 `json:"fp_block_rate"`
}

// SetRate fills FPBlockRate from the block counters.
func (c *FeedbackCounters) SetRate() {
	c.FPBlockRate = nil
	if c.ReviewedBlocks > 0 {
		rate := float64(c.FalsePositiveBlocks) / float64(c.ReviewedBlocks)
		c.FPBlockRate = &rate
	}
}

// FeedbackGroup is one row of a feedback summary breakdown.
type FeedbackGroup struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	FeedbackCounters
}

// Feedback summary dimensions.
const (
	FeedbackDimTotal    = "total"
	FeedbackDimApp      = "app"
	FeedbackDimCategory = "category"
	FeedbackDimMethod   = "method"
)

// FeedbackSummaryRow is one aggregate the store returns: Dim names the
// breakdown (FeedbackDim*), Key/Label the group within it (empty for the
// total). FPBlockRate is left nil; the application computes it.
type FeedbackSummaryRow struct {
	Dim string
	FeedbackGroup
}

// FeedbackSummaryStore aggregates waf_decisions and waf_decision_feedback of
// one project. Decisions count when from <= recorded_at < to; appID "" means
// every app (including unmapped Host-header traffic).
type FeedbackSummaryStore interface {
	AppInProject(ctx context.Context, projectID, appID string) (bool, error)
	FeedbackSummary(ctx context.Context, projectID, appID string, from, to time.Time) ([]FeedbackSummaryRow, error)
}
