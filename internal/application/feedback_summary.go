package application

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// Errors FeedbackSummary.Summarize returns for caller mistakes; anything else
// is a storage failure.
var (
	ErrFeedbackInvalidRange = errors.New("range must be 24h, 7d or 30d")
	ErrFeedbackAppNotFound  = errors.New("app not found")
)

// FeedbackSummaryGroupLimit caps each breakdown list.
const FeedbackSummaryGroupLimit = 50

// FeedbackUnmappedAppLabel names the by_app row of decisions without an app
// (Host-header traffic no app claims); its key is "".
const FeedbackUnmappedAppLabel = "Unmapped host"

var feedbackRanges = map[string]time.Duration{
	"24h": 24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
	"30d": 30 * 24 * time.Hour,
}

// FeedbackSummaryResult is the body of
// GET /api/projects/:id/waf/feedback/summary.
type FeedbackSummaryResult struct {
	Range      string                  `json:"range"`
	From       time.Time               `json:"from"`
	To         time.Time               `json:"to"`
	AppID      string                  `json:"app_id"`
	Totals     domain.FeedbackCounters `json:"totals"`
	ByApp      []domain.FeedbackGroup  `json:"by_app"`
	ByCategory []domain.FeedbackGroup  `json:"by_category"`
	ByMethod   []domain.FeedbackGroup  `json:"by_method"`
}

// FeedbackSummary aggregates operator feedback on WAF decisions into the
// false-positive block rate.
type FeedbackSummary struct {
	Store domain.FeedbackSummaryStore
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Summarize returns the summary of rangeName ("" = 7d) ending now, for one
// app of the project or (appID "") for the whole project.
func (s *FeedbackSummary) Summarize(ctx context.Context, projectID, rangeName, appID string) (*FeedbackSummaryResult, error) {
	if rangeName == "" {
		rangeName = "7d"
	}
	span, ok := feedbackRanges[rangeName]
	if !ok {
		return nil, ErrFeedbackInvalidRange
	}
	if appID != "" {
		found, err := s.Store.AppInProject(ctx, projectID, appID)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, ErrFeedbackAppNotFound
		}
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	to := now().UTC().Truncate(time.Second)
	from := to.Add(-span)
	rows, err := s.Store.FeedbackSummary(ctx, projectID, appID, from, to)
	if err != nil {
		return nil, err
	}
	out := &FeedbackSummaryResult{
		Range: rangeName, From: from, To: to, AppID: appID,
		ByApp: []domain.FeedbackGroup{}, ByCategory: []domain.FeedbackGroup{}, ByMethod: []domain.FeedbackGroup{},
	}
	for _, row := range rows {
		g := row.FeedbackGroup
		g.SetRate()
		switch row.Dim {
		case domain.FeedbackDimTotal:
			out.Totals = g.FeedbackCounters
		case domain.FeedbackDimApp:
			if g.Key == "" {
				g.Label = FeedbackUnmappedAppLabel
			} else if g.Label == "" {
				g.Label = g.Key
			}
			out.ByApp = append(out.ByApp, g)
		case domain.FeedbackDimCategory:
			out.ByCategory = append(out.ByCategory, g)
		case domain.FeedbackDimMethod:
			out.ByMethod = append(out.ByMethod, g)
		}
	}
	out.Totals.SetRate()
	out.ByApp = topFeedbackGroups(out.ByApp)
	out.ByCategory = topFeedbackGroups(out.ByCategory)
	out.ByMethod = topFeedbackGroups(out.ByMethod)
	return out, nil
}

// topFeedbackGroups sorts by blocks descending, then key, and keeps the
// first FeedbackSummaryGroupLimit.
func topFeedbackGroups(groups []domain.FeedbackGroup) []domain.FeedbackGroup {
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].Blocks != groups[j].Blocks {
			return groups[i].Blocks > groups[j].Blocks
		}
		return groups[i].Key < groups[j].Key
	})
	if len(groups) > FeedbackSummaryGroupLimit {
		groups = groups[:FeedbackSummaryGroupLimit]
	}
	return groups
}
