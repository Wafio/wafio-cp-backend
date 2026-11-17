package application

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

type fakeFeedbackStore struct {
	apps     map[string]bool
	rows     []domain.FeedbackSummaryRow
	err      error
	gotApp   string
	from, to time.Time
	calls    int
}

func (f *fakeFeedbackStore) AppInProject(_ context.Context, _, appID string) (bool, error) {
	return f.apps[appID], nil
}

func (f *fakeFeedbackStore) FeedbackSummary(_ context.Context, _, appID string, from, to time.Time) ([]domain.FeedbackSummaryRow, error) {
	f.calls++
	f.gotApp, f.from, f.to = appID, from, to
	return f.rows, f.err
}

func TestFeedbackSummaryRangeAndWindow(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 30, 45, 999, time.FixedZone("x", 3600))
	store := &fakeFeedbackStore{}
	svc := &FeedbackSummary{Store: store, Now: func() time.Time { return now }}
	for name, span := range map[string]time.Duration{"": 7 * 24 * time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour} {
		out, err := svc.Summarize(context.Background(), "p", name, "")
		if err != nil {
			t.Fatal(err)
		}
		want := name
		if want == "" {
			want = "7d"
		}
		if out.Range != want || !out.To.Equal(now.Truncate(time.Second)) || out.To.Location() != time.UTC || out.To.Sub(out.From) != span {
			t.Fatalf("range %q: %+v", name, out)
		}
		if !store.from.Equal(out.From) || !store.to.Equal(out.To) {
			t.Fatalf("store window %v..%v, response %v..%v", store.from, store.to, out.From, out.To)
		}
		if out.ByApp == nil || out.ByCategory == nil || out.ByMethod == nil || out.Totals.FPBlockRate != nil {
			t.Fatalf("empty summary must have empty lists and a null rate: %+v", out)
		}
	}
	for _, bad := range []string{"1h", "7D", "all", "-7d"} {
		if _, err := svc.Summarize(context.Background(), "p", bad, ""); !errors.Is(err, ErrFeedbackInvalidRange) {
			t.Fatalf("range %q: err %v", bad, err)
		}
	}
}

func TestFeedbackSummaryForeignAppNeverQueries(t *testing.T) {
	store := &fakeFeedbackStore{apps: map[string]bool{"own": true}}
	svc := &FeedbackSummary{Store: store}
	if _, err := svc.Summarize(context.Background(), "p", "7d", "foreign"); !errors.Is(err, ErrFeedbackAppNotFound) {
		t.Fatalf("foreign app: %v", err)
	}
	if store.calls != 0 {
		t.Fatal("summary queried for a foreign app")
	}
	if _, err := svc.Summarize(context.Background(), "p", "7d", "own"); err != nil || store.gotApp != "own" {
		t.Fatalf("own app: %v, store app %q", err, store.gotApp)
	}
}

func TestFeedbackSummaryRatesSortingAndCap(t *testing.T) {
	rows := []domain.FeedbackSummaryRow{
		{Dim: domain.FeedbackDimTotal, FeedbackGroup: domain.FeedbackGroup{FeedbackCounters: domain.FeedbackCounters{Blocks: 10, ReviewedBlocks: 4, FalsePositiveBlocks: 1}}},
		{Dim: domain.FeedbackDimApp, FeedbackGroup: domain.FeedbackGroup{Key: "", FeedbackCounters: domain.FeedbackCounters{Blocks: 1}}},
		{Dim: domain.FeedbackDimApp, FeedbackGroup: domain.FeedbackGroup{Key: "b", Label: "Shop", FeedbackCounters: domain.FeedbackCounters{Blocks: 5, Reviewed: 1, Unsure: 1}}},
		{Dim: domain.FeedbackDimApp, FeedbackGroup: domain.FeedbackGroup{Key: "a", Label: "Api", FeedbackCounters: domain.FeedbackCounters{Blocks: 5, ReviewedBlocks: 2, FalsePositiveBlocks: 2}}},
	}
	for i := 0; i < 60; i++ {
		key := fmt.Sprintf("cat%02d", i)
		rows = append(rows, domain.FeedbackSummaryRow{Dim: domain.FeedbackDimCategory, FeedbackGroup: domain.FeedbackGroup{Key: key, Label: key, FeedbackCounters: domain.FeedbackCounters{Blocks: int64(i % 3)}}})
	}
	svc := &FeedbackSummary{Store: &fakeFeedbackStore{rows: rows}}
	out, err := svc.Summarize(context.Background(), "p", "24h", "")
	if err != nil {
		t.Fatal(err)
	}
	if out.Totals.FPBlockRate == nil || *out.Totals.FPBlockRate != 0.25 {
		t.Fatalf("total rate %v", out.Totals.FPBlockRate)
	}
	if len(out.ByApp) != 3 || out.ByApp[0].Key != "a" || out.ByApp[1].Key != "b" || out.ByApp[2].Key != "" {
		t.Fatalf("by_app order %+v", out.ByApp)
	}
	if *out.ByApp[0].FPBlockRate != 1 || out.ByApp[1].FPBlockRate != nil {
		t.Fatalf("by_app rates %+v", out.ByApp)
	}
	if out.ByApp[2].Label != FeedbackUnmappedAppLabel {
		t.Fatalf("unmapped label %q", out.ByApp[2].Label)
	}
	if len(out.ByCategory) != FeedbackSummaryGroupLimit || out.ByCategory[0].Key != "cat02" || out.ByCategory[0].Blocks != 2 {
		t.Fatalf("by_category %d first %+v", len(out.ByCategory), out.ByCategory[0])
	}
	if len(out.ByMethod) != 0 {
		t.Fatalf("by_method %+v", out.ByMethod)
	}
}
