package agentserver

import (
	"context"
	"encoding/json"
	"log"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/engine"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// Ingest of EdgeStatus, the report of a WAF agent on the compression, files, cache and redirects of
// an app. Every field is untrusted. What it says is shown to the owner and never acted on, so the
// checks keep the stored report small and made of fixed names, and keep an agent from filling the
// table: only for an app assigned to the stream's agent in its project, for a generation the stream
// was sent, and not more often than the budget below.

const (
	// edgeDetailMax is the longest detail kept, in bytes.
	edgeDetailMax = 256
	// edgeCounterCap is the largest counter kept, so that a number stays exact in JavaScript.
	edgeCounterCap = 1 << 53
	// edgeEntriesMax is the most feature entries kept: one for each part.
	edgeEntriesMax = 4
	// edgeStatusEvery is the shortest time between two reports of one app on one stream, unless the
	// report answers a newer bundle generation than the last one kept.
	edgeStatusEvery = 10 * time.Second
	// edgeAppsMax bounds the apps one stream is tracked for; the agent chooses the ids.
	edgeAppsMax = 512
)

var (
	edgeFeatureNames = []string{repository.EdgeRedirects, repository.EdgeCompression, repository.EdgeStaticFiles, repository.EdgeCache}
	edgeStates       = []string{"applied", "refused"}
	edgeCodes        = []string{"invalid", "root_missing", "root_not_directory", "root_unreadable", "root_forbidden",
		"cache_dir_unusable", "disk_too_small", "memory_too_small"}
)

// edgeUnknown stands for a feature, state or code that is not in the lists of the protocol.
const edgeUnknown = "unknown"

// edgeSeen is the last report kept for an app on a stream.
type edgeSeen struct {
	at         time.Time
	generation int64
}

// takeEdgeSlot says whether a report for the app may go on: the first one, one that answers a newer
// generation than the last kept, or one at least edgeStatusEvery after it.
func (h *streamHandle) takeEdgeSlot(app string, generation int64, now time.Time) bool {
	h.edgeMu.Lock()
	defer h.edgeMu.Unlock()
	last, known := h.edgeSeen[app]
	if known && generation <= last.generation && now.Sub(last.at) < edgeStatusEvery {
		return false
	}
	if !known && len(h.edgeSeen) >= edgeAppsMax {
		for id, e := range h.edgeSeen {
			if now.Sub(e.at) >= edgeStatusEvery {
				delete(h.edgeSeen, id)
			}
		}
		if len(h.edgeSeen) >= edgeAppsMax {
			return false
		}
	}
	if h.edgeSeen == nil {
		h.edgeSeen = make(map[string]edgeSeen)
	}
	h.edgeSeen[app] = edgeSeen{at: now, generation: max(generation, last.generation)}
	return true
}

// handleEdgeStatus stores the report. It runs on the receive loop of the stream, so reports of one
// agent are stored in the order it sent them.
func (s *Server) handleEdgeStatus(h *streamHandle, es *agentv1.EdgeStatus) {
	defer recoverPanic("edge-status")
	// Only a WAF agent that said it applies an edge part sends this message.
	if h.agentKind != "waf" || !engine.AgentEdgeFeatures(h.features).Any() {
		return
	}
	store := s.edgeStore()
	if store == nil {
		return
	}
	rep, ok := edgeReport(h, es)
	// The agent can only have applied a bundle that this stream was sent.
	if !ok || rep.Generation > h.desiredGeneration() || !h.takeEdgeSlot(rep.AppID, rep.Generation, s.now()) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := store.UpsertEdgeStatus(ctx, rep); err != nil {
		log.Printf("[agentserver] edge status not stored agent=%s app=%s: %v", h.agentID, rep.AppID, err)
	}
}

// edgeReport builds the report from what the message says, after the checks that need no database. It
// reports false for a message that must be dropped: an app id that is not a UUID or a negative
// generation.
func edgeReport(h *streamHandle, es *agentv1.EdgeStatus) (repository.EdgeStatusReport, bool) {
	app, err := uuid.Parse(es.GetAppId())
	if err != nil || es.GetGeneration() < 0 {
		return repository.EdgeStatusReport{}, false
	}
	rep := repository.EdgeStatusReport{ProjectID: h.projectID, AgentID: h.agentID, AppID: app.String(), Generation: es.GetGeneration()}
	rep.Features = make([]repository.EdgeFeatureState, 0, edgeEntriesMax)
	seen := map[string]bool{}
	for _, f := range es.GetFeatures() {
		if len(rep.Features) == edgeEntriesMax {
			break
		}
		name := fixedName(f.GetFeature(), edgeFeatureNames)
		if name != edgeUnknown && seen[name] {
			continue
		}
		seen[name] = true
		e := repository.EdgeFeatureState{Feature: name, State: fixedName(f.GetState(), edgeStates)}
		if e.State == "refused" {
			e.Code = fixedName(f.GetCode(), edgeCodes)
			e.Detail = cleanDetail(f.GetDetail())
			e.RunningPrevious = f.GetRunningPrevious()
		}
		rep.Features = append(rep.Features, e)
	}
	if c := es.GetCache(); c != nil {
		rep.Cache = marshalCounters(map[string]uint64{
			"requests": c.GetRequests(), "hits_memory": c.GetHitsMemory(), "hits_disk": c.GetHitsDisk(), "misses": c.GetMisses(),
			"bypass": c.GetBypass(), "stale": c.GetStale(), "stored": c.GetStored(), "skipped_no_lifetime": c.GetSkippedNoLifetime(),
			"skipped_private": c.GetSkippedPrivate(), "skipped_too_large": c.GetSkippedTooLarge(), "skipped_streamed": c.GetSkippedStreamed(),
			"skipped_disk_full": c.GetSkippedDiskFull(), "evictions": c.GetEvictions(), "corrupt": c.GetCorrupt(),
			"disk_bytes": c.GetDiskBytes(), "memory_bytes": c.GetMemoryBytes(), "objects": c.GetObjects(),
		})
	}
	if c := es.GetCompression(); c != nil {
		rep.Compression = marshalCounters(map[string]uint64{
			"responses": c.GetResponses(), "skipped_streamed": c.GetSkippedStreamed(), "bytes_saved": c.GetBytesSaved(),
		})
	}
	return rep, true
}

// fixedName returns v when it is one of the names, and edgeUnknown otherwise.
func fixedName(v string, names []string) string {
	if slices.Contains(names, v) {
		return v
	}
	return edgeUnknown
}

// cleanDetail drops control characters and anything that is not valid text, and cuts the rest to
// edgeDetailMax bytes at a character boundary.
func cleanDetail(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || (!unicode.IsPrint(r) && r != ' ') {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > edgeDetailMax {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// marshalCounters writes counters as a JSON object, each one capped at edgeCounterCap.
func marshalCounters(c map[string]uint64) json.RawMessage {
	capped := make(map[string]uint64, len(c))
	for k, v := range c {
		capped[k] = min(v, edgeCounterCap)
	}
	raw, err := json.Marshal(capped)
	if err != nil {
		return nil
	}
	return raw
}

// edgeStore is the part of the repository that the edge reports and removals use, which a test
// replaces.
type edgeStore interface {
	UpdateEdgeFeatures(ctx context.Context, projectID, agentID string, redirects, compression, staticFiles, cache bool) error
	UpsertEdgeStatus(ctx context.Context, rep repository.EdgeStatusReport) (bool, error)
	PendingCachePurges(ctx context.Context, projectID, agentID, appID string) ([]repository.CachePurge, error)
	FinishCachePurge(ctx context.Context, projectID, agentID, id, state, code string) (bool, error)
}

func (s *Server) edgeStore() edgeStore {
	switch {
	case s.edge != nil:
		return s.edge
	case s.Repo != nil && s.Repo.Edge != nil:
		return s.Repo.Edge
	}
	return nil
}

// storeEdgeFeatures records which parts of the edge settings the agent said it applies in Hello.
// Synchronous, like storeAgentFeatures: Stream calls it before it registers the stream, so the flags
// are written before the first bundle. A failure is logged.
func (s *Server) storeEdgeFeatures(projectID, agentID string, features []string) {
	defer recoverPanic("store-edge-features")
	store := s.edgeStore()
	if store == nil || agentID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	f := engine.AgentEdgeFeatures(features)
	if err := store.UpdateEdgeFeatures(ctx, projectID, agentID, f.Redirects, f.Compression, f.StaticFiles, f.Cache); err != nil {
		log.Printf("[agentserver] store edge features failed project=%s agent=%s: %v", projectID, agentID, err)
	}
}
