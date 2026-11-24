package agentserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/engine"
)

// projectBundleLoader is the BundleLoader of the control plane. It returns
// an empty bundle (generation=0) when the project has no agents registered
// yet, otherwise it forwards to the first WAF agent's bundle for that
// project so the existing fleet code keeps working unchanged.
type projectBundleLoader struct {
	repo           *repository.Repository
	goodBotFetcher *GoodBotFetcher // may be nil
}

// NewProjectBundleLoaderWithGoodBot creates a bundle loader that includes
// official good-bot IP ranges (fetched by the control plane) in every bundle.
func NewProjectBundleLoaderWithGoodBot(repo *repository.Repository, f *GoodBotFetcher) BundleLoader {
	return &projectBundleLoader{repo: repo, goodBotFetcher: f}
}

type miniBundle struct {
	// AgentID scopes Generation: the agent orders bundles only within one
	// agent identity (a re-registered agent is a new row).
	AgentID      string          `json:"agent_id,omitempty"`
	Generation   int64           `json:"generation"`
	ProjectID    string          `json:"project_id"`
	Apps         []bundleAppLite `json:"apps"`
	RulesJSON    json.RawMessage `json:"rules_json,omitempty"`
	Sensitivity  int             `json:"sensitivity,omitempty"`
	GoodBotCIDRs []string        `json:"good_bot_cidrs,omitempty"`
}

type bundleAppLite struct {
	AppID       string          `json:"app_id"`
	ListenHost  string          `json:"listen_host,omitempty"`
	ListenPort  int             `json:"listen_port,omitempty"`
	Upstream    string          `json:"upstream"`
	Mode        string          `json:"mode"`
	RulesJSON   json.RawMessage `json:"rules_json,omitempty"`
	Sensitivity int             `json:"sensitivity,omitempty"`
	// Per-app reverse-proxy config (migration 000061).
	ProxyConfig json.RawMessage `json:"proxy_config,omitempty"`
	// FastCGI config (migration 000044).
	FCGIDocRoot string `json:"fcgi_doc_root,omitempty"`
	FCGIIndex   string `json:"fcgi_index,omitempty"`
	// FCGIKeepConn is present only when true (migration 000123). An agent that reads it closes the
	// FastCGI connection after each reply unless it is set. One that does not know the key ignores
	// it: before 2.1.1 it keeps the connection open, 2.1.1 closes it.
	FCGIKeepConn bool `json:"fcgi_keep_conn,omitempty"`
	// Per-app custom WAF rules.
	CustomGUIRules    []json.RawMessage `json:"custom_gui_rules,omitempty"`
	CustomScriptRules []json.RawMessage `json:"custom_script_rules,omitempty"`
	CustomTuningRules []json.RawMessage `json:"custom_tuning_rules,omitempty"`
	// Maintenance is the stored maintenance object, present only while it is switched on
	// (migration 000119). An agent that does not know the key ignores it.
	Maintenance json.RawMessage `json:"maintenance,omitempty"`
	// TLS is present only while the app is in gateway mode (migration 000124): the agent then
	// terminates TLS for the hosts. It names an uploaded certificate by id and leaf and never carries
	// key material, since the agent keeps the bundle in plain text.
	TLS *repository.BundleTLS `json:"tls,omitempty"`
	// Compression, StaticFiles and Cache are the stored delivery objects, present only while their
	// enabled is true (migration 000127). An agent that does not know a key ignores it. The main host
	// name is in tls and the path prefix in proxy_config.
	Compression json.RawMessage `json:"compression,omitempty"`
	StaticFiles json.RawMessage `json:"static_files,omitempty"`
	Cache       json.RawMessage `json:"cache,omitempty"`
}

// LoadBundle returns the bundle for a specific agent. Only apps assigned to
// that agent (via waf_agent_apps) are included — so each agent only opens
// the ports that belong to it.
func (l *projectBundleLoader) LoadBundle(ctx context.Context, projectID, agentName string) ([]byte, int64, error) {
	if projectID == "" {
		return nil, 0, fmt.Errorf("missing project_id")
	}
	// An agent that is not registered yet gets the empty bundle.
	agentID, err := l.repo.EBPF.LookupAgentIDByName(ctx, projectID, agentName)
	if err != nil {
		agentID = ""
	}
	return l.build(ctx, projectID, agentID, nil)
}

// BundleBytes returns the size of the bundle that is sent to the agent: what LoadBundle builds for
// it, after the rewrite NormalizeBundle makes. edit, when not nil, changes the application rows
// the bundle is built from, to measure a bundle that does not exist yet. It never changes the
// database.
func (l *projectBundleLoader) BundleBytes(ctx context.Context, projectID, agentID string, edit func([]repository.WAFBundleAppRow) []repository.WAFBundleAppRow) (int, error) {
	out, _, err := l.build(ctx, projectID, agentID, edit)
	if err != nil {
		return 0, err
	}
	out, _ = engine.NormalizeBundle(out)
	return len(out), nil
}

// bundleSizer is the part of a BundleLoader that can measure a bundle.
type bundleSizer interface {
	BundleBytes(ctx context.Context, projectID, agentID string, edit func([]repository.WAFBundleAppRow) []repository.WAFBundleAppRow) (int, error)
}

// BundleBytes returns the size in bytes of the bundle the agent with this id gets in a
// ServerMessage, and with edit, of the bundle it would get if its application rows were changed.
// See engine.MaxAgentBundleBytes for the largest bundle an agent accepts.
func (s *Server) BundleBytes(ctx context.Context, projectID, agentID string, edit func([]repository.WAFBundleAppRow) []repository.WAFBundleAppRow) (int, error) {
	sizer, ok := s.BundleLoader.(bundleSizer)
	if !ok {
		return 0, errors.New("the bundle loader cannot measure a bundle")
	}
	return sizer.BundleBytes(ctx, projectID, agentID, edit)
}

// build makes the bundle of the agent with this id, and returns it with its generation. An empty
// agentID gives the empty bundle of an agent that is not registered yet.
func (l *projectBundleLoader) build(ctx context.Context, projectID, agentID string, edit func([]repository.WAFBundleAppRow) []repository.WAFBundleAppRow) ([]byte, int64, error) {
	mb := miniBundle{ProjectID: projectID}

	// Project-level config fallback for sensitivity / rules.
	if pc, err := l.repo.Project.GetConfig(ctx, projectID); err == nil && pc != nil {
		if len(pc.RulesJSON) > 0 {
			mb.RulesJSON = json.RawMessage(pc.RulesJSON)
		}
		mb.Sensitivity = pc.Sensitivity
	}

	if agentID == "" {
		out, _ := json.Marshal(&mb)
		return out, 0, nil
	}

	mb.AgentID = agentID
	rows, err := l.repo.WAF.ListAssignmentsForAgent(ctx, agentID)
	if err != nil {
		return nil, 0, err
	}
	if edit != nil {
		rows = edit(rows)
	}

	mb.Apps = make([]bundleAppLite, 0, len(rows))
	for _, a := range rows {
		if !a.InBundle() {
			continue
		}
		app := bundleAppLite{
			AppID:        a.AppID,
			ListenHost:   a.ListenHost,
			ListenPort:   a.ListenPort,
			Upstream:     a.Upstream,
			Mode:         a.Mode,
			FCGIDocRoot:  a.FCGIDocRoot,
			FCGIIndex:    a.FCGIIndex,
			FCGIKeepConn: a.FCGIKeepConn,
		}
		if len(a.ProxyConfig) > 0 {
			app.ProxyConfig = json.RawMessage(a.ProxyConfig)
		}
		if len(a.RulesJSON) > 0 {
			app.RulesJSON = json.RawMessage(a.RulesJSON)
		}
		if a.Sensitivity > 0 {
			app.Sensitivity = a.Sensitivity
		}
		if maintenanceOn(a.Maintenance) {
			app.Maintenance = json.RawMessage(a.Maintenance)
		}
		app.TLS = a.TLS
		if repository.DeliveryEnabled(a.Compression) {
			app.Compression = json.RawMessage(a.Compression)
		}
		if repository.DeliveryEnabled(a.StaticFiles) {
			app.StaticFiles = json.RawMessage(a.StaticFiles)
		}
		if repository.DeliveryEnabled(a.Cache) {
			app.Cache = json.RawMessage(a.Cache)
		}
		if guiRules, err := l.repo.WafCustomRules.ListGUIRulesRaw(ctx, a.AppID); err == nil && len(guiRules) > 0 {
			app.CustomGUIRules = guiRules
		}
		if scriptRules, err := l.repo.WafCustomRules.ListScriptRulesRaw(ctx, a.AppID); err == nil && len(scriptRules) > 0 {
			if allowed := sandboxedScriptRules(a.AppID, scriptRules); len(allowed) > 0 {
				app.CustomScriptRules = allowed
			}
		}
		if tuningRules, err := l.repo.WafCustomRules.ListTuningRulesRaw(ctx, a.AppID); err == nil && len(tuningRules) > 0 {
			app.CustomTuningRules = tuningRules
		}
		mb.Apps = append(mb.Apps, app)
	}

	// Set generation from agent's bundle_gen table.
	if gen, gerr := l.repo.WAF.GetBundleGeneration(ctx, agentID); gerr == nil {
		mb.Generation = gen
	}

	// Include good-bot IP ranges fetched by the control plane.
	// Agents that have no outbound internet still get up-to-date bot IP ranges.
	if l.goodBotFetcher != nil {
		if cidrs := l.goodBotFetcher.GetCIDRs(); len(cidrs) > 0 {
			mb.GoodBotCIDRs = cidrs
		}
	}

	out, err := json.Marshal(&mb)
	if err != nil {
		return nil, 0, err
	}
	return out, mb.Generation, nil
}

// maintenanceOn reports whether a stored maintenance object has its switch on.
func maintenanceOn(raw []byte) bool {
	var m struct {
		Enabled bool `json:"enabled"`
	}
	return json.Unmarshal(raw, &m) == nil && m.Enabled
}
