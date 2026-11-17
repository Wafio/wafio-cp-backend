package agentserver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// projectBundleLoader is a Stage 1 minimum viable BundleLoader. It returns
// an empty bundle (generation=0) when the project has no agents registered
// yet, otherwise it forwards to the first WAF agent's bundle for that
// project so the existing fleet code keeps working unchanged.
//
// Stage 2 will replace this with a project-scoped aggregate that does not
// require an agent row at all.
type projectBundleLoader struct {
	repo           *repository.Repository
	goodBotFetcher *GoodBotFetcher // may be nil
}

func NewProjectBundleLoader(repo *repository.Repository) BundleLoader {
	return &projectBundleLoader{repo: repo}
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
	// Per-app custom WAF rules.
	CustomGUIRules    []json.RawMessage `json:"custom_gui_rules,omitempty"`
	CustomScriptRules []json.RawMessage `json:"custom_script_rules,omitempty"`
	CustomTuningRules []json.RawMessage `json:"custom_tuning_rules,omitempty"`
}

// LoadBundle returns the bundle for a specific agent. Only apps assigned to
// that agent (via waf_agent_apps) are included — so each agent only opens
// the ports that belong to it.
func (l *projectBundleLoader) LoadBundle(ctx context.Context, projectID, agentName string) ([]byte, int64, error) {
	if projectID == "" {
		return nil, 0, fmt.Errorf("missing project_id")
	}
	mb := miniBundle{ProjectID: projectID}

	// Project-level config fallback for sensitivity / rules.
	if pc, err := l.repo.Project.GetConfig(ctx, projectID); err == nil && pc != nil {
		if len(pc.RulesJSON) > 0 {
			mb.RulesJSON = json.RawMessage(pc.RulesJSON)
		}
		mb.Sensitivity = pc.Sensitivity
	}

	// Resolve agent_id from (project_id, agent_name).
	agentID, err := l.repo.EBPF.LookupAgentIDByName(ctx, projectID, agentName)
	if err != nil || agentID == "" {
		// Agent not registered yet — return empty bundle.
		out, _ := json.Marshal(&mb)
		return out, 0, nil
	}

	mb.AgentID = agentID
	rows, err := l.repo.WAF.ListAssignmentsForAgent(ctx, agentID)
	if err != nil {
		return nil, 0, err
	}

	mb.Apps = make([]bundleAppLite, 0, len(rows))
	for _, a := range rows {
		if a.ListenPort <= 0 || a.Upstream == "" {
			continue
		}
		app := bundleAppLite{
			AppID:       a.AppID,
			ListenHost:  a.ListenHost,
			ListenPort:  a.ListenPort,
			Upstream:    a.Upstream,
			Mode:        a.Mode,
			FCGIDocRoot: a.FCGIDocRoot,
			FCGIIndex:   a.FCGIIndex,
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
