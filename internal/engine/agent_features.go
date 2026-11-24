package engine

import "slices"

// The WAF agent reports two capabilities in Hello.features: FeatureScriptRules when it can run script
// rules, FeatureNoScriptRules when it cannot (an earlier agent build without scripts), and
// FeatureMaintenanceMode when it can answer with the maintenance page, and FeatureTLSCertificates
// when it can serve TLS from the bundle. Other names (v1 agents) are ignored; every agent gets the
// same bundle.

// FeatureScriptRules is the Hello.features entry a WAF agent sends when it can
// run script rules.
const FeatureScriptRules = "script_rules"

// FeatureNoScriptRules is the Hello.features entry a WAF agent sends when it
// cannot run script rules (an earlier agent build without scripts). A script rule
// then leaves every request of its application unfinished, which becomes LOG.
const FeatureNoScriptRules = "no_script_rules"

// AgentScriptRules says whether the WAF agent that sent these Hello.features
// can run script rules: false when it reports FeatureNoScriptRules, true when
// it reports FeatureScriptRules or any other feature (a v1 agent), nil when it
// reports none (an agent built before Hello.features existed cannot be told
// either way).
func AgentScriptRules(features []string) *bool {
	if len(features) == 0 {
		return nil
	}
	can := !slices.Contains(features, FeatureNoScriptRules)
	return &can
}

// FeatureMaintenanceMode is the Hello.features entry a WAF agent sends when it answers requests of an
// application in maintenance mode with the maintenance page. An agent without it ignores the
// maintenance key of the bundle, so visitors would still see the site.
const FeatureMaintenanceMode = "maintenance_mode"

// AgentMaintenanceMode says whether the WAF agent that sent these Hello.features supports
// maintenance mode. It is called for an agent that said Hello: an empty list comes from an agent
// built before Hello.features existed, which is older than maintenance mode, so the answer is no.
// Only an agent that never connected stays unknown, and that is the stored NULL, not a value of
// this function.
func AgentMaintenanceMode(features []string) *bool {
	can := slices.Contains(features, FeatureMaintenanceMode)
	return &can
}

// FeatureTLSCertificates is the Hello.features entry a WAF agent sends when it terminates TLS for
// the applications whose bundle entry says so: it accepts CertificateInstall and sends
// CertificateStatus. An agent without it ignores the tls key of the bundle, so no key is sent to it.
const FeatureTLSCertificates = "tls_certificates"

// AgentTLSCertificates says whether the WAF agent that sent these Hello.features serves TLS
// certificates. As for maintenance mode, an agent that said Hello with no such feature (an empty
// list included) is older than the feature, so the answer is no; only an agent that never
// connected stays unknown, and that is the stored NULL.
func AgentTLSCertificates(features []string) *bool {
	can := slices.Contains(features, FeatureTLSCertificates)
	return &can
}

// The WAF agent names each part of the edge settings of an app that it applies from the bundle and
// reports in EdgeStatus: the main host redirect and the path prefix, compression, files from a
// folder, and the response cache. A build that has the cache sends FeatureEdgeCache whether or not
// its cache directory is usable (EdgeStatus says so), so a missing name means an older agent.
const (
	FeatureEdgeRedirects   = "edge_redirects"
	FeatureEdgeCompression = "edge_compression"
	FeatureEdgeStaticFiles = "edge_static_files"
	FeatureEdgeCache       = "edge_cache"
)

// EdgeFeatures says which parts of the edge settings a WAF agent reported in Hello.
type EdgeFeatures struct {
	Redirects, Compression, StaticFiles, Cache bool
}

// AgentEdgeFeatures reads the edge features of an agent that said Hello. As for TLS, an agent that
// sent a list without a name is older than that part, so the answer is false; only an agent that
// never connected stays unknown, and that is the stored NULL.
func AgentEdgeFeatures(features []string) EdgeFeatures {
	return EdgeFeatures{
		Redirects:   slices.Contains(features, FeatureEdgeRedirects),
		Compression: slices.Contains(features, FeatureEdgeCompression),
		StaticFiles: slices.Contains(features, FeatureEdgeStaticFiles),
		Cache:       slices.Contains(features, FeatureEdgeCache),
	}
}

// Any says whether the agent sends EdgeStatus: it has at least one edge feature.
func (e EdgeFeatures) Any() bool { return e.Redirects || e.Compression || e.StaticFiles || e.Cache }
