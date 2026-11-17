package domain

import "time"

// App represents a WAF-target application within a project.
type App struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`

	// WAF inline-proxy routing
	ListenHost  *string `json:"listen_host"`
	ListenPort  *int    `json:"listen_port"`
	UpstreamURL *string `json:"upstream_url"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Deployment represents a build & deploy attempt.
type Deployment struct {
	ID         string     `json:"id"`
	AppID      string     `json:"app_id"`
	GitCommit  string     `json:"git_commit,omitempty"`
	GitMessage string     `json:"git_message,omitempty"`
	Status     string     `json:"status"`
	BuildLog   string     `json:"build_log,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// Deployment statuses.
const (
	DeployStatusPending   = "pending"
	DeployStatusCloning   = "cloning"
	DeployStatusBuilding  = "building"
	DeployStatusDeploying = "deploying"
	DeployStatusLive      = "live"
	DeployStatusFailed    = "failed"
)
