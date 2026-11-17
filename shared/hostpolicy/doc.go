// Package hostpolicy holds the firewall and trace policy model of the host agent and its
// validation: the API types, the lockout guard (ValidateFirewallSafety), IP list and geo
// capacity checks, port scopes, trace event types and enforcement policies. The control plane
// and the host agent run the same code, so a policy the control plane accepts is one the agent
// applies. It imports nothing from the BPF loader and nothing under internal/.
package hostpolicy
