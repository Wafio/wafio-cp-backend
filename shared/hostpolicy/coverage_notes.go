package hostpolicy

// BaselineCoverageNotes are the firewall's permanent design limits. Every
// agent reports them in Status.CoverageWarnings, whatever its state, so they
// say nothing about a particular host: the fleet view does not count them as
// degradation (only the warnings after them, which depend on the attached
// objects and hooks). Keep the texts stable — old agents send the same ones.
var BaselineCoverageNotes = []string{
	"fragment reassembly and more than two VLAN tags or eight IPv6 extension headers are unsupported; enforcement rejects these packets",
	"return-flow cache does not validate TCP sequence numbers",
	"detection state capacity exhaustion and idle cleanup races can reduce coverage",
}
