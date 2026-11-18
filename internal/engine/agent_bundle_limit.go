package engine

// MaxAgentBundleBytes is the largest bundle the control plane sends to a WAF agent. The agent
// receives it in one gRPC message and refuses a message of more than 4 MiB (4,194,304 bytes; the
// decoding limit of its client). The envelope around the bundle is under 128 bytes; 1 KiB is left
// for it. A bundle over the limit would end the stream at every connect, so the agent would keep
// its last bundle and never get a newer one.
const MaxAgentBundleBytes = 4<<20 - 1<<10
