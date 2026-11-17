package agentcore

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// DefaultLocalAPITokenFile is where the host agent writes its local API token. /run is
// tmpfs, so the token lives for one boot at most; the
// systemd unit's RuntimeDirectory=wafio creates the directory.
const DefaultLocalAPITokenFile = "/run/wafio/host-agent.token" //nolint:gosec // G101: a file path, not a credential

// Environment overrides for the token file (host agent writes it, WAF agent
// reads it for the IP-jail push) and the optional group that may read it.
const (
	EnvLocalAPITokenFile  = "WAFIO_LOCAL_API_TOKEN_FILE"  //nolint:gosec // G101: an environment variable name, not a credential
	EnvLocalAPITokenGroup = "WAFIO_LOCAL_API_TOKEN_GROUP" //nolint:gosec // G101: an environment variable name, not a credential
)

// localAPITokenBytes is the token entropy: 32 random bytes, hex-encoded.
const localAPITokenBytes = 32

// maxLocalAPITokenFileBytes bounds what a client reads from the token file.
const maxLocalAPITokenFileBytes = 1024

// newLocalAPIToken returns a fresh random token (64 hex characters).
func newLocalAPIToken() (string, error) {
	b := make([]byte, localAPITokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate local API token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// WriteLocalAPIToken atomically writes token to path with mode 0600 (0640
// when group names a group allowed to read it, e.g. the WAF agent's service
// group for the IP-jail push). The file is written to a temp file in the same
// directory and renamed, so a reader never sees a partial token and a symlink
// planted at path is replaced rather than followed. A group that does not
// exist or cannot be applied (no CAP_CHOWN, not a member) is logged and the
// file is still written, root-only 0600: the token is never left unwritten.
func WriteLocalAPIToken(path, token, group string) error {
	if path == "" {
		return errors.New("local API token file path is empty")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: group readers of the 0640 token need to traverse the directory
		return fmt.Errorf("create token directory: %w", err)
	}
	group = strings.TrimSpace(group)
	gid, gerr := lookupTokenGroup(group)
	if gerr != nil {
		logTokenGroupFallback(group, gerr)
	}
	tmp, err := os.CreateTemp(dir, ".host-agent.token.*")
	if err != nil {
		return fmt.Errorf("create token file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename
	mode := os.FileMode(0o600)
	if gid >= 0 {
		// Needs CAP_CHOWN or membership in the group (SupplementaryGroups=
		// in the unit). On failure the token stays root-only: the local API
		// keeps working for root, only group readers lose access.
		if err := tmp.Chown(-1, gid); err != nil {
			logTokenGroupFallback(group, err)
		} else {
			mode = 0o640
		}
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod token file: %w", err)
	}
	if _, err := tmp.WriteString(token + "\n"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write token file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync token file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close token file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install token file: %w", err)
	}
	return nil
}

// lookupTokenGroup resolves the token group to a gid; -1 for no group.
func lookupTokenGroup(group string) (int, error) {
	if group == "" {
		return -1, nil
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return -1, err
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return -1, fmt.Errorf("bad gid %q", g.Gid)
	}
	return gid, nil
}

// logTokenGroupFallback reports that the token file stays root-only (0600)
// because the configured group could not be applied.
func logTokenGroupFallback(group string, err error) {
	log.Printf("WARNING: local API: token group %q not applied (%v); token file stays root-only (0600) and group readers such as the WAF agent IP-jail push cannot read it. Add SupplementaryGroups=%s to the host agent unit or create the group", group, err, group)
}

// ReadLocalAPIToken reads the host agent's local API token from path. Clients
// read it on each call: the host agent writes a new token every start.
func ReadLocalAPIToken(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is the agent's configured token file
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }() // read-only file
	buf := make([]byte, maxLocalAPITokenFileBytes)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return "", fmt.Errorf("read local API token: %w", err)
	}
	token := strings.TrimSpace(string(buf[:n]))
	if token == "" {
		return "", errors.New("local API token file is empty")
	}
	return token, nil
}

// SetupLocalAPIToken generates the token and publishes it at path. A write
// failure does not stop the agent (the firewall must keep running) and does
// not open the API: the token stays in memory only, so every local call is
// refused until the agent restarts with a writable path.
func SetupLocalAPIToken(path, group string) (token string, published bool, err error) {
	token, err = newLocalAPIToken()
	if err != nil {
		return "", false, err
	}
	if path == "" {
		path = DefaultLocalAPITokenFile
	}
	if werr := WriteLocalAPIToken(path, token, group); werr != nil {
		return token, false, werr
	}
	return token, true, nil
}
