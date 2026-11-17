package bloom

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// MalwareHashEngine manages two-layer malware inspection (L1 Bloom Filter + L2 Exact Store).
type MalwareHashEngine struct {
	mu              sync.RWMutex
	metadata        DatabaseStatus
	l1              *Filter
	l2              map[[32]byte]string   // exact hash -> threat name
	customAllowlist map[[32]byte]struct{} // exact hash -> allowed
	customBlocklist map[[32]byte]string   // exact hash -> threat name
}

// NewMalwareHashEngine initializes an empty malware hash engine.
func NewMalwareHashEngine(expectedItems int, fpRate float64) *MalwareHashEngine {
	return &MalwareHashEngine{
		l1:              NewFilter(expectedItems, fpRate),
		l2:              make(map[[32]byte]string),
		customAllowlist: make(map[[32]byte]struct{}),
		customBlocklist: make(map[[32]byte]string),
	}
}

// AddMalwareHash adds a known malware SHA-256 hash (32-byte raw) and optional threat label into L1 & L2.
func (e *MalwareHashEngine) AddMalwareHash(hash [32]byte, threatName string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if threatName == "" {
		threatName = "Generic.Malware.Hash"
	}
	if _, exists := e.l2[hash]; !exists {
		e.l1.Add(hash[:])
	}
	e.l2[hash] = threatName
}

// AddMalwareHexHash adds a known malware SHA-256 hex string (64 characters).
func (e *MalwareHashEngine) AddMalwareHexHash(hexStr, threatName string) error {
	hexStr = strings.TrimSpace(hexStr)
	if len(hexStr) != 64 {
		return fmt.Errorf("invalid sha256 hex length: %d (expected 64)", len(hexStr))
	}
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return fmt.Errorf("decode hex: %w", err)
	}
	var sum [32]byte
	copy(sum[:], raw)
	e.AddMalwareHash(sum, threatName)
	return nil
}

// SetCustomAllowlist overrides specific hashes to always allow.
func (e *MalwareHashEngine) SetCustomAllowlist(hexHashes []string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.customAllowlist = make(map[[32]byte]struct{}, len(hexHashes))
	for _, h := range hexHashes {
		h = strings.TrimSpace(h)
		if len(h) == 64 {
			if raw, err := hex.DecodeString(h); err == nil {
				var sum [32]byte
				copy(sum[:], raw)
				e.customAllowlist[sum] = struct{}{}
			}
		}
	}
}

// SetCustomBlocklist sets custom user/project hashes that must be blocked.
func (e *MalwareHashEngine) SetCustomBlocklist(hexHashes []string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.customBlocklist = make(map[[32]byte]string, len(hexHashes))
	for _, h := range hexHashes {
		h = strings.TrimSpace(h)
		if len(h) == 64 {
			if raw, err := hex.DecodeString(h); err == nil {
				var sum [32]byte
				copy(sum[:], raw)
				e.customBlocklist[sum] = "Custom.Project.Blocklist"
			}
		}
	}
}

// Stats returns engine statistics.
func (e *MalwareHashEngine) Stats() (itemsCount uint64, bitsCount uint64, fpRate float64) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.l1 == nil {
		return 0, 0, 0
	}
	return e.l1.ItemsCount(), e.l1.BitsCount(), e.l1.EstimatedFPRate()
}

// LoadFromTextReader loads hashes from a plain text list (one hex hash per line, optional # comments or tab/space separated threat name).
func (e *MalwareHashEngine) LoadFromTextReader(r io.Reader) (int, error) {
	const maxBytes = 128 * 1024 * 1024
	limited := &io.LimitedReader{R: r, N: maxBytes + 1}
	digest := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(limited, digest))
	parsed := make(map[[32]byte]string)
	labels := make(map[string]string)
	var updated time.Time
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if value, ok := strings.CutPrefix(line, "# Updated: "); ok {
			var err error
			updated, err = time.Parse(time.RFC3339, value)
			if err != nil || updated.After(time.Now().Add(5*time.Minute)) {
				return 0, errors.New("invalid malware snapshot timestamp")
			}
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		raw, err := hex.DecodeString(fields[0])
		if err != nil || len(raw) != 32 {
			return 0, errors.New("invalid SHA-256 record")
		}
		name := "Malware.Generic"
		if len(fields) > 1 {
			name = fields[1]
		}
		if IsRetiredBuiltin(strings.ToLower(fields[0]), name) {
			continue
		}
		if len(name) > 160 {
			return 0, errors.New("signature label too long")
		}
		// Do not retain each entire input line through its label substring.
		if label, ok := labels[name]; ok {
			name = label
		} else {
			name = strings.Clone(name)
			labels[name] = name
		}
		var hash [32]byte
		copy(hash[:], raw)
		parsed[hash] = name
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("read signatures: %w", err)
	}
	if limited.N == 0 {
		return 0, errors.New("signature database exceeds 128 MiB")
	}
	if len(parsed) == 0 {
		return 0, errors.New("empty signature database")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.l2) == 0 {
		e.l2 = parsed
	} else {
		for hash, name := range parsed {
			e.l2[hash] = name
		}
	}
	e.l1 = NewFilter(len(e.l2), .0001)
	for hash := range e.l2 {
		e.l1.Add(hash[:])
	}
	e.metadata.Version = hex.EncodeToString(digest.Sum(nil))
	e.metadata.Items = len(e.l2)
	e.metadata.UpdatedAt = updated
	return len(parsed), nil
}

// DatabaseStatus describes the exact snapshot used for a lookup, not a safety guarantee.
type DatabaseStatus struct {
	Version   string    `json:"version,omitempty"`
	Source    string    `json:"source,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
	Items     int       `json:"items"`
	Stale     bool      `json:"stale"`
	Degraded  bool      `json:"degraded"`
}

// ReplaceFromTextReader builds a complete replacement before publishing L1 and L2 together.
func (e *MalwareHashEngine) ReplaceFromTextReader(r io.Reader, source string, updated time.Time) error {
	next := NewMalwareHashEngine(1, .0001)
	if _, err := next.LoadFromTextReader(r); err != nil {
		e.mu.Lock()
		e.metadata.Degraded = true
		e.mu.Unlock()
		return err
	}
	next.metadata.Source = source
	if next.metadata.UpdatedAt.IsZero() {
		next.metadata.UpdatedAt = updated.UTC()
	}
	e.mu.Lock()
	e.l1, e.l2, e.metadata = next.l1, next.l2, next.metadata
	e.mu.Unlock()
	return nil
}

// ExportL1Binary exports the serialized L1 Bloom filter.
func (e *MalwareHashEngine) ExportL1Binary(w io.Writer) (int64, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.l1 == nil {
		return 0, errors.New("l1 filter is nil")
	}
	return e.l1.WriteTo(w)
}

// Clone creates an independent copy of the engine.
func (e *MalwareHashEngine) Clone() *MalwareHashEngine {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var buf bytes.Buffer
	_, _ = e.l1.WriteTo(&buf)
	l1Clone, _ := ReadFrom(&buf)

	l2Clone := make(map[[32]byte]string, len(e.l2))
	for k, v := range e.l2 {
		l2Clone[k] = v
	}

	allowClone := make(map[[32]byte]struct{}, len(e.customAllowlist))
	for k := range e.customAllowlist {
		allowClone[k] = struct{}{}
	}

	blockClone := make(map[[32]byte]string, len(e.customBlocklist))
	for k, v := range e.customBlocklist {
		blockClone[k] = v
	}

	return &MalwareHashEngine{
		l1:              l1Clone,
		metadata:        e.metadata,
		l2:              l2Clone,
		customAllowlist: allowClone,
		customBlocklist: blockClone,
	}
}

func (e *MalwareHashEngine) MarkDegraded() {
	e.mu.Lock()
	e.metadata.Degraded = true
	e.mu.Unlock()
}
