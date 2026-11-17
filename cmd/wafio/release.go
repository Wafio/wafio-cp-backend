package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wafio/wafio-cp-backend/internal/updater"
)

// Release signing lives here rather than in a shell script so the payload the
// signer produces and the payload the agent verifies come from one definition.
// A signing tool that disagrees with its verifier by one newline produces
// signatures that fail everywhere and look like a key problem.

const signaturePayloadPrefix = "wafio-release-v1"

func releasePayload(version, sha256Hex string) []byte {
	return []byte(signaturePayloadPrefix + "\n" + version + "\n" + strings.ToLower(sha256Hex))
}

var releaseCmd = &cobra.Command{
	Use:   "release",
	Short: "Release signing helpers",
	Long: "Generate the release signing key and sign build artefacts.\n\n" +
		"Agents verify these signatures with a public key compiled into their binary.\n" +
		"Until that key is set, self-update refuses to install anything.",
}

var releaseKeygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate an Ed25519 release signing key",
	Long: "Writes the private key to the path given by --out and prints the public key.\n\n" +
		"Run this on a machine that does the releasing, not on a server that runs\n" +
		"WAFio. The private key must never reach a control plane: the whole point of\n" +
		"the signature is that a compromised control plane cannot produce one.",
	RunE: runReleaseKeygen,
}

var releaseSignCmd = &cobra.Command{
	Use:   "sign <artefact> [artefact...]",
	Short: "Sign build artefacts for a release",
	Long: "Hashes each artefact, signs (version, hash) with the release key, and writes\n" +
		"a detached <artefact>.sig next to it. Upload the .sig alongside the artefact;\n" +
		"agents fetch it from the release host, not from the control plane.",
	Args: cobra.MinimumNArgs(1),
	RunE: runReleaseSign,
}

var releaseVerifyCmd = &cobra.Command{
	Use:   "verify <artefact> [artefact...]",
	Short: "Verify detached release signatures",
	Long: "Verifies each <artefact>.sig against the public key compiled into the updater.\n" +
		"No artifact should be published until this command accepts the whole release set.",
	Args: cobra.MinimumNArgs(1),
	RunE: runReleaseVerify,
}

var (
	releaseKeyOut  string
	releaseKeyPath string
	releaseVersion string
)

func init() {
	releaseKeygenCmd.Flags().StringVar(&releaseKeyOut, "out", "wafio-release.key",
		"path to write the private key to")
	releaseSignCmd.Flags().StringVar(&releaseKeyPath, "key", "wafio-release.key",
		"path to the private key")
	releaseSignCmd.Flags().StringVar(&releaseVersion, "version", "",
		"release version the signature is bound to, e.g. v1.2.0 (required)")
	_ = releaseSignCmd.MarkFlagRequired("version")
	releaseVerifyCmd.Flags().StringVar(&releaseVersion, "version", "",
		"release version the signature is bound to, e.g. v1.2.0 (required)")
	_ = releaseVerifyCmd.MarkFlagRequired("version")

	releaseCmd.AddCommand(releaseKeygenCmd, releaseSignCmd, releaseVerifyCmd)
	rootCmd.AddCommand(releaseCmd)
}

func runReleaseKeygen(*cobra.Command, []string) error {
	// Refuse to clobber. Overwriting a release key silently would invalidate
	// every signature already published under it.
	if _, err := os.Stat(releaseKeyOut); err == nil {
		return fmt.Errorf("%s already exists; move it aside first (overwriting it would "+
			"orphan every signature made with it)", releaseKeyOut)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	// 0600 before any bytes are written, not after.
	f, err := os.OpenFile(releaseKeyOut, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600) //nolint:gosec // G304: path comes from the CLI/operator or this package, not from a request
	if err != nil {
		return fmt.Errorf("create %s: %w", releaseKeyOut, err)
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(priv) + "\n"); err != nil {
		_ = f.Close() // already failing with the write error
		return fmt.Errorf("write %s: %w", releaseKeyOut, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", releaseKeyOut, err)
	}

	fmt.Printf("Private key written to %s (mode 0600). Back it up; it cannot be recovered.\n\n", releaseKeyOut)
	fmt.Printf("Public key:\n\n    %s\n\n", base64.StdEncoding.EncodeToString(pub))
	fmt.Print("Add it to releasePublicKeys in internal/updater/verify.go and rebuild.\n" +
		"Until it is there, agents refuse every self-update, which is the safe state.\n\n" +
		"Do not copy the private key to a control plane or a WAF host. An attacker who\n" +
		"reaches it can sign a binary that every agent will install as root.\n")
	return nil
}

func runReleaseSign(_ *cobra.Command, args []string) error {
	if strings.TrimSpace(releaseVersion) == "" {
		return fmt.Errorf("--version is required; the signature binds the artefact to a release")
	}

	info, err := os.Stat(releaseKeyPath)
	if err != nil {
		return fmt.Errorf("stat key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("release key must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("release key must be owner-only (mode 0600 or stricter), got %04o", info.Mode().Perm())
	}

	raw, err := os.ReadFile(releaseKeyPath) //nolint:gosec // G304: path comes from the CLI/operator or this package, not from a request
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}
	priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return fmt.Errorf("key is not valid base64: %w", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	key := ed25519.PrivateKey(priv)

	for _, path := range args {
		sum, err := fileSHA256(path)
		if err != nil {
			return err
		}
		sig := ed25519.Sign(key, releasePayload(releaseVersion, sum))
		sigPath := path + ".sig"
		if err := os.WriteFile(sigPath, []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0644); err != nil { //nolint:gosec // G306: public artefact that must stay world-readable; mode kept
			return fmt.Errorf("write %s: %w", sigPath, err)
		}
		fmt.Printf("%s\n  sha256 %s\n  signed %s\n", filepath.Base(path), sum, sigPath)
	}

	fmt.Printf("\nUpload each .sig next to its artefact on the release host.\n" +
		"An artefact without one is refused, not installed unverified.\n")
	return nil
}

func runReleaseVerify(_ *cobra.Command, args []string) error {
	if strings.TrimSpace(releaseVersion) == "" {
		return fmt.Errorf("--version is required; the signature must be bound to a release")
	}
	for _, path := range args {
		sum, err := fileSHA256(path)
		if err != nil {
			return err
		}
		sig, err := os.ReadFile(path + ".sig") //nolint:gosec // G304: path comes from the CLI/operator or this package, not from a request
		if err != nil {
			return fmt.Errorf("read %s.sig: %w", path, err)
		}
		if err := updater.VerifyRelease(releaseVersion, sum, strings.TrimSpace(string(sig))); err != nil {
			return fmt.Errorf("verify %s: %w", filepath.Base(path), err)
		}
		fmt.Printf("verified %s (%s)\n", filepath.Base(path), sum)
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path comes from the CLI/operator or this package, not from a request
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }() // read-only file
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
