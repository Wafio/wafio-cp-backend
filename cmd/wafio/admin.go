package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/application"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/config"
	"github.com/wafio/wafio-cp-backend/shared/email"
)

// Replaces the removed setup wizard. First-run bootstrap is now:
//
//	wafio migrate up
//	wafio admin create --email you@example.com --name "Your Name"
//
// The control plane installer (install-controlplane.sh of wafio-release) drives both steps.

var (
	adminEmail    string
	adminName     string
	adminPassword string
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Manage instance administrators",
}

var adminCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create an administrator account",
	Long: "Create an administrator account.\n\n" +
		"Use this once after `wafio migrate up` to bootstrap the first login.\n" +
		"The password is read from the terminal unless --password is given; passing\n" +
		"it as a flag exposes it in the process list and shell history.",
	RunE: runAdminCreate,
}

var adminListCmd = &cobra.Command{
	Use:   "list",
	Short: "List administrator accounts",
	RunE:  runAdminList,
}

func init() {
	adminCreateCmd.Flags().StringVar(&adminEmail, "email", "", "administrator email address (required)")
	adminCreateCmd.Flags().StringVar(&adminName, "name", "", "display name (required)")
	adminCreateCmd.Flags().StringVar(&adminPassword, "password", "",
		"password; omit to be prompted (recommended — a flag value is visible in `ps`)")
	adminCmd.AddCommand(adminCreateCmd, adminListCmd)
	rootCmd.AddCommand(adminCmd)
}

func openRepo(ctx context.Context) (*repository.Repository, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	repo, err := repository.New(ctx, cfg.Database.DSN())
	if err != nil {
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	return repo, nil
}

// readPasswordTwice prompts for a password without echoing it and requires the
// two entries to match.
func readPasswordTwice() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		// Non-interactive (CI, piped installer): read a single line from stdin.
		sc := bufio.NewScanner(os.Stdin)
		if !sc.Scan() {
			return "", errors.New("no password on stdin")
		}
		return strings.TrimSpace(sc.Text()), nil
	}
	fmt.Print("Password: ")
	first, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return "", err
	}
	fmt.Print("Confirm password: ")
	second, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return "", err
	}
	if string(first) != string(second) {
		return "", errors.New("passwords do not match")
	}
	return string(first), nil
}

func runAdminCreate(*cobra.Command, []string) error {
	adminEmail = email.NormalizeEmail(adminEmail)
	adminName = strings.TrimSpace(adminName)
	if adminEmail == "" {
		return errors.New("--email is required")
	}
	if !strings.Contains(adminEmail, "@") {
		return errors.New("--email is not a valid address")
	}
	if adminName == "" {
		return errors.New("--name is required")
	}

	pw := adminPassword
	if pw == "" {
		var err error
		if pw, err = readPasswordTwice(); err != nil {
			return err
		}
	}
	if len(pw) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	if len(pw) > application.MaxPasswordBytes {
		return errors.New("password can be at most 72 bytes long")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	repo, err := openRepo(ctx)
	if err != nil {
		return err
	}
	defer repo.Close()

	hadAdmin, err := repo.User.HasAnyAdmin(ctx)
	if err != nil {
		return fmt.Errorf("check existing administrators: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	user, err := repo.User.CreateWithRole(ctx, adminEmail, string(hash), adminName, "admin")
	if err != nil {
		return fmt.Errorf("create administrator: %w", err)
	}

	fmt.Printf("Administrator created: %s (%s)\n", user.Email, user.ID)
	if !hadAdmin {
		fmt.Println("This is the first administrator on this instance. Sign in at the dashboard to continue.")
	}
	return nil
}

func runAdminList(*cobra.Command, []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	repo, err := openRepo(ctx)
	if err != nil {
		return err
	}
	defer repo.Close()

	users, _, err := repo.User.List(ctx, 200, 0)
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}
	n := 0
	fmt.Printf("%-38s  %-32s  %s\n", "ID", "EMAIL", "NAME")
	for _, u := range users {
		if u.Role != "admin" {
			continue
		}
		n++
		fmt.Printf("%-38s  %-32s  %s\n", u.ID, u.Email, u.Name)
	}
	if n == 0 {
		fmt.Println("(no administrators — run `wafio admin create`)")
	}
	return nil
}
