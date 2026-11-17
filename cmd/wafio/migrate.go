package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/spf13/cobra"
	"github.com/wafio/wafio-cp-backend/internal/config"
)

var migrationsDir string
var migrateDownSteps int

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Run database migrations",
}

var migrateUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Apply all migrations",
	RunE:  runMigrateUp,
}

var migrateDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Rollback one migration",
	RunE:  runMigrateDown,
}

var migrateFreshCmd = &cobra.Command{
	Use:   "fresh",
	Short: "Rollback all migrations then apply all (fresh database)",
	RunE:  runMigrateFresh,
}

func init() {
	migrateCmd.PersistentFlags().StringVar(&migrationsDir, "migrations", "", "path to migrations directory (default: auto-detect from project root)")
	migrateCmd.AddCommand(migrateUpCmd)
	migrateCmd.AddCommand(migrateDownCmd)
	migrateDownCmd.Flags().IntVar(&migrateDownSteps, "steps", 1, "number of migrations to roll back (default: one)")
	migrateCmd.AddCommand(migrateFreshCmd)
}

// findMigrationsDir walks up from cwd until it finds a directory containing "migrations" and "config".
// So you can run "wafio migrate fresh" from project root or any subfolder.
func findMigrationsDir() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := cwd
	for {
		migrationsPath := filepath.Join(dir, "migrations")
		configPath := filepath.Join(dir, "config")
		if fi, err := os.Stat(migrationsPath); err == nil && fi.IsDir() {
			if _, err := os.Stat(configPath); err == nil {
				return migrationsPath, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	// Fallback: migrations in cwd
	fallback := filepath.Join(cwd, "migrations")
	if fi, err := os.Stat(fallback); err == nil && fi.IsDir() {
		return fallback, nil
	}
	return "", errors.New("migrations folder not found (run from project root or a subfolder of it)")
}

// migrationsSource returns the file:// URL for the migrate library and the project root (for Chdir).
// Use absolute path with file:/// (three slashes) so the file driver gets a valid path regardless of cwd.
func migrationsSource() (sourceURL string, projectRoot string, err error) {
	var migrationsPath string
	if migrationsDir != "" {
		if !filepath.IsAbs(migrationsDir) {
			migrationsPath, _ = filepath.Abs(migrationsDir)
		} else {
			migrationsPath = migrationsDir
		}
		if fi, err := os.Stat(migrationsPath); err != nil || !fi.IsDir() {
			return "", "", errors.New("migrations path is not a directory: " + migrationsDir)
		}
		projectRoot = filepath.Dir(migrationsPath)
		abs := filepath.Clean(migrationsPath)
		// file:// + /path (absolute path) = file:///path (three slashes total)
		return "file://" + filepath.ToSlash(abs), projectRoot, nil
	}
	found, err := findMigrationsDir()
	if err != nil {
		return "", "", err
	}
	abs, _ := filepath.Abs(found)
	projectRoot = filepath.Dir(abs)
	return "file://" + filepath.ToSlash(abs), projectRoot, nil
}

func wrapMigrateErr(err error, projectRoot, sourceURL string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "does not exist") || strings.Contains(msg, "no such file") {
		migrationsPath := filepath.Join(projectRoot, "migrations")
		_, statErr := os.Stat(migrationsPath)
		hint := fmt.Sprintf(" (project root: %s, source: %s)", projectRoot, sourceURL)
		if statErr == nil {
			hint = fmt.Sprintf("%s — migrations folder exists. Try: cd %s then ./wafio migrate fresh", hint, projectRoot)
		} else {
			hint = fmt.Sprintf("%s — ensure folder exists: %s", hint, migrationsPath)
		}
		return fmt.Errorf("%v%s", err, hint)
	}
	return err
}

func runMigrateUp(*cobra.Command, []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := cfg.ValidateDatabase(); err != nil {
		return err
	}
	sourceURL, projectRoot, err := migrationsSource()
	if err != nil {
		return err
	}
	m, err := migrate.New(sourceURL, cfg.Database.DSN())
	if err != nil {
		return wrapMigrateErr(err, projectRoot, sourceURL)
	}
	defer func() { _, _ = m.Close() }() // shutdown path; nothing left to report
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return err
	}
	if err := ensurePerChunkIndexesAfter(m, cfg.Database.DSN()); err != nil {
		return err
	}
	log.Println("migrate up: ok")
	return nil
}

func runMigrateDown(*cobra.Command, []string) error {
	if migrateDownSteps < 1 {
		return errors.New("steps must be at least 1")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := cfg.ValidateDatabase(); err != nil {
		return err
	}
	sourceURL, projectRoot, err := migrationsSource()
	if err != nil {
		return err
	}
	m, err := migrate.New(sourceURL, cfg.Database.DSN())
	if err != nil {
		return wrapMigrateErr(err, projectRoot, sourceURL)
	}
	defer func() { _, _ = m.Close() }() // shutdown path; nothing left to report
	if err := rollbackSteps(m, migrateDownSteps); err != nil && err != migrate.ErrNoChange {
		return err
	}
	log.Printf("migrate down: rolled back %d migration(s)", migrateDownSteps)
	return nil
}

func rollbackSteps(m interface{ Steps(int) error }, steps int) error {
	if steps < 1 {
		return errors.New("steps must be at least 1")
	}
	return m.Steps(-steps)
}

func runMigrateFresh(*cobra.Command, []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := cfg.ValidateDatabase(); err != nil {
		return err
	}
	sourceURL, projectRoot, err := migrationsSource()
	if err != nil {
		return err
	}
	m, err := migrate.New(sourceURL, cfg.Database.DSN())
	if err != nil {
		return wrapMigrateErr(err, projectRoot, sourceURL)
	}
	defer func() { _, _ = m.Close() }() // shutdown path; nothing left to report
	for {
		if err := m.Steps(-1); err != nil {
			if err == migrate.ErrNoChange {
				break
			}
			// When no migration is applied, Steps(-1) returns os.ErrNotExist
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			return wrapMigrateErr(err, projectRoot, sourceURL)
		}
	}
	log.Println("migrate fresh: rolled back all")
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return wrapMigrateErr(err, projectRoot, sourceURL)
	}
	if err := ensurePerChunkIndexesAfter(m, cfg.Database.DSN()); err != nil {
		return err
	}
	log.Println("migrate fresh: up ok")
	return nil
}
