package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/config"
	"github.com/wafio/wafio-cp-backend/internal/otp"
)

// oldKeyEnv holds the key that totp.enc_key had before the operator changed it.
const oldKeyEnv = "WAFIO_OLD_TOTP_ENC_KEY"

var rekeyApply bool

var rekeyCmd = &cobra.Command{
	Use:   "rekey",
	Short: "Re-encrypt the stored secrets after totp.enc_key was changed",
	Long: "Re-encrypt every value that is sealed with totp.enc_key from the old key to the new one: the TOTP secrets\n" +
		"of the users, the SMTP password, the malware database key and the private keys of uploaded certificates.\n\n" +
		"The old key is read from the environment variable " + oldKeyEnv + ", the new key from the\n" +
		"configuration (totp.enc_key), which must already hold it. Without --apply the command only counts what it\n" +
		"would rewrite. With --apply it rewrites everything in one transaction, and writes nothing when a value\n" +
		"opens with neither key. A value that already opens with the new key counts as done, so the command can\n" +
		"be run again. It never prints a value.\n\n" +
		"Stop the control plane before --apply and start it again after, with the new key.",
	Args: cobra.NoArgs,
	// A refusal is a message about keys or rows; the usage text would bury it.
	SilenceUsage: true,
	RunE:         runRekey,
}

func init() {
	rekeyCmd.Flags().BoolVar(&rekeyApply, "apply", false, "rewrite the values in one transaction; without it the command only reports")
	rootCmd.AddCommand(rekeyCmd)
}

// rekeyKeys builds the two keys and refuses a missing one, one that is no key, and two that are the
// same. The errors name the variable or setting, never a key.
func rekeyKeys(oldRaw, newRaw string) (oldKey, newKey *otp.Encryptor, err error) {
	if strings.TrimSpace(oldRaw) == "" {
		return nil, nil, fmt.Errorf("%s is not set: put the key that totp.enc_key had before it was changed in it", oldKeyEnv)
	}
	if strings.TrimSpace(newRaw) == "" {
		return nil, nil, errors.New("totp.enc_key is not set: configure the new key (env WAFIO_TOTP_ENC_KEY) before running rekey")
	}
	if oldKey, err = otp.NewEncryptor(oldRaw); err != nil {
		return nil, nil, fmt.Errorf("%s is not a valid key: %w", oldKeyEnv, err)
	}
	if newKey, err = otp.NewEncryptor(newRaw); err != nil {
		return nil, nil, fmt.Errorf("totp.enc_key is not a valid key: %w", err)
	}
	// The keys are the same when one opens what the other sealed, however each was written (hex or
	// base64).
	probe, err := oldKey.Encrypt("probe")
	if err != nil {
		return nil, nil, err
	}
	if _, err := newKey.Decrypt(probe); err == nil {
		return nil, nil, fmt.Errorf("%s and totp.enc_key are the same key: there is nothing to rewrite", oldKeyEnv)
	}
	return oldKey, newKey, nil
}

func runRekey(cmd *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if err := cfg.ValidateDatabase(); err != nil {
		return err
	}
	oldKey, newKey, err := rekeyKeys(os.Getenv(oldKeyEnv), cfg.TOTP.EncKey)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	repo, err := repository.New(ctx, cfg.Database.DSN())
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer repo.Close()

	report, err := repo.Rekey(ctx, oldKey, newKey, rekeyApply)
	printRekeyReport(cmd.OutOrStdout(), report, rekeyApply, err)
	if errors.Is(err, repository.ErrRekeyUnreadable) {
		return errors.New("nothing was changed: fix the rows above or give the key that sealed them in " + oldKeyEnv)
	}
	return err
}

var rekeyKindNames = map[string]string{
	repository.RekeyKindTOTPSecret:     "TOTP secrets of users",
	repository.RekeyKindTOTPPending:    "TOTP secrets waiting for a code",
	repository.RekeyKindSMTPPassword:   "SMTP password",
	repository.RekeyKindMalwareKey:     "malware database key",
	repository.RekeyKindCertificateKey: "certificate private keys",
}

// printRekeyReport writes the counts per kind and what happened. It prints no value and no key; the
// rows it names are ids and setting names.
func printRekeyReport(w io.Writer, r repository.RekeyReport, apply bool, runErr error) {
	if len(r.Counts) == 0 {
		return
	}
	mode := "dry run, nothing is changed"
	if apply {
		mode = "apply"
	}
	fmt.Fprintf(w, "Values sealed with totp.enc_key (%s)\n\n", mode)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "VALUE\tTO REWRITE\tALREADY NEW KEY\tPLAIN TEXT\tUNREADABLE")
	for _, c := range r.Counts {
		name := rekeyKindNames[c.Kind]
		if name == "" {
			name = c.Kind
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\n", name, c.ToRewrite, c.AlreadyNew, c.NotSealed, c.Unreadable)
	}
	_ = tw.Flush()
	fmt.Fprintln(w)
	for _, c := range r.Counts {
		for _, row := range c.UnreadableRows {
			fmt.Fprintf(w, "Opens with neither key: %s (%s)\n", row, c.Kind)
		}
		if shown := len(c.UnreadableRows); c.Unreadable > shown {
			fmt.Fprintf(w, "... and %d more of %s\n", c.Unreadable-shown, c.Kind)
		}
	}
	switch {
	case runErr != nil:
		// The caller reports the error; nothing was written.
	case r.Applied:
		fmt.Fprintf(w, "Rewrote %d values in one transaction. Start the control plane with the new totp.enc_key.\n", r.ToRewrite())
	case r.ToRewrite() == 0:
		fmt.Fprintln(w, "Dry run: nothing to rewrite.")
	default:
		fmt.Fprintf(w, "Dry run: %d values would be rewritten. Run again with --apply to do it.\n", r.ToRewrite())
	}
}
