package utctime

import (
	"encoding/json"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
	_ "time/tzdata" // Asia/Jakarta must resolve even on a host without zoneinfo.

	"github.com/jackc/pgx/v5/pgtype"
)

const tzChildEnv = "WAFIO_UTCTIME_TZ_CHILD"

// jsonTimestamp matches an RFC 3339 string value inside a JSON document.
var jsonTimestamp = regexp.MustCompile(`"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"`)

func assertUTCJSON(t *testing.T, what, body string) {
	t.Helper()
	found := jsonTimestamp.FindAllString(body, -1)
	if len(found) == 0 {
		t.Fatalf("%s: no timestamp in %s", what, body)
	}
	for _, ts := range found {
		if !strings.HasSuffix(ts, `Z"`) {
			t.Errorf("%s: timestamp %s is not UTC (want a \"Z\" suffix)", what, ts)
		}
	}
}

// TestPinsUTCUnderNonUTCHostZone runs its checks in a child process started
// with TZ=Asia/Jakarta, so a regression shows up as "+07:00" even on a CI
// host whose own zone is already UTC.
func TestPinsUTCUnderNonUTCHostZone(t *testing.T) {
	if os.Getenv(tzChildEnv) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestPinsUTCUnderNonUTCHostZone$", "-test.count=1", "-test.v")
		cmd.Env = append(os.Environ(), tzChildEnv+"=1", "TZ=Asia/Jakarta")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child under TZ=Asia/Jakarta failed: %v\n%s", err, out)
		}
		t.Logf("child under TZ=Asia/Jakarta:\n%s", out)
		return
	}

	jakarta, err := time.LoadLocation("Asia/Jakarta")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(time.Date(2026, 9, 27, 21, 49, 16, 0, jakarta)); !strings.Contains(string(b), "+07:00") {
		t.Fatalf("sanity: a Jakarta time must marshal with +07:00, got %s", b)
	}

	t.Run("process clock", func(t *testing.T) {
		if time.Local != time.UTC {
			t.Fatalf("time.Local = %v under TZ=Asia/Jakarta; this package's init must pin it to UTC", time.Local)
		}
		if loc := time.Now().Location(); loc != time.UTC {
			t.Fatalf("time.Now().Location() = %v, want UTC", loc)
		}
		b, _ := json.Marshal(map[string]any{"generated_at": time.Now()})
		assertUTCJSON(t, "time.Now()", string(b))
	})

	t.Run("pgx-decoded timestamptz", func(t *testing.T) {
		// The same codec every pooled connection uses to scan timestamptz.
		m := pgtype.NewMap()
		wire, err := m.Encode(pgtype.TimestamptzOID, pgtype.BinaryFormatCode, time.Date(2026, 9, 27, 14, 49, 16, 0, time.UTC), nil)
		if err != nil {
			t.Fatal(err)
		}
		var scanned time.Time
		if err := m.Scan(pgtype.TimestamptzOID, pgtype.BinaryFormatCode, wire, &scanned); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(map[string]any{"created_at": scanned})
		if got, want := string(b), `{"created_at":"2026-09-27T14:49:16Z"}`; got != want {
			t.Fatalf("scanned row JSON = %s, want %s", got, want)
		}
	})
}
