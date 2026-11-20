package domain

import (
	"testing"
	"time"
)

const oneDay = 24 * time.Hour

func TestDaysLeftRoundsDown(t *testing.T) {
	now := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	for left, want := range map[time.Duration]int{
		12*oneDay + 23*time.Hour: 12,
		12 * oneDay:              12,
		oneDay:                   1,
		oneDay - time.Second:     0,
		time.Hour:                0,
		0:                        0,
		-time.Second:             -1,
		-12 * time.Hour:          -1,
		-oneDay:                  -1,
		-oneDay - time.Second:    -2,
	} {
		if got := DaysLeft(now.Add(left), now); got != want {
			t.Errorf("%s left: %d days, want %d", left, got, want)
		}
	}
}

func TestExpiryLevel(t *testing.T) {
	now := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	for name, c := range map[string]struct {
		source   string
		lifetime time.Duration // 0: the start is not known
		left     time.Duration
		days     int
		due      bool
	}{
		"uploaded, far":                 {TLSSourceUploaded, 90 * oneDay, 31 * oneDay, 0, false},
		"uploaded, 30 days and a bit":   {TLSSourceUploaded, 90 * oneDay, 30*oneDay + 23*time.Hour, 30, true},
		"uploaded, 29 days":             {TLSSourceUploaded, 90 * oneDay, 29 * oneDay, 30, true},
		"uploaded, 14 days and a bit":   {TLSSourceUploaded, 90 * oneDay, 14*oneDay + time.Hour, 14, true},
		"uploaded, 13 days":             {TLSSourceUploaded, 90 * oneDay, 13 * oneDay, 14, true},
		"uploaded, 3 days and a bit":    {TLSSourceUploaded, 90 * oneDay, 3*oneDay + time.Hour, 3, true},
		"uploaded, 2 days":              {TLSSourceUploaded, 90 * oneDay, 2 * oneDay, 3, true},
		"uploaded, an hour":             {TLSSourceUploaded, 90 * oneDay, time.Hour, 3, true},
		"uploaded, expired":             {TLSSourceUploaded, 90 * oneDay, -time.Hour, 3, true},
		"uploaded of five days, 4 days": {TLSSourceUploaded, 5 * oneDay, 4 * oneDay, 14, true},
		"acme, far":                     {TLSSourceACME, 90 * oneDay, 40 * oneDay, 0, false},
		"acme, 15 days":                 {TLSSourceACME, 90 * oneDay, 15 * oneDay, 0, false},
		"acme, 14 days":                 {TLSSourceACME, 90 * oneDay, 14 * oneDay, 14, true},
		"acme, 4 days":                  {TLSSourceACME, 90 * oneDay, 4 * oneDay, 14, true},
		"acme, 3 days":                  {TLSSourceACME, 90 * oneDay, 3 * oneDay, 3, true},
		"acme, expired":                 {TLSSourceACME, 90 * oneDay, -oneDay, 3, true},
		"acme of 45 days renews at 15":  {TLSSourceACME, 45 * oneDay, 14 * oneDay, 14, true},
		"acme of 42 days renews at 14":  {TLSSourceACME, 42 * oneDay, 10 * oneDay, 0, false},
		"acme of 42 days, 3 days":       {TLSSourceACME, 42 * oneDay, 3 * oneDay, 3, true},
		"acme of 30 days, 5 days":       {TLSSourceACME, 30 * oneDay, 5 * oneDay, 0, false},
		"acme of 6 days, 2 days":        {TLSSourceACME, 6 * oneDay, 2 * oneDay, 0, false},
		"acme of 6 days, expired":       {TLSSourceACME, 6 * oneDay, -oneDay, 0, false},
		"acme, start unknown":           {TLSSourceACME, 0, 10 * oneDay, 14, true},
		"acme, start unknown, 3 days":   {TLSSourceACME, 0, 3 * oneDay, 3, true},
		"no source":                     {"", 90 * oneDay, oneDay, 0, false},
		"another source":                {"other", 90 * oneDay, oneDay, 0, false},
	} {
		notAfter := now.Add(c.left)
		var notBefore time.Time
		if c.lifetime > 0 {
			notBefore = notAfter.Add(-c.lifetime)
		}
		days, due := ExpiryLevel(c.source, notBefore, notAfter, now)
		if days != c.days || due != c.due {
			t.Errorf("%s: level %d due %v, want %d %v", name, days, due, c.days, c.due)
		}
	}
	// A start after the end is a bad record, not a short life: nothing is skipped.
	notAfter := now.Add(10 * oneDay)
	if days, due := ExpiryLevel(TLSSourceACME, notAfter.Add(oneDay), notAfter, now); days != 14 || !due {
		t.Errorf("a start after the end: %d %v", days, due)
	}
}

// The levels are in descending order, which ExpiryLevel relies on to find the tightest one.
func TestExpiryLevelsAreDescending(t *testing.T) {
	for name, levels := range map[string][]int{"uploaded": UploadedExpiryDays, "acme": ACMEExpiryDays} {
		for i := 1; i < len(levels); i++ {
			if levels[i] >= levels[i-1] {
				t.Errorf("%s levels %v are not descending", name, levels)
			}
		}
	}
}
