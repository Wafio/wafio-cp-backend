package bodyinspect

import (
	"testing"
)

func TestDecodedLimit(t *testing.T) {
	for routeMax, want := range map[int]int{0: MaxDecodedBodyBytes, -1: MaxDecodedBodyBytes, 64 << 20: MaxDecodedBodyBytes, 1 << 20: 1 << 20, 4096: 4096} {
		if got := DecodedLimit(routeMax); got != want {
			t.Errorf("DecodedLimit(%d) = %d, want %d", routeMax, got, want)
		}
	}
}
