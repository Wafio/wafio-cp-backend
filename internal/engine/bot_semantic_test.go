package engine

import (
	"testing"
)

func TestPrepareBotProtection_Nil(t *testing.T) {
	PrepareBotProtection(nil)
}
