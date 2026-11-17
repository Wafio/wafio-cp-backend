package application

import (
	"encoding/json"
	"testing"
)

func TestDeliverySnapshotPreservesStatusWithoutClaimingPersistence(t *testing.T) {
	raw := withTelemetryDelivery(json.RawMessage(`{"running":true}`), json.RawMessage(`{"pending_batches":2,"persisted_acknowledgements":false}`), 3)
	var got struct {
		Running  bool `json:"running"`
		Failures int  `json:"telemetry_send_failures"`
		Delivery struct {
			Pending   int  `json:"pending_batches"`
			Persisted bool `json:"persisted_acknowledgements"`
		} `json:"telemetry_delivery"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Running || got.Failures != 3 || got.Delivery.Pending != 2 || got.Delivery.Persisted {
		t.Fatalf("wrong delivery evidence %s", raw)
	}
}
