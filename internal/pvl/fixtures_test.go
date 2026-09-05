package pvl

import (
	"time"

	"zkredact/pkg/scheme"
)

func policyFixture() scheme.Policy {
	return scheme.Policy{
		ID:        "pol-0000",
		Version:   1,
		Predicate: "((sender OR receiver) AND validator)",
	}
}

func requestFixture() *scheme.Request {
	return &scheme.Request{
		ID:          "req-0001",
		RequesterID: "id-000000",
		TargetTxID:  "tx-00000003",
		NewContent:  []byte("redacted"),
		PolicyID:    "pol-0000",
		Timestamp:   time.Unix(1750000000, 0),
		Nonce:       []byte("nonce-1"),
	}
}
