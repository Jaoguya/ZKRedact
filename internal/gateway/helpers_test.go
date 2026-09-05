package gateway

import (
	"bytes"
	"math/big"
)

func bigOne() *big.Int { return big.NewInt(1) }

func containsBytes(haystack, needle []byte) bool {
	return bytes.Contains(haystack, needle)
}
