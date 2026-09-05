package ref22

import "math/big"

func bigFromBytes(b []byte) *big.Int { return new(big.Int).SetBytes(b) }
