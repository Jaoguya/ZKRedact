package zk

import "errors"

// ErrPolicyNotSatisfied reports attributes that do not satisfy the policy.
//
// A DENIAL, not a failure: the request was well formed and the answer is no.
// Exp 1 counts denials separately from errors, and conflating them would let a
// scheme that denies everything look like one that authorizes cheaply.
var ErrPolicyNotSatisfied = errors.New("attributes do not satisfy the policy predicate")

// ErrOutOfScope reports a redaction location outside the policy's permitted
// range. Also a denial.
var ErrOutOfScope = errors.New("redaction location is outside the policy scope")
