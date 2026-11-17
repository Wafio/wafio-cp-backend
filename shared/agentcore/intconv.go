package agentcore

// signedInt is any signed integer type; NonNegUint64 converts it with an
// explicit bounds check instead of a silently wrapping conversion.
type signedInt interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64
}

// NonNegUint64 converts v to uint64, clamping negative values to 0.
func NonNegUint64[T signedInt](v T) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v) //nolint:gosec // G115: bounds checked above
}
