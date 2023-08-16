package recloak

import "time"

// Checks whether the given timestamp is expired (in the past) or not.
func isTimestampExpired(timestamp int64) bool {
	exp := time.Unix(timestamp, 0)
	now := time.Now()

	return exp.After(now)
}
