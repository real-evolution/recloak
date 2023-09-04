package recloak

import (
	"time"

	"github.com/Nerzal/gocloak/v13"
)

// A re-export of `gocloak.APIError` for convenience.
type APIError = gocloak.APIError

// Checks whether the given timestamp is expired (in the past) or not.
func isTimestampExpired(timestamp int64) bool {
	exp := time.Unix(timestamp, 0)
	now := time.Now()

	return exp.After(now)
}

// Checks whether an array contains all of the given items.
func arrayContainsAll(array, required []string) bool {
	if len(array) < len(required) {
		return false
	}

	for _, item := range required {
		if !arrayContains(array, item) {
			return false
		}
	}

	return true
}

// Checks whether an array contains any of the given items.
func arrayContainsAny(array, required []string) bool {
	for _, item := range required {
		if arrayContains(array, item) {
			return true
		}
	}

	return false
}

// Checks whether an array contains the given item.
func arrayContains(array []string, required string) bool {
	for _, item := range array {
		if item == required {
			return true
		}
	}

	return false
}
