package task

import (
	"strings"
	"time"
)

const (
	maxRetries        = 5
	retryDelay        = 10 * time.Second
	connectionRefused = "connect: connection refused"
)

func WithRetry(fetchFunc func() ([]string, error)) ([]string, error) {
	var result []string
	var err error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		result, err = fetchFunc()
		if err == nil {
			return result, nil
		}

		// Check if it's a connection refused error
		if strings.Contains(err.Error(), connectionRefused) {
			time.Sleep(retryDelay)
			continue
		}

		// If it's not a connection refused, don't retry
		break
	}
	return nil, err
}
