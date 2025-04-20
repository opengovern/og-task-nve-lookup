package task

import (
	"time"
)

const (
	maxRetries        = 10
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

		time.Sleep(retryDelay)
		continue
	}
	return nil, err
}
