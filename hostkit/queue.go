// SPDX-License-Identifier: MIT

package hostkit

import (
	"context"
	"time"
)

// WaitLoop implements wait_seconds for providers without server-side long
// polling: poll runs at least once and repeats every interval until it returns
// a non-zero count, an error, or the client deadline now+wait passes. If ctx
// ends before that deadline it returns an INTERNAL error (since v3; earlier
// versions returned nil, turning a cancellation into an empty receive).
func WaitLoop(ctx context.Context, wait, interval time.Duration, now func() time.Time, sleep func(context.Context, time.Duration) error, poll func(ctx context.Context) (int, error)) error {
	if now == nil {
		now = time.Now
	}
	if sleep == nil {
		sleep = SleepContext
	}
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	deadline := now().Add(wait)
	for {
		n, err := poll(ctx)
		if err != nil || n > 0 {
			return err
		}
		remaining := deadline.Sub(now())
		if remaining <= 0 {
			return nil
		}
		if err := sleep(ctx, min(interval, remaining)); err != nil {
			// The caller's context ended before the requested wait: that is a
			// failure, not an empty successful receive (v3).
			return ProviderError(Internal, 0, "", "receive wait interrupted: "+err.Error())
		}
	}
}

// ReceiptPrecedence applies the ack/nack error precedence of design 07 §5.4:
// a missing queue (NOT_FOUND) wins over a malformed or rejected receipt.
// e is the adapter's error; queueExists probes the queue (read-only).
//
//   - NOT_FOUND for the queue                 -> NOT_FOUND
//   - INVALID_ARGUMENT, or NOT_FOUND for the
//     message (onMissingMessage decides)      -> probe queue; missing -> NOT_FOUND
//   - anything else                           -> unchanged
//
// It returns nil when the outcome is success (an idempotent ack of a message
// that is already gone from an existing queue).
func ReceiptPrecedence(e *CloudError, ackMissingIsOK bool, queueExists func() (bool, *CloudError)) *CloudError {
	if e == nil || e.Code == OK {
		return nil
	}
	if e.Code == NotFound && e.Absent == AbsentQueue {
		return e
	}
	receiptProblem := e.Code == InvalidArgument || (e.Code == NotFound && (e.Absent == AbsentMessage || e.Absent == AbsentUnknown))
	if !receiptProblem {
		return e
	}
	exists, perr := queueExists()
	if perr != nil {
		return perr
	}
	if !exists {
		return ProviderError(NotFound, e.HTTPStatus, e.ProviderCode, "queue does not exist").WithAbsent(AbsentQueue)
	}
	if e.Code == NotFound && e.Absent == AbsentMessage {
		if ackMissingIsOK {
			return nil
		}
		c := *e
		c.Code = InvalidArgument
		c.Message = "receipt does not identify an in-flight message: " + e.Message
		return &c
	}
	// Unqualified NOT_FOUND or a rejected receipt on an existing queue: report it unchanged.
	return e
}
