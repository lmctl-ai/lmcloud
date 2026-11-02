// SPDX-License-Identifier: MIT

package hostkit

import (
	"context"
	"sort"
)

// DefaultMaxPages bounds exhaustive listings.
const DefaultMaxPages = 1000

// PageFetch returns one page of items and the next continuation token ("" = last page).
type PageFetch[T any] func(ctx context.Context, token string) (items []T, next string, err error)

// ListAll follows every page. It never returns partial success: a repeated
// token (no progress or a cycle), exceeding maxPages, a cancelled/expired ctx
// or any page error fails the whole call.
func ListAll[T any](ctx context.Context, maxPages int, fetch PageFetch[T]) ([]T, *CloudError) {
	if maxPages <= 0 {
		maxPages = DefaultMaxPages
	}
	var out []T
	seen := map[string]bool{}
	token := ""
	for page := 0; ; page++ {
		if page >= maxPages {
			return nil, ProviderError(Internal, 0, "", "listing exceeded "+itoa(int64(maxPages))+" pages; refusing to return a partial result")
		}
		if err := ctx.Err(); err != nil {
			return nil, ProviderError(Internal, 0, "", "listing stopped before completion: "+err.Error())
		}
		items, next, err := fetch(ctx, token)
		if err != nil {
			return nil, AsCloudError(err)
		}
		out = append(out, items...)
		if next == "" {
			return out, nil
		}
		if next == token || seen[next] {
			return nil, ProviderError(Internal, 0, "", "pagination stalled: continuation token repeated")
		}
		seen[next] = true
		token = next
	}
}

// SortedUnique returns names sorted in byte order with duplicates removed.
func SortedUnique(names []string) []string {
	out := append([]string(nil), names...)
	sort.Strings(out)
	n := 0
	for i, s := range out {
		if i == 0 || s != out[n-1] {
			out[n] = s
			n++
		}
	}
	return out[:n]
}
