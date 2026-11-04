// SPDX-License-Identifier: MIT

package hostkit

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestOpusPinnedTokenBytesEvictActivePassword(t *testing.T) {
	s := NewErrorState()
	s.SetAbort(false)
	active := "ActivePass12345"
	s.PinActiveSecret("pw:\x00pool\x00alice", active)
	tok := strings.Repeat("A", 780) // measured real fake RS256 session size, see cloudhost probe
	n := 0
	for i := 0; i < 6000; i++ { // 47 users at the 128-session cap; 3 sessions each across 2000 users
		n++
		s.PinActiveSecret(fmt.Sprintf("tok:\x00pool\x00u%d\x00%064d", i, i), fmt.Sprintf("%s.%08d", tok, i))
	}
	for i := 0; i < 5000; i++ {
		s.AddRedaction(fmt.Sprintf("Churn%012d", i))
	}
	_ = s.Fail("user_sign_in", "pool", ProviderError(Internal, 500, "x", "upstream echoed "+active))
	t.Logf("sessions=%d message=%q", n, s.Last().Message)
	if strings.Contains(s.Last().Message, active) {
		t.Fatal("active password evicted from pins by legal live session tokens")
	}
}

func TestOpusPinnedKeyCountEvictsActivePassword(t *testing.T) {
	s := NewErrorState()
	s.SetAbort(false)
	active := "ActivePass12345"
	s.PinActiveSecret("pw:first", active)
	for i := 0; i < 16400; i++ {
		s.PinActiveSecret(fmt.Sprintf("pw:\x00p\x00u%d", i), fmt.Sprintf("Pw%010d", i))
	}
	for i := 0; i < 5000; i++ {
		s.AddRedaction(fmt.Sprintf("Churn%012d", i))
	}
	_ = s.Fail("op", "pool", ProviderError(Internal, 500, "x", "upstream echoed "+active))
	if strings.Contains(s.Last().Message, active) {
		t.Fatal("legal 16.4k users (cap 128 pools x 2000) evict active password pin")
	}
}

func TestOpusPinnedOrderLeaksUnderChurn(t *testing.T) {
	s := NewErrorState()
	for i := 0; i < 300000; i++ {
		k := fmt.Sprintf("tok:\x00pool\x00alice\x00%064d", i)
		s.PinActiveSecret(k, fmt.Sprintf("TokenValue%d", i))
		s.UnpinActiveSecret(k)
	}
	t.Logf("live pins=%d pinnedOrder len=%d", len(s.pinnedSecrets), len(s.pinnedOrder))
	var m runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m)
	t.Logf("heap=%dMiB", m.HeapAlloc>>20)
	if len(s.pinnedOrder) > 2*maxPinnedRedactionKeys {
		t.Fatalf("pinnedOrder unbounded under pin/unpin churn: %d entries with %d live pins", len(s.pinnedOrder), len(s.pinnedSecrets))
	}
}

func TestOpusOverlappingPinnedSecretsPartialLeak(t *testing.T) {
	leaks := 0
	for i := 0; i < 200; i++ {
		s := NewErrorState()
		s.SetAbort(false)
		s.PinActiveSecret("a", "Prefix1234")
		s.PinActiveSecret("b", "Prefix1234TailSecret99")
		_ = s.Fail("op", "pool", ProviderError(Internal, 500, "x", "echo Prefix1234TailSecret99 end"))
		if strings.Contains(s.Last().Message, "TailSecret99") {
			leaks++
		}
	}
	t.Logf("partial leaks %d/200", leaks)
	if leaks > 0 {
		t.Fatal("map-order scrub leaks the tail of a longer active secret")
	}
}
