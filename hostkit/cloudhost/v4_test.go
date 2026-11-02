// SPDX-License-Identifier: MIT

package cloudhost

import (
	"regexp"
	"strings"
	"testing"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
)

var hex32 = regexp.MustCompile(`(?i)[0-9a-f]{32}`)

// v4: a provider echo of the create token never reaches last_error or aborts.
func TestCreateTokenNeverInLastErrorOrAbort(t *testing.T) {
	f := fakeadapter.New(fakeadapter.Options{EchoCreateToken: true})
	h := New(Config{Store: f, Queue: f, Endpoints: &hostkit.EndpointResolver{Getenv: func(string) string { return "" }}})
	h.SetAbortOnError(false)
	for _, create := range []func() (bool, error){
		func() (bool, error) { return h.BucketCreate(false, "echo-bkt") },
		func() (bool, error) { return h.QueueCreate(false, "echo-q") },
	} {
		if ok, err := create(); ok || err != nil {
			t.Fatalf("expected a recorded failure, got %v %v", ok, err)
		}
		last := h.LastError()
		if last.Code != hostkit.PermissionDenied {
			t.Fatalf("last=%+v", last)
		}
		for _, field := range []string{last.Message, last.ProviderCode} {
			if hex32.MatchString(field) || !strings.Contains(field, hostkit.CreateTokenMarker) {
				t.Fatalf("token not redacted: %q", field)
			}
		}
	}
	h.SetAbortOnError(true)
	_, err := h.BucketCreate(false, "echo-bkt2")
	if err == nil || hex32.MatchString(err.Error()) || !strings.Contains(err.Error(), hostkit.CreateTokenMarker) {
		t.Fatalf("abort message: %v", err)
	}
}
