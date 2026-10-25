// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0

package providers

import (
	"context"
	"testing"

	"github.com/opentofu/opentofu/internal/builtin/providers/archive"
	"github.com/opentofu/opentofu/internal/builtin/providers/local"
	"github.com/opentofu/opentofu/internal/builtin/providers/null"
	"github.com/opentofu/opentofu/internal/builtin/providers/random"
	"github.com/opentofu/opentofu/internal/builtin/providers/time"
	"github.com/opentofu/opentofu/internal/builtin/providers/tls"
	"github.com/opentofu/opentofu/internal/providers"
)

func TestBuiltinProvidersInProcess(t *testing.T) {
	cases := []struct {
		name         string
		factory      providers.Factory
		expectedType string
	}{
		{"null", InProcessFrameworkFactory("null", null.New), "null_resource"},
		{"local", InProcessFrameworkFactory("local", local.New), "local_file"},
		{"random", InProcessFrameworkFactory("random", random.New), "random_pet"},
		{"time", InProcessFrameworkFactory("time", time.New), "time_static"},
		{"archive", InProcessFrameworkFactory("archive", archive.New), "archive_file"},
		{"tls", InProcessFrameworkFactory("tls", tls.New), "tls_private_key"},
	}

	ctx := context.Background()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := tc.factory()
			if err != nil {
				t.Fatalf("factory error for %s: %v", tc.name, err)
			}
			defer p.Close(ctx)

			resp := p.GetProviderSchema(ctx)
			if resp.Diagnostics.HasErrors() {
				t.Fatalf("GetProviderSchema failed for %s: %v", tc.name, resp.Diagnostics.Err())
			}

			if _, ok := resp.ResourceTypes[tc.expectedType]; !ok {
				t.Fatalf("[%s] expected resource %q in ResourceTypes, got %v", tc.name, tc.expectedType, resp.ResourceTypes)
			}
			t.Logf("[%s] successfully verified resource %q", tc.name, tc.expectedType)
		})
	}
}
