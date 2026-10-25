// Copyright IBM Corp. 2017, 2026
// SPDX-License-Identifier: MPL-2.0

package tls

import (
	"github.com/hashicorp/terraform-plugin-framework/provider"
	tlsprovider "github.com/opentofu/opentofu/internal/builtin/providers/tls/provider"
)

func New() provider.Provider {
	return tlsprovider.New()
}
