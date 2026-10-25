// Copyright IBM Corp. 2017, 2026
// SPDX-License-Identifier: MPL-2.0

package local

import (
	"github.com/hashicorp/terraform-plugin-framework/provider"
	localprovider "github.com/opentofu/opentofu/internal/builtin/providers/local/provider"
)

func New() provider.Provider {
	return localprovider.New()
}
