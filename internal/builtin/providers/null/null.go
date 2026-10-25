// Copyright IBM Corp. 2017, 2026
// SPDX-License-Identifier: MPL-2.0

package null

import (
	"github.com/hashicorp/terraform-plugin-framework/provider"
	nullprovider "github.com/opentofu/opentofu/internal/builtin/providers/null/provider"
)

func New() provider.Provider {
	return nullprovider.New()
}
