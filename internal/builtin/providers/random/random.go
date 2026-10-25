// Copyright IBM Corp. 2017, 2026
// SPDX-License-Identifier: MPL-2.0

package random

import (
	"github.com/hashicorp/terraform-plugin-framework/provider"
	randomprovider "github.com/opentofu/opentofu/internal/builtin/providers/random/provider"
)

func New() provider.Provider {
	return randomprovider.New()
}
