// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: MPL-2.0

package time

import (
	"github.com/hashicorp/terraform-plugin-framework/provider"
	timeprovider "github.com/opentofu/opentofu/internal/builtin/providers/time/provider"
)

func New() provider.Provider {
	return timeprovider.New()
}
