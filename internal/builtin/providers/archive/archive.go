// Copyright IBM Corp. 2017, 2026
// SPDX-License-Identifier: MPL-2.0

package archive

import (
	"github.com/hashicorp/terraform-plugin-framework/provider"
	archiveprovider "github.com/opentofu/opentofu/internal/builtin/providers/archive/provider"
)

func New() provider.Provider {
	return archiveprovider.New()
}
