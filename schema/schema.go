// SPDX-License-Identifier: MIT

package schema

import (
	_ "embed"
)

// EmbeddedSchema contains the raw bytes of the lmcloud DSL schema.
//
//go:embed lmcloud.dsl.json
var EmbeddedSchema []byte
