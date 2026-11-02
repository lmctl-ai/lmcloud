// SPDX-License-Identifier: MIT

// Package schema embeds the canonical raw lmcloud schema bytes. Every
// lm<provider> host must serve exactly these bytes for --lmcode-schema --json.
package schema

import _ "embed"

//go:embed lmcloud.dsl.json
var Bytes []byte
