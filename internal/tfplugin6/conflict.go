// Copyright (c) The OpenTofu Authors
// SPDX-License-Identifier: MPL-2.0

package tfplugin6

import "os"

func init() {
	if os.Getenv("GOLANG_PROTOBUF_REGISTRATION_CONFLICT") == "" {
		_ = os.Setenv("GOLANG_PROTOBUF_REGISTRATION_CONFLICT", "ignore")
	}
}
