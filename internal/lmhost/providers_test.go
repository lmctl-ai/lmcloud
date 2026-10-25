// SPDX-License-Identifier: MIT

package lmhost

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAllBuiltinProvidersEndToEnd(t *testing.T) {
	h := NewHost()
	tmpDir := t.TempDir()

	srcDir := filepath.Join(tmpDir, "source_dir")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "sample.txt"), []byte("archive content inside zip"), 0644); err != nil {
		t.Fatal(err)
	}

	tf := `
resource "random_pet" "server" {
  length    = 2
  separator = "-"
}

resource "random_password" "db_pass" {
  length  = 16
  special = false
}

resource "random_id" "cluster_id" {
  byte_length = 4
}

resource "local_file" "rendered" {
  content  = "Server name: ${random_pet.server.id}\nCluster: ${random_id.cluster_id.hex}\n"
  filename = "${path.module}/server.txt"
}

resource "time_static" "deployed_at" {
  triggers = {
    server_id = random_pet.server.id
  }
}

resource "tls_private_key" "ca" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem = tls_private_key.ca.private_key_pem

  subject {
    common_name  = "in-process.local"
    organization = "LMCloud Testing"
  }

  validity_period_hours = 12
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

data "archive_file" "backup" {
  type        = "zip"
  source_dir  = "${path.module}/source_dir"
  output_path = "${path.module}/backup.zip"
}

resource "null_resource" "hook" {
  triggers = {
    pet = random_pet.server.id
    sha = data.archive_file.backup.output_sha
  }
}

output "server_name" {
  value = random_pet.server.id
}

output "password_len" {
  value     = length(random_password.db_pass.result)
  sensitive = true
}

output "cert_subject" {
  value = tls_self_signed_cert.ca.subject[0].common_name
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte(tf), 0644); err != nil {
		t.Fatal(err)
	}

	if !h.Init(tmpDir) {
		t.Fatalf("Init failed: %s", h.LastError())
	}

	plan := h.Plan(tmpDir)
	if plan.errored {
		t.Fatalf("Plan failed: %s", plan.lastError)
	}
	if plan.Add() <= 0 {
		t.Fatalf("expected planned additions, got %d", plan.Add())
	}

	if !h.Apply(tmpDir) {
		t.Fatalf("Apply failed: %s", h.LastError())
	}

	serverName := h.Output(tmpDir, "server_name")
	if serverName == "" {
		t.Fatalf("expected non-empty server_name output")
	}

	passLen := h.Output(tmpDir, "password_len")
	if passLen != "16" {
		t.Fatalf("expected password length 16, got %q", passLen)
	}

	certSubject := h.Output(tmpDir, "cert_subject")
	if certSubject != "in-process.local" {
		t.Fatalf("expected cert_subject 'in-process.local', got %q", certSubject)
	}

	// Verify local_file on disk
	renderedFile := filepath.Join(tmpDir, "server.txt")
	content, err := os.ReadFile(renderedFile)
	if err != nil {
		t.Fatalf("failed to read rendered local_file: %v", err)
	}
	if !strings.Contains(string(content), serverName) {
		t.Fatalf("rendered content does not contain serverName %q:\n%s", serverName, content)
	}

	// Verify archive_file on disk
	zipFile := filepath.Join(tmpDir, "backup.zip")
	if stat, err := os.Stat(zipFile); err != nil || stat.Size() == 0 {
		t.Fatalf("expected valid backup.zip file on disk, got err=%v", err)
	}

	state := h.ShowState(tmpDir)
	if !strings.Contains(state, "random_pet.server") ||
		!strings.Contains(state, "tls_self_signed_cert.ca") ||
		!strings.Contains(state, "time_static.deployed_at") {
		t.Fatalf("state missing expected resources:\n%s", state)
	}

	t.Logf("Success! Server: %s, Cert Common Name: %s", serverName, certSubject)
}
