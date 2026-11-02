#!/usr/bin/env bash
# Runs end-to-end provider-native object storage round trips with plain curl against each simulator.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIM_CTL="$HERE/sim.sh"

[ -x "$SIM_CTL" ] || { echo "ERROR: $SIM_CTL is not executable" >&2; exit 1; }

current_sim=""
# shellcheck disable=SC2317
cleanup() {
  if [ -n "$current_sim" ]; then
    "$SIM_CTL" stop "$current_sim" >/dev/null 2>&1 || true
    current_sim=""
  fi
}
trap cleanup EXIT ERR INT TERM

pass_count=0
fail_count=0
results=()

test_aws() {
  echo "=== Testing AWS (awssim) ==="
  current_sim="aws"
  local url
  url="$("$SIM_CTL" start aws)"
  echo "  Started awssim at $url"

  local ts
  ts="$(python3 -c 'import time; print(int(time.time() * 1000))')"
  local bucket="test-aws-bucket-$ts"
  local obj="test-file-$ts.txt"
  local payload="awssim S3 test payload $ts binary:\x00\x01\xfe\xff"
  local tmp_in
  tmp_in="$(mktemp "${TMPDIR:-/tmp}/lmcloud.XXXXXX")"
  local tmp_out
  tmp_out="$(mktemp "${TMPDIR:-/tmp}/lmcloud.XXXXXX")"
  printf "%b" "$payload" > "$tmp_in"

  echo "  Creating S3 bucket $bucket (PUT $url/$bucket)..."
  curl -f -s -S -X PUT "$url/$bucket" >/dev/null

  echo "  Putting object $obj (PUT $url/$bucket/$obj)..."
  curl -f -s -S -X PUT --data-binary "@$tmp_in" "$url/$bucket/$obj" >/dev/null

  echo "  Getting object $obj (GET $url/$bucket/$obj)..."
  curl -f -s -S "$url/$bucket/$obj" -o "$tmp_out"

  if ! cmp -s "$tmp_in" "$tmp_out"; then
    echo "ERROR: Retrieved payload does not match uploaded payload for AWS!" >&2
    rm -f "$tmp_in" "$tmp_out"
    return 1
  fi
  echo "  Verified payload byte equality."

  echo "  Deleting object $obj (DELETE $url/$bucket/$obj)..."
  curl -f -s -S -X DELETE "$url/$bucket/$obj" >/dev/null

  echo "  Deleting bucket $bucket (DELETE $url/$bucket)..."
  curl -f -s -S -X DELETE "$url/$bucket" >/dev/null

  rm -f "$tmp_in" "$tmp_out"
  "$SIM_CTL" stop aws >/dev/null
  current_sim=""
  echo "PASS: awssim S3 round trip"
  return 0
}

test_azure() {
  echo "=== Testing Azure (azuresim) ==="
  current_sim="azure"
  local url
  url="$("$SIM_CTL" start azure)"
  echo "  Started azuresim at $url"

  local ts
  ts="$(python3 -c 'import time; print(int(time.time() * 1000))')"
  local account="devstoreaccount1"
  local container="test-azure-container-$ts"
  local blob="test-blob-$ts.txt"
  local payload="azuresim Blob test payload $ts binary:\x00\x01\xfe\xff"
  local tmp_in
  tmp_in="$(mktemp "${TMPDIR:-/tmp}/lmcloud.XXXXXX")"
  local tmp_out
  tmp_out="$(mktemp "${TMPDIR:-/tmp}/lmcloud.XXXXXX")"
  printf "%b" "$payload" > "$tmp_in"

  echo "  Creating Blob container $container (PUT $url/$account/$container?restype=container)..."
  curl -f -s -S -X PUT "$url/$account/$container?restype=container" >/dev/null

  echo "  Putting block blob $blob (PUT $url/$account/$container/$blob)..."
  curl -f -s -S -X PUT -H 'x-ms-blob-type: BlockBlob' --data-binary "@$tmp_in" "$url/$account/$container/$blob" >/dev/null

  echo "  Getting blob $blob (GET $url/$account/$container/$blob)..."
  curl -f -s -S "$url/$account/$container/$blob" -o "$tmp_out"

  if ! cmp -s "$tmp_in" "$tmp_out"; then
    echo "ERROR: Retrieved payload does not match uploaded payload for Azure!" >&2
    rm -f "$tmp_in" "$tmp_out"
    return 1
  fi
  echo "  Verified payload byte equality."

  echo "  Deleting blob $blob (DELETE $url/$account/$container/$blob)..."
  curl -f -s -S -X DELETE "$url/$account/$container/$blob" >/dev/null

  echo "  Deleting container $container (DELETE $url/$account/$container?restype=container)..."
  curl -f -s -S -X DELETE "$url/$account/$container?restype=container" >/dev/null

  rm -f "$tmp_in" "$tmp_out"
  "$SIM_CTL" stop azure >/dev/null
  current_sim=""
  echo "PASS: azuresim Blob Storage round trip"
  return 0
}

test_gcp() {
  echo "=== Testing GCP (gcpsim) ==="
  current_sim="gcp"
  local url
  url="$("$SIM_CTL" start gcp)"
  echo "  Started gcpsim at $url"

  local ts
  ts="$(python3 -c 'import time; print(int(time.time() * 1000))')"
  local project="gcpsim-local"
  local bucket="test-gcp-bucket-$ts"
  local obj="test-obj-$ts.txt"
  local payload="gcpsim GCS test payload $ts binary:\x00\x01\xfe\xff"
  local tmp_in
  tmp_in="$(mktemp "${TMPDIR:-/tmp}/lmcloud.XXXXXX")"
  local tmp_out
  tmp_out="$(mktemp "${TMPDIR:-/tmp}/lmcloud.XXXXXX")"
  printf "%b" "$payload" > "$tmp_in"

  echo "  Creating GCS bucket $bucket (POST $url/storage/v1/b?project=$project)..."
  curl -f -s -S -X POST -H 'Content-Type: application/json' \
    -d "{\"name\": \"$bucket\"}" \
    "$url/storage/v1/b?project=$project" >/dev/null

  echo "  Uploading object media $obj (POST $url/upload/storage/v1/b/$bucket/o?uploadType=media&name=$obj)..."
  curl -f -s -S -X POST -H 'Content-Type: application/octet-stream' \
    --data-binary "@$tmp_in" \
    "$url/upload/storage/v1/b/$bucket/o?uploadType=media&name=$obj" >/dev/null

  echo "  Getting object media $obj (GET $url/storage/v1/b/$bucket/o/$obj?alt=media)..."
  curl -f -s -S "$url/storage/v1/b/$bucket/o/$obj?alt=media" -o "$tmp_out"

  if ! cmp -s "$tmp_in" "$tmp_out"; then
    echo "ERROR: Retrieved payload does not match uploaded payload for GCP!" >&2
    rm -f "$tmp_in" "$tmp_out"
    return 1
  fi
  echo "  Verified payload byte equality."

  echo "  Deleting object $obj (DELETE $url/storage/v1/b/$bucket/o/$obj)..."
  curl -f -s -S -X DELETE "$url/storage/v1/b/$bucket/o/$obj" >/dev/null

  echo "  Deleting bucket $bucket (DELETE $url/storage/v1/b/$bucket)..."
  curl -f -s -S -X DELETE "$url/storage/v1/b/$bucket" >/dev/null

  rm -f "$tmp_in" "$tmp_out"
  "$SIM_CTL" stop gcp >/dev/null
  current_sim=""
  echo "PASS: gcpsim GCS round trip"
  return 0
}

test_oci() {
  echo "=== Testing OCI (ocisim) ==="
  current_sim="oci"
  local url
  url="$("$SIM_CTL" start oci)"
  echo "  Started ocisim at $url"

  local ts
  ts="$(python3 -c 'import time; print(int(time.time() * 1000))')"
  local tenancy="ocid1.tenancy.oc1..flocilocaltenancy0000000000000000000000000000000000000000"
  local bucket="test-oci-bucket-$ts"
  local obj="test-obj-$ts.txt"
  local payload="ocisim Object Storage test payload $ts binary:\x00\x01\xfe\xff"
  local tmp_in
  tmp_in="$(mktemp "${TMPDIR:-/tmp}/lmcloud.XXXXXX")"
  local tmp_out
  tmp_out="$(mktemp "${TMPDIR:-/tmp}/lmcloud.XXXXXX")"
  printf "%b" "$payload" > "$tmp_in"

  echo "  Retrieving OCI namespace (GET $url/n/)..."
  local ns
  ns="$(curl -f -s -S "$url/n/" | tr -d '"\r\n')"
  if [ -z "$ns" ]; then
    ns="floci-local"
  fi
  echo "  Namespace: $ns"

  echo "  Creating OCI bucket $bucket (POST $url/n/$ns/b/)..."
  curl -f -s -S -X POST -H 'Content-Type: application/json' \
    -d "{\"name\": \"$bucket\", \"compartmentId\": \"$tenancy\"}" \
    "$url/n/$ns/b/" >/dev/null

  echo "  Putting object $obj (PUT $url/n/$ns/b/$bucket/o/$obj)..."
  curl -f -s -S -X PUT -H 'Content-Type: application/octet-stream' \
    --data-binary "@$tmp_in" \
    "$url/n/$ns/b/$bucket/o/$obj" >/dev/null

  echo "  Getting object $obj (GET $url/n/$ns/b/$bucket/o/$obj)..."
  curl -f -s -S "$url/n/$ns/b/$bucket/o/$obj" -o "$tmp_out"

  if ! cmp -s "$tmp_in" "$tmp_out"; then
    echo "ERROR: Retrieved payload does not match uploaded payload for OCI!" >&2
    rm -f "$tmp_in" "$tmp_out"
    return 1
  fi
  echo "  Verified payload byte equality."

  echo "  Deleting object $obj (DELETE $url/n/$ns/b/$bucket/o/$obj)..."
  curl -f -s -S -X DELETE "$url/n/$ns/b/$bucket/o/$obj" >/dev/null

  echo "  Deleting bucket $bucket (DELETE $url/n/$ns/b/$bucket)..."
  curl -f -s -S -X DELETE "$url/n/$ns/b/$bucket" >/dev/null

  rm -f "$tmp_in" "$tmp_out"
  "$SIM_CTL" stop oci >/dev/null
  current_sim=""
  echo "PASS: ocisim Object Storage round trip"
  return 0
}

targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  targets=("aws" "azure" "gcp" "oci")
fi

for sim in "${targets[@]}"; do
  set +e
  case "$sim" in
    aws|awssim)
      test_aws
      rc=$?
      ;;
    azure|azuresim)
      test_azure
      rc=$?
      ;;
    gcp|gcpsim)
      test_gcp
      rc=$?
      ;;
    oci|ocisim)
      test_oci
      rc=$?
      ;;
    *)
      echo "ERROR: Unknown sim '$sim'" >&2
      rc=2
      ;;
  esac
  set -e

  cleanup

  if [ $rc -eq 0 ]; then
    pass_count=$((pass_count + 1))
    results+=("$sim: PASS")
  else
    fail_count=$((fail_count + 1))
    results+=("$sim: FAIL")
  fi
  echo ""
done

echo "========================================"
echo "Simulator Object Round Trip Test Summary"
echo "========================================"
for r in "${results[@]}"; do
  echo "$r"
done
echo "Passed: $pass_count, Failed: $fail_count"

if [ "$fail_count" -gt 0 ]; then
  exit 1
fi
exit 0
