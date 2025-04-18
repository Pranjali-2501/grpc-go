#!/bin/bash
#
#  Copyright 2019 gRPC authors.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

set -e +x

export TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

clean () {
  for i in {1..10}; do
    jobs -p | xargs -n1 pkill -P
    # A simple "wait" just hangs sometimes.  Running `jobs` seems to help.
    sleep 1
    if jobs | read; then
      return
    fi
  done
  echo "$(tput setaf 1) clean failed to kill tests $(tput sgr 0)"
  jobs
  pstree
  exit 1
}

fail () {
    echo "$(tput setaf 1) $(date): $1 $(tput sgr 0)"
    clean
    exit 1
}

pass () {
    echo "$(tput setaf 2) $(date): $1 $(tput sgr 0)"
}

withTimeout () {
    timer=$1
    shift

    # Run command in the background.
    cmd=$(printf '%q ' "$@")
    eval "$cmd" &
    wpid=$!
    # Kill after $timer seconds.
    sleep $timer && kill $wpid &
    kpid=$!
    # Wait for the background thread.
    wait $wpid
    res=$?
    # Kill the killer pid in case it's still running.
    kill $kpid || true
    wait $kpid || true
    return $res
}

# Don't run some tests that need a special environment:
#  "google_default_credentials"
#  "compute_engine_channel_credentials"
#  "compute_engine_creds"
#  "service_account_creds"
#  "jwt_token_creds"
#  "oauth2_auth_token"
#  "per_rpc_creds"
#  "pick_first_unary"

CASES=(
  "empty_unary"
  "large_unary"
  "client_streaming"
  "server_streaming"
  "ping_pong"
  "empty_stream"
  "timeout_on_sleeping_server"
  "cancel_after_begin"
  "cancel_after_first_response"
  "status_code_and_message"
  "special_status_message"
  "custom_metadata"
  "unimplemented_method"
  "unimplemented_service"
  "orca_per_rpc"
  "orca_oob"
  "rpc_soak"
  "channel_soak"
)

# Build server
echo "$(tput setaf 4) $(date): building server $(tput sgr 0)"
if ! go build -o /dev/null ./interop/server; then
  fail "failed to build server"
else
  pass "successfully built server"
fi

# Build client
echo "$(tput setaf 4) $(date): building client $(tput sgr 0)"
if ! go build -o /dev/null ./interop/client; then
  fail "failed to build client"
else
  pass "successfully built client"
fi

# Start server
SERVER_LOG="$(mktemp)"
GRPC_GO_LOG_SEVERITY_LEVEL=info go run ./interop/server --use_tls &> $SERVER_LOG  &

for case in ${CASES[@]}; do
    echo "$(tput setaf 4) $(date): testing: ${case} $(tput sgr 0)"

    CLIENT_LOG="$(mktemp)"
    if ! GRPC_GO_LOG_SEVERITY_LEVEL=info withTimeout 20 go run ./interop/client \
         --use_tls \
         --server_host_override=foo.test.google.fr \
         --use_test_ca --test_case="${case}" \
         --service_config_json='{ "loadBalancingConfig": [{ "test_backend_metrics_load_balancer": {} }]}' \
       &> $CLIENT_LOG; then
        fail "FAIL: test case ${case}
        got server log:
        $(cat $SERVER_LOG)
        got client log:
        $(cat $CLIENT_LOG)
        "
    else
      pass "PASS: test case ${case}"
    fi
done

clean
