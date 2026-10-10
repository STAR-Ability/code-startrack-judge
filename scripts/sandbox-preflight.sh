#!/usr/bin/env bash
# Read-only host feature inspection. This does not start go-judge or execute code.
set -euo pipefail

if [[ $# -ne 0 ]]; then
  printf 'Usage: %s\n' "$0" >&2
  exit 2
fi

failures=0
pass() { printf 'PASS %s\n' "$1"; }
fail() { printf 'FAIL %s\n' "$1"; failures=$((failures + 1)); }
info() { printf 'INFO %s\n' "$1"; }

info 'Host eligibility inspection only; no sandbox behavior or readiness is certified.'
platform=$(uname -s)
if [[ "$platform" != Linux ]]; then
  fail "Linux required for real sandbox qualification; detected $platform."
  info 'Use portable mocks locally and a dedicated Linux host for real validation.'
  exit 1
fi
pass "Linux $(uname -r), architecture $(uname -m)"

if [[ -r /sys/fs/cgroup/cgroup.controllers ]]; then
  controllers=$(< /sys/fs/cgroup/cgroup.controllers)
  pass 'Unified cgroup v2 filesystem is visible.'
  for controller in cpu memory pids; do
    if [[ " $controllers " == *" $controller "* ]]; then
      pass "cgroup v2 controller is visible: $controller"
    else
      fail "cgroup v2 controller is unavailable here: $controller"
    fi
  done
else
  fail 'Readable cgroup v2 controller metadata is required by the production profile.'
fi

for namespace in cgroup ipc mnt net pid user uts; do
  if [[ -e "/proc/self/ns/$namespace" ]]; then
    pass "Namespace interface is visible: $namespace"
  else
    fail "Namespace interface is unavailable: $namespace"
  fi
done

if [[ -r /proc/sys/kernel/seccomp/actions_avail ]]; then
  seccomp_actions=$(< /proc/sys/kernel/seccomp/actions_avail)
  if [[ " $seccomp_actions " == *' errno '* && " $seccomp_actions " == *' allow '* ]]; then
    pass 'Kernel advertises seccomp actions; filter enforcement still needs runtime tests.'
  else
    fail 'Required seccomp action support could not be established.'
  fi
else
  fail 'Readable kernel seccomp capability metadata is required for this inspection.'
fi

info 'Not checked: actual cgroup delegation/writes, namespace creation, seccomp enforcement,'
info 'go-judge initialization, mounts, secrets, network denial, limits, or cleanup.'
if (( failures > 0 )); then
  printf 'RESULT INELIGIBLE: %s host feature check(s) failed. Execution must stay disabled.\n' "$failures"
  exit 1
fi
info 'RESULT HOST_FEATURES_PRESENT: proceed to operator review and real isolation tests.'
info 'A zero exit status is never permission to execute submissions or mark judge ready.'
