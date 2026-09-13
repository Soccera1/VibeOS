#!/usr/bin/env bash
# Shared static-userspace toolchain selection. Safe to source from build scripts.

musl_init() {
  if [[ -z "${MUSL_CC:-}" ]]; then
    local candidate
    if command -v zig >/dev/null 2>&1; then
      MUSL_CC='zig cc -target x86_64-linux-musl'
    else
      for candidate in x86_64-linux-musl-gcc musl-gcc gcc-musl; do
        if command -v "$candidate" >/dev/null 2>&1; then
          MUSL_CC="$candidate"
          break
        fi
      done
    fi
  fi
  if [[ -z "${MUSL_CC:-}" ]]; then
    echo 'No musl compiler found; install Zig or musl GCC, or set MUSL_CC.' >&2
    return 1
  fi
  if [[ "$MUSL_CC" == 'zig cc'* || "$MUSL_CC" == */zig\ cc* ]]; then
    local cache_root
    cache_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/build"
    export ZIG_GLOBAL_CACHE_DIR="${ZIG_GLOBAL_CACHE_DIR:-$cache_root/zig-global-cache}"
    export ZIG_LOCAL_CACHE_DIR="${ZIG_LOCAL_CACHE_DIR:-$cache_root/zig-local-cache}"
    MUSL_CXX="${MUSL_CXX:-${MUSL_CC/ cc/ c++}}"
    MUSL_AR="${MUSL_AR:-${MUSL_CC%% cc*} ar}"
    MUSL_RANLIB="${MUSL_RANLIB:-${MUSL_CC%% cc*} ranlib}"
  else
    # A musl-gcc wrapper generally has no matching C++ standard library.
    # Only infer C++ for a complete cross toolchain, never host g++.
    if [[ -z "${MUSL_CXX:-}" && "$MUSL_CC" == *-linux-musl-gcc ]]; then
      MUSL_CXX="${MUSL_CC%-gcc}-g++"
    fi
    MUSL_AR="${MUSL_AR:-ar}"
    MUSL_RANLIB="${MUSL_RANLIB:-ranlib}"
  fi
  export MUSL_CC MUSL_CXX MUSL_AR MUSL_RANLIB
}

# Commands can contain whitespace-separated arguments, without shell evaluation.
# Use an executable wrapper for arguments that themselves contain whitespace.
musl_command() {
  local value="$1"
  MUSL_COMMAND=()
  if [[ -x "$value" ]]; then
    MUSL_COMMAND=("$value")
  else
    read -r -a MUSL_COMMAND <<< "$value"
  fi
  if [[ ${#MUSL_COMMAND[@]} == 0 ]] || ! command -v "${MUSL_COMMAND[0]}" >/dev/null 2>&1; then
    echo "Musl tool not found: $value" >&2
    return 1
  fi
}

musl_run() {
  local kind="$1" value
  shift
  musl_init || return
  case "$kind" in
    cc) value="$MUSL_CC" ;;
    c++) value="${MUSL_CXX:-}" ;;
    ar) value="$MUSL_AR" ;;
    ranlib) value="$MUSL_RANLIB" ;;
    *) echo "Unknown musl tool: $kind" >&2; return 1 ;;
  esac
  if [[ -z "$value" ]]; then
    echo 'Set MUSL_CXX to a musl C++ compiler with static C++ libraries (needed by groff).' >&2
    return 1
  fi
  musl_command "$value" || return
  "${MUSL_COMMAND[@]}" "$@"
}

musl_write_wrapper() {
  local output="$1" kind="${2:-cc}" profile="${3:-standard}" value
  musl_init || return
  case "$kind" in
    cc) value="$MUSL_CC" ;;
    c++) value="${MUSL_CXX:-}" ;;
  esac
  if [[ -z "$value" ]]; then
    echo 'Set MUSL_CXX to a musl C++ compiler with static C++ libraries (needed by groff).' >&2
    return 1
  fi
  musl_command "$value" || return
  mkdir -p "$(dirname "$output")"
  {
    printf '#!/usr/bin/env bash\nset -euo pipefail\ncommand=('
    printf '%q ' "${MUSL_COMMAND[@]}"
    printf ')\n'
    if [[ "${MUSL_COMMAND[0]##*/}" == zig ]]; then
      printf 'profile=%q\n' "$profile"
      cat "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/zig_flags.sh"
      printf 'exec "${command[@]}" "${filtered[@]}"\n'
    else
      printf 'exec "${command[@]}" "$@"\n'
    fi
  } > "$output"
  chmod +x "$output"
}

musl_fingerprint() {
  musl_init || return
  printf '%s\n' "$MUSL_CC" "${MUSL_CXX:-}" "$MUSL_AR" "$MUSL_RANLIB"
  cksum "${BASH_SOURCE[0]}" "$(dirname "${BASH_SOURCE[0]}")/zig_flags.sh"
}

# Bash and ncurses keep configured objects in their source trees.
# Invalidate those objects as well as installed libraries when tools change.
musl_prepare_cached_build() {
  local directory="$1" source_dir="$2" fingerprint
  fingerprint="$(musl_fingerprint)" || return
  if [[ ! -f "$directory/.musl-toolchain" ]] || \
     [[ "$(cat "$directory/.musl-toolchain")" != "$fingerprint" ]]; then
    if [[ -f "$source_dir/Makefile" ]]; then
      make -C "$source_dir" distclean >/dev/null
    fi
    rm -rf "$directory"
  fi
  mkdir -p "$directory"
}

musl_check() (
  set -euo pipefail
  musl_init
  local scratch
  scratch="$(mktemp -d)"
  trap 'rm -rf "$scratch"' EXIT
  cat > "$scratch/probe.c" <<'PROBE'
#include <features.h>
#include <stdio.h>
#if defined(__GLIBC__) || !defined(__x86_64__)
#error Static userspace requires an x86_64 musl toolchain, not glibc
#endif
int main(void) { return puts("musl toolchain works") < 0; }
PROBE
  if ! musl_run cc -static -no-pie "$scratch/probe.c" -o "$scratch/probe" > "$scratch/cc.log" 2>&1; then
    cat "$scratch/cc.log" >&2
    exit 1
  fi
  musl_run ar --version >/dev/null
  musl_run ranlib --version >/dev/null
  local binaries=("$scratch/probe") binary
  if [[ "${1:-}" == c++ ]]; then
    cat > "$scratch/probe.cc" <<'PROBE'
#include <features.h>
#include <iostream>
#if defined(__GLIBC__) || !defined(__x86_64__)
#error Static C++ userspace requires an x86_64 musl toolchain, not glibc
#endif
int main() { std::cout << "musl C++ works"; }
PROBE
    if ! musl_run c++ -static -no-pie "$scratch/probe.cc" -o "$scratch/probe-cxx" > "$scratch/cxx.log" 2>&1; then
      cat "$scratch/cxx.log" >&2
      exit 1
    fi
    binaries+=("$scratch/probe-cxx")
  fi
  for binary in "${binaries[@]}"; do
    readelf -h "$binary" > "$scratch/header"
    readelf -l "$binary" > "$scratch/segments"
    if ! grep -q 'Machine:.*Advanced Micro Devices X86-64' "$scratch/header" || \
       ! grep -q 'Type:.*EXEC' "$scratch/header" || grep -q INTERP "$scratch/segments"; then
      echo 'Musl compiler must produce static amd64 ET_EXEC binaries.' >&2
      exit 1
    fi
  done
  echo "Musl toolchain: $MUSL_CC"
)

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  set -euo pipefail
  case "${1:-}" in
    fingerprint) musl_fingerprint ;;
    check) shift; musl_check "$@" ;;
    cc|c++|ar|ranlib) musl_run "$@" ;;
    *) echo "usage: $0 {check [c++]|cc|c++|ar|ranlib} [arguments...]" >&2; exit 1 ;;
  esac
fi
