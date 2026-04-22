#!/usr/bin/env bash

strip_binaries_enabled() {
  [[ "${STRIP_BINARIES:-1}" != "0" ]]
}

resolve_strip_tool() {
  if [[ -n "${STRIP:-}" ]]; then
    printf '%s\n' "$STRIP"
    return 0
  fi

  if command -v llvm-strip >/dev/null 2>&1; then
    printf '%s\n' "llvm-strip"
    return 0
  fi

  if command -v strip >/dev/null 2>&1; then
    printf '%s\n' "strip"
    return 0
  fi

  echo "No strip tool found (set STRIP or install llvm-strip/strip)" >&2
  return 1
}

is_elf_binary() {
  local path="$1"
  [[ -f "$path" ]] || return 1
  readelf -h "$path" >/dev/null 2>&1
}

maybe_strip_binary() {
  local path="$1"
  local strip_tool

  strip_binaries_enabled || return 0
  is_elf_binary "$path" || return 0

  strip_tool="$(resolve_strip_tool)"
  "$strip_tool" "$path"
}

maybe_strip_tree_binaries() {
  local root="$1"
  local path

  strip_binaries_enabled || return 0
  [[ -d "$root" ]] || return 0

  while IFS= read -r -d '' path; do
    maybe_strip_binary "$path"
  done < <(find "$root" -type f \( -path '*/bin/*' -o -path '*/sbin/*' -o -perm /111 \) -print0)
}
