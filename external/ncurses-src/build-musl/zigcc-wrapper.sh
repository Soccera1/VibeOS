#!/usr/bin/env bash
set -euo pipefail
filtered=()
for arg in "$@"; do
  case "$arg" in
    -Wl,-rpath*|-Wl,--rpath*|-Wl,-soname*|-Wl,--soname*|-Wl,--version-script*|-Wl,--gc-sections)
      continue
      ;;
    -Wl,*)
      payload="${arg#-Wl,}"
      IFS=',' read -r -a parts <<< "$payload"
      kept=()
      for part in "${parts[@]}"; do
        case "$part" in
          -rpath*|--rpath*|-soname*|--soname*|--version-script*|--gc-sections)
            continue
            ;;
        esac
        kept+=("$part")
      done
      if (( ${#kept[@]} > 0 )); then
        (IFS=','; filtered+=("-Wl,${kept[*]}"))
      fi
      continue
      ;;
  esac
  filtered+=("$arg")
done
exec zig cc -target x86_64-linux-musl "${filtered[@]}"
