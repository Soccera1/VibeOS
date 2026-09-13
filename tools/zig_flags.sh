# Included in generated Zig compiler wrappers, never used for GCC/Clang.
filtered=()
for arg in "$@"; do
  if [[ "$profile" == plain ]]; then
    filtered+=("$arg")
    continue
  fi
  if [[ "$profile" == terminal ]]; then
    case "$arg" in
      -Wl,-rpath*|-Wl,--rpath*|-Wl,-soname*|-Wl,--soname*|-Wl,--version-script*|-Wl,--gc-sections) continue ;;
    esac
  else
    case "$arg" in
      -march=x86-64|-fuse-ld=*|--verbose|-static-libgcc|-static-libstdc++|-static-pie|-finline-limit=0|-falign-jumps=1|-falign-labels=1) continue ;;
    esac
  fi
  if [[ "$arg" == -Wl,* ]]; then
    IFS=',' read -r -a parts <<< "${arg#-Wl,}"
    kept=()
    drop_next=0
    for part in "${parts[@]}"; do
      if (( drop_next )); then
        drop_next=0
        continue
      fi
      if [[ "$profile" == terminal ]]; then
        case "$part" in
          -rpath*|--rpath*|-soname*|--soname*|--version-script*|--gc-sections) continue ;;
        esac
      else
        case "$part" in
          -Map) drop_next=1; continue ;;
          -Map=*|--warn-common|--sort-common|--warn-execstack|--warn-rwx-segments|--verbose) continue ;;
        esac
      fi
      kept+=("$part")
    done
    if (( ${#kept[@]} > 0 )); then
      # Do not append in a subshell: that would discard retained linker flags.
      joined="$(IFS=','; printf '%s' "${kept[*]}")"
      filtered+=("-Wl,$joined")
    fi
    continue
  fi
  filtered+=("$arg")
done
