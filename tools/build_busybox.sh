#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <output-busybox> <busybox-src-dir> <prebuilt-busybox> <rootfs-busybox>" >&2
  exit 1
fi

OUT_BIN="$1"
SRC_DIR="$2"
PREBUILT_BIN="$3"
ROOTFS_BIN="$4"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

mkdir -p "$(dirname "$OUT_BIN")"

have_source_tarball() {
  find "$REPO_ROOT" -maxdepth 1 -type f \
    \( -name 'busybox-*.tar' -o -name 'busybox-*.tar.gz' -o -name 'busybox-*.tgz' -o -name 'busybox-*.tar.bz2' -o -name 'busybox-*.tar.xz' \) \
    | grep -q .
}

set_cfg() {
  local cfg_file="$1"
  local key="$2"
  local val="$3"
  if grep -q "^${key}=" "$cfg_file"; then
    sed -i "s|^${key}=.*|${key}=${val}|" "$cfg_file"
    return
  fi
  if grep -q "^# ${key} is not set$" "$cfg_file"; then
    sed -i "s|^# ${key} is not set$|${key}=${val}|" "$cfg_file"
    return
  fi
  echo "${key}=${val}" >> "$cfg_file"
}

unset_cfg() {
  local cfg_file="$1"
  local key="$2"
  if grep -q "^${key}=" "$cfg_file"; then
    sed -i "s|^${key}=.*|# ${key} is not set|" "$cfg_file"
    return
  fi
  if ! grep -q "^# ${key} is not set$" "$cfg_file"; then
    echo "# ${key} is not set" >> "$cfg_file"
  fi
}

validate_busybox_binary() {
  local bin="$1"
  if [[ ! -x "$bin" ]]; then
    echo "BusyBox binary is not executable: $bin" >&2
    return 1
  fi

  if ! readelf -h "$bin" | grep -q "Machine:[[:space:]]*Advanced Micro Devices X86-64"; then
    echo "BusyBox is not amd64: $bin" >&2
    return 1
  fi

  if ! readelf -h "$bin" | grep -q "Type:[[:space:]]*EXEC"; then
    echo "BusyBox must be non-PIE ET_EXEC for current loader: $bin" >&2
    return 1
  fi

  if readelf -l "$bin" | grep -q "Requesting program interpreter"; then
    echo "BusyBox must be static (no PT_INTERP): $bin" >&2
    return 1
  fi
}

copy_candidate() {
  local src="$1"
  validate_busybox_binary "$src"
  cp "$src" "$OUT_BIN"
  chmod +x "$OUT_BIN"
  echo "Using prebuilt upstream BusyBox: $src"
}

extract_source_from_tarball() {
  local archive
  archive="$(find "$REPO_ROOT" -maxdepth 1 -type f \( -name 'busybox-*.tar' -o -name 'busybox-*.tar.gz' -o -name 'busybox-*.tgz' -o -name 'busybox-*.tar.bz2' -o -name 'busybox-*.tar.xz' \) | sort | head -n 1 || true)"
  if [[ -z "$archive" ]]; then
    return 1
  fi

  mkdir -p "$(dirname "$SRC_DIR")"

  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' RETURN
  tar -xf "$archive" -C "$tmpdir"

  local extracted
  extracted="$(find "$tmpdir" -mindepth 1 -maxdepth 1 -type d | head -n 1 || true)"
  if [[ -z "$extracted" ]]; then
    echo "Failed to find BusyBox source directory inside $archive" >&2
    return 1
  fi

  rm -rf "$SRC_DIR"
  mv "$extracted" "$SRC_DIR"
  echo "Extracted BusyBox source: $archive -> $SRC_DIR"
}

prepare_zig_wrapper() {
  local abs_src
  abs_src="$(cd "$SRC_DIR" && pwd)"
  local wrapper="$abs_src/.zigcc-musl-wrapper.sh"
  cat > "$wrapper" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

filtered=()
for arg in "$@"; do
  case "$arg" in
    -march=x86-64|-fuse-ld=*|--verbose|-static-libgcc|-finline-limit=0|-falign-jumps=1|-falign-labels=1)
      continue
      ;;
  esac

  if [[ "$arg" == -Wl,* ]]; then
    payload="${arg#-Wl,}"
    IFS=',' read -r -a parts <<< "$payload"
    kept=()
    drop_next=0
    for part in "${parts[@]}"; do
      if (( drop_next )); then
        drop_next=0
        continue
      fi
      case "$part" in
        -Map)
          drop_next=1
          continue
          ;;
        -Map=*|--warn-common|--sort-common|--warn-execstack|--warn-rwx-segments|--verbose)
          continue
          ;;
      esac
      kept+=("$part")
    done
    if (( ${#kept[@]} > 0 )); then
      (IFS=','; filtered+=("-Wl,${kept[*]}"))
    fi
    continue
  fi

  filtered+=("$arg")
done

exec zig cc -target x86_64-linux-musl "${filtered[@]}"
EOF
  chmod +x "$wrapper"
  echo "$wrapper"
}

build_from_source() {
  if [[ ! -d "$SRC_DIR" ]]; then
    extract_source_from_tarball
  fi

  if [[ ! -d "$SRC_DIR" ]]; then
    cat >&2 <<EOF
No upstream BusyBox source or binary found.
Provide one of:
  - $ROOTFS_BIN
  - $PREBUILT_BIN
  - $SRC_DIR
  - busybox-*.tar.* in repository root
EOF
    exit 1
  fi

  make -C "$SRC_DIR" distclean >/dev/null
  make -C "$SRC_DIR" defconfig >/dev/null

  local cfg="$SRC_DIR/.config"
  set_cfg "$cfg" "CONFIG_STATIC" "y"
  unset_cfg "$cfg" "CONFIG_PIE"
  set_cfg "$cfg" "CONFIG_FEATURE_SH_STANDALONE" "y"
  set_cfg "$cfg" "CONFIG_FEATURE_PREFER_APPLETS" "y"
  set_cfg "$cfg" "CONFIG_FEATURE_SH_NOFORK" "y"
  set_cfg "$cfg" "CONFIG_ASH" "y"
  set_cfg "$cfg" "CONFIG_SH_IS_ASH" "y"
  unset_cfg "$cfg" "CONFIG_HUSH"
  unset_cfg "$cfg" "CONFIG_ASH_JOB_CONTROL"
  unset_cfg "$cfg" "CONFIG_TC"
  unset_cfg "$cfg" "CONFIG_FEATURE_UTMP"
  unset_cfg "$cfg" "CONFIG_FEATURE_WTMP"
  unset_cfg "$cfg" "CONFIG_PAM"
  # Disable full-screen applets until terminal alt-screen/cursor control is complete.
  unset_cfg "$cfg" "CONFIG_VI"
  unset_cfg "$cfg" "CONFIG_LESS"
  unset_cfg "$cfg" "CONFIG_MORE"
  unset_cfg "$cfg" "CONFIG_TOP"

  make -C "$SRC_DIR" oldconfig >/dev/null

  local cc_cmd
  local extra_cflags="-mno-avx -mno-avx2 -mno-avx512f -fno-tree-vectorize"
  local abs_src
  local jobs
  abs_src="$(cd "$SRC_DIR" && pwd)"
  jobs="$(nproc)"

  if command -v zig >/dev/null 2>&1; then
    export ZIG_GLOBAL_CACHE_DIR="$abs_src/.zig-global-cache"
    export ZIG_LOCAL_CACHE_DIR="$abs_src/.zig-local-cache"
    rm -rf "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"
    mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR"
    cc_cmd="$(prepare_zig_wrapper)"
    jobs="${BUSYBOX_ZIG_JOBS:-1}"
    echo "Building BusyBox from source with zig cc (x86_64-linux-musl)"
  else
    cc_cmd="${BUSYBOX_CC:-cc}"
    echo "zig not found; building BusyBox with CC=$cc_cmd"
  fi

  make -C "$SRC_DIR" -j"$jobs" \
    CC="$cc_cmd" \
    HOSTCC="${HOSTCC:-cc}" \
    EXTRA_CFLAGS="$extra_cflags" \
    busybox >/dev/null

  validate_busybox_binary "$SRC_DIR/busybox"
  cp "$SRC_DIR/busybox" "$OUT_BIN"
  chmod +x "$OUT_BIN"
  echo "Built upstream BusyBox from source: $SRC_DIR"
}

if [[ -d "$SRC_DIR" ]] || have_source_tarball; then
  build_from_source
  exit 0
fi

if [[ -x "$ROOTFS_BIN" ]]; then
  copy_candidate "$ROOTFS_BIN"
  exit 0
fi

if [[ -x "$PREBUILT_BIN" ]]; then
  copy_candidate "$PREBUILT_BIN"
  exit 0
fi

cat >&2 <<EOF
No upstream BusyBox source or binary found.
Provide one of:
  - $SRC_DIR
  - busybox-*.tar.* in repository root
  - $ROOTFS_BIN
  - $PREBUILT_BIN
EOF
exit 1
