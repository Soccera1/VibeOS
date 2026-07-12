#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <output-root> <glibc-source> <build-root>" >&2
  exit 1
fi

OUT_ROOT="$1"
SOURCE_INPUT="$2"
mkdir -p "$3"
BUILD_ROOT="$(cd "$3" && pwd)"
SOURCE_DIR="$(cd "$SOURCE_INPUT" && pwd)"
OBJECT_DIR="$BUILD_ROOT/obj"
INSTALL_DIR="$BUILD_ROOT/install"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ ! -x "$SOURCE_DIR/configure" ]]; then
  echo "glibc source tree is incomplete: $SOURCE_DIR" >&2
  exit 1
fi

mkdir -p "$OBJECT_DIR"
if [[ ! -f "$OBJECT_DIR/config.make" ]]; then
  (
    cd "$OBJECT_DIR"
    env CFLAGS='-O2 -march=x86-64 -mtune=generic' \
      "$SOURCE_DIR/configure" \
        --prefix=/usr \
        --libdir=/usr/lib64 \
        --libexecdir=/usr/lib64 \
        --enable-kernel=3.2 \
        --disable-werror \
        --disable-nscd \
        --without-selinux
  )
fi

# Some host distributions build libgcc itself for a newer x86-64 ISA even
# when callers use -march=x86-64.  glibc imports __popcountdi2 from that
# archive, so provide the baseline implementation as a normal libc routine.
cat > "$OBJECT_DIR/configparms" <<EOF
ifeq (\$(subdir),stdlib)
sysdep_routines += vibeos-popcountdi2
CFLAGS-vibeos-popcountdi2.c += -mno-popcnt -fno-builtin
\$(objpfx)vibeos-popcountdi2.o \$(objpfx)vibeos-popcountdi2.os \
  \$(objpfx)vibeos-popcountdi2.op \$(objpfx)vibeos-popcountdi2.oS: \
  $REPO_ROOT/userspace/glibc_popcount.c
	\$(compile-command.c)
endif
EOF

# Keep parallelism deliberately modest: glibc is large, while the rest of the
# VibeOS build also uses the shared compiler cache and constrained CI runners.
make -s -C "$OBJECT_DIR" -j"${GLIBC_JOBS:-2}"
rm -rf "$INSTALL_DIR"
make -s -C "$OBJECT_DIR" -j1 install_root="$INSTALL_DIR" install

find_installed_file() {
  local name="$1"
  local candidate
  for candidate in \
    "$INSTALL_DIR/lib64/$name" \
    "$INSTALL_DIR/usr/lib64/$name" \
    "$INSTALL_DIR/lib/$name" \
    "$INSTALL_DIR/usr/lib/$name"; do
    if [[ -e "$candidate" ]]; then
      readlink -f "$candidate"
      return 0
    fi
  done
  return 1
}

validate_elf64_dso() {
  local path="$1"
  readelf -h "$path" | grep -q 'Class:[[:space:]]*ELF64'
  readelf -h "$path" | grep -q 'Machine:[[:space:]]*Advanced Micro Devices X86-64'
  readelf -h "$path" | grep -q 'Type:[[:space:]]*DYN'
}

rm -rf "$OUT_ROOT"
mkdir -p "$OUT_ROOT/root/lib64" "$OUT_ROOT/usr/lib64"

loader="$(find_installed_file ld-linux-x86-64.so.2)" || {
  echo "built x86-64 glibc loader was not installed" >&2
  exit 1
}
validate_elf64_dso "$loader"
cp -L "$loader" "$OUT_ROOT/root/lib64/ld-linux-x86-64.so.2"
chmod 755 "$OUT_ROOT/root/lib64/ld-linux-x86-64.so.2"

required=(libc.so.6 libm.so.6 libpthread.so.0 libdl.so.2 librt.so.1)
optional=(libanl.so.1 libresolv.so.2 libutil.so.1 libnss_compat.so.2 libnss_dns.so.2 libnss_files.so.2)
for soname in "${required[@]}"; do
  source_path="$(find_installed_file "$soname")" || {
    echo "required built glibc runtime object not found: $soname" >&2
    exit 1
  }
  validate_elf64_dso "$source_path"
  cp -L "$source_path" "$OUT_ROOT/usr/lib64/$soname"
  chmod 755 "$OUT_ROOT/usr/lib64/$soname"
done
for soname in "${optional[@]}"; do
  if source_path="$(find_installed_file "$soname")"; then
    validate_elf64_dso "$source_path"
    cp -L "$source_path" "$OUT_ROOT/usr/lib64/$soname"
    chmod 755 "$OUT_ROOT/usr/lib64/$soname"
  fi
done

printf 'Built baseline glibc runtime: %s\n' "$("$loader" --version | head -n 1)"
