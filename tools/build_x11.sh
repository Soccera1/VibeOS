#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <output-usr-tree> <distfiles-dir>" >&2
  exit 1
fi

OUT_ROOT="$1"
DISTFILES="$2"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$REPO_ROOT/build/x11-work"
SRC="$WORK/src"
OBJ="$WORK/obj"
STAGE="$WORK/stage"
JOBS="${X11_JOBS:-$(nproc)}"

archives=(
  xorgproto-2025.1.tar.xz xtrans-1.6.0.tar.xz
  libXau-1.0.12.tar.xz libXdmcp-1.1.5.tar.xz
  xcb-proto-1.17.0.tar.xz libxcb-1.17.0.tar.xz
  libX11-1.8.13.tar.xz libXext-1.3.7.tar.xz
  libICE-1.1.2.tar.xz libSM-1.2.6.tar.xz libXt-1.3.1.tar.xz
  libXmu-1.3.1.tar.xz libXpm-3.5.19.tar.xz libXaw-1.0.16.tar.xz libXinerama-1.1.6.tar.xz
  termcap-2.0.8.tar.bz2 termcap-2.0.8-patches-2.tar.xz
  zlib-1.3.2.tar.xz libmd-1.2.0.tar.xz pixman-0.46.4.tar.xz
  freetype-2.14.3.tar.xz libfontenc-1.1.9.tar.xz libXfont2-2.0.7.tar.xz
  libxkbfile-1.2.0.tar.xz xkbcomp-1.5.0.tar.xz xkeyboard-config-2.47.tar.xz
  font-util-1.4.1.tar.xz font-misc-misc-1.1.3.tar.xz
  xlibre-xserver-25.1.8.tar.gz xinit-1.4.4.tar.xz xterm-406.tgz
)

for archive in "${archives[@]}"; do
  [[ -f "$DISTFILES/$archive" ]] || { echo "missing distfile: $DISTFILES/$archive" >&2; exit 1; }
done

rm -rf "$WORK" "$OUT_ROOT"
mkdir -p "$SRC" "$OBJ" "$STAGE" "$OUT_ROOT"

extract() {
  local archive="$1" name="$2"
  mkdir -p "$SRC/$name"
  tar -xf "$DISTFILES/$archive" -C "$SRC/$name" --strip-components=1
}

extract xorgproto-2025.1.tar.xz xorgproto
extract xtrans-1.6.0.tar.xz xtrans
extract libXau-1.0.12.tar.xz libXau
extract libXdmcp-1.1.5.tar.xz libXdmcp
extract xcb-proto-1.17.0.tar.xz xcb-proto
extract libxcb-1.17.0.tar.xz libxcb
extract libX11-1.8.13.tar.xz libX11
extract libXext-1.3.7.tar.xz libXext
extract libICE-1.1.2.tar.xz libICE
extract libSM-1.2.6.tar.xz libSM
extract libXt-1.3.1.tar.xz libXt
extract libXmu-1.3.1.tar.xz libXmu
extract libXpm-3.5.19.tar.xz libXpm
extract libXaw-1.0.16.tar.xz libXaw
extract libXinerama-1.1.6.tar.xz libXinerama
extract termcap-2.0.8.tar.bz2 termcap
mkdir -p "$SRC/termcap-patches"
tar -xf "$DISTFILES/termcap-2.0.8-patches-2.tar.xz" -C "$SRC/termcap-patches"
for patch_name in \
  004_all_termcap-compat-glibc21.patch \
  012_all_libtermcap-compat-2.0.8-fPIC.patch \
  013_all_libtermcap-compat_bcopy_fix.patch \
  014_all_libtermcap-build-settings.patch \
  015_all_libtermcap-only-shared-lib.patch; do
  (cd "$SRC/termcap" && patch -p1 < "$SRC/termcap-patches/patch/$patch_name")
done
extract zlib-1.3.2.tar.xz zlib
extract libmd-1.2.0.tar.xz libmd
extract pixman-0.46.4.tar.xz pixman
extract freetype-2.14.3.tar.xz freetype
extract libfontenc-1.1.9.tar.xz libfontenc
extract libXfont2-2.0.7.tar.xz libXfont2
extract libxkbfile-1.2.0.tar.xz libxkbfile
extract xkbcomp-1.5.0.tar.xz xkbcomp
extract xkeyboard-config-2.47.tar.xz xkeyboard-config
extract font-util-1.4.1.tar.xz font-util
extract font-misc-misc-1.1.3.tar.xz font-misc-misc
extract xlibre-xserver-25.1.8.tar.gz xlibre
extract xinit-1.4.4.tar.xz xinit
extract xterm-406.tgz xterm
(cd "$SRC/xlibre" && patch -p1 < "$REPO_ROOT/tools/patches/xlibre-vibeos-no-epoll.patch")
(cd "$SRC/xlibre" && patch -p1 < "$REPO_ROOT/tools/patches/xlibre-vibeos-baseline-libgcc.patch")
(cd "$SRC/xlibre" && patch -p1 < "$REPO_ROOT/tools/patches/xlibre-vibeos-precompiled-xkb.patch")
(cd "$SRC/xlibre" && patch -p1 < "$REPO_ROOT/tools/patches/xlibre-vibeos-vt-property.patch")
cp "$REPO_ROOT/userspace/glibc_popcount.c" "$SRC/xlibre/hw/kdrive/fbdev/vibeos-popcount.c"
cp "$REPO_ROOT/userspace/glibc_popcount.c" "$SRC/xlibre/hw/vfb/vibeos-popcount.c"

export PKG_CONFIG_SYSROOT_DIR="$STAGE"
export PKG_CONFIG_LIBDIR="$STAGE/usr/lib64/pkgconfig:$STAGE/usr/share/pkgconfig"
export CFLAGS="-O2 -march=x86-64 -mtune=generic"
export CXXFLAGS="$CFLAGS"
export CPPFLAGS="-I$STAGE/usr/include"
export LDFLAGS="-L$STAGE/usr/lib64 -Wl,-rpath-link,$STAGE/usr/lib64"
export LD_LIBRARY_PATH="$STAGE/usr/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

configure_build() {
  local name="$1"; shift
  mkdir -p "$OBJ/$name"
  (cd "$OBJ/$name" && "$SRC/$name/configure" --prefix=/usr --libdir=/usr/lib64 \
    --disable-static --enable-shared "$@")
  make -C "$OBJ/$name" -j"$JOBS"
  make -C "$OBJ/$name" DESTDIR="$STAGE" install
  find "$STAGE" -type f -name '*.la' -delete
}

meson_build() {
  local name="$1"; shift
  meson setup "$OBJ/$name" "$SRC/$name" --prefix=/usr --libdir=lib64 --buildtype=release "$@"
  meson compile -C "$OBJ/$name" -j "$JOBS"
  DESTDIR="$STAGE" meson install -C "$OBJ/$name"
}

configure_build xorgproto --without-xmlto --without-fop
configure_build xtrans --without-xmlto
configure_build libXau --without-xmlto
configure_build libXdmcp --without-xmlto
configure_build xcb-proto
configure_build libxcb --without-doxygen --disable-devel-docs
configure_build libX11 --without-xmlto --without-fop --disable-specs
configure_build libXext --without-xmlto
configure_build libICE --without-xmlto
configure_build libSM --without-xmlto
configure_build libXt --without-xmlto
configure_build libXmu --without-xmlto
configure_build libXpm --without-xmlto
configure_build libXaw --without-xmlto
configure_build libXinerama --without-xmlto

make -C "$SRC/termcap" libtermcap.so.2.0.8 CC=gcc CFLAGS="$CFLAGS -std=gnu89" LDFLAGS="$LDFLAGS"
install -m 755 "$SRC/termcap/libtermcap.so.2.0.8" "$STAGE/usr/lib64/libtermcap.so.2.0.8"
ln -s libtermcap.so.2.0.8 "$STAGE/usr/lib64/libtermcap.so.2"
ln -s libtermcap.so.2 "$STAGE/usr/lib64/libtermcap.so"
install -m 644 "$SRC/termcap/termcap.h" "$STAGE/usr/include/termcap.h"

(cd "$SRC/zlib" && ./configure --prefix=/usr --libdir=/usr/lib64 --shared)
make -C "$SRC/zlib" -j"$JOBS"
make -C "$SRC/zlib" DESTDIR="$STAGE" install

configure_build libmd
meson_build pixman -Dtests=disabled -Ddemos=disabled -Dgtk=disabled -Dlibpng=disabled
meson_build freetype -Dzlib=enabled -Dpng=disabled -Dbrotli=disabled -Dharfbuzz=disabled -Dbzip2=disabled
configure_build libfontenc --without-xmlto
configure_build libXfont2 --without-xmlto
meson_build libxkbfile
configure_build xkbcomp --without-xmlto
meson_build xkeyboard-config -Dcompat-rules=true
configure_build font-util --without-xmlto
configure_build font-misc-misc --without-xmlto \
  --with-fontrootdir=/usr/share/fonts/X11 --with-fontdir=/usr/share/fonts/X11/misc

# Avoid spawning xkbcomp during server startup. VibeOS supports fork/exec, but
# the server's popen-based compiler path exercises process/stdio semantics that
# are deliberately outside the small graphical runtime. The launcher exposes a
# fixed pc105/us keyboard, so compile that map once while building the image.
cat > "$WORK/vibeos.xkb" <<'EOF'
xkb_keymap {
    xkb_keycodes  { include "evdev+aliases(qwerty)" };
    xkb_types     { include "complete" };
    xkb_compat    { include "complete" };
    xkb_symbols   { include "pc+us+inet(evdev)" };
    xkb_geometry  { include "pc(pc105)" };
};
EOF
"$STAGE/usr/bin/xkbcomp" -w 1 -R"$STAGE/usr/share/xkeyboard-config-2" -xkm \
  "$WORK/vibeos.xkb" "$STAGE/usr/share/xkeyboard-config-2/vibeos.xkm"

meson_build xlibre \
  -Dxorg=false -Dxfbdev=true -Dxvfb=true -Dxephyr=false -Dxnest=false \
  -Dglamor=false -Dglx=false -Dglx_dri=false \
  -Ddri1=false -Ddri2=false -Ddri3=false -Ddrm=false \
  -Dxdmcp=false -Dxdm-auth-1=false -Dipv6=false -Dinput_thread=false \
  -Dudev=false -Dudev_kms=false -Dseatd_libseat=false \
  -Dsystemd_logind=false -Dsystemd_notify=false -Dhal=false \
  -Dmitshm=false -Dxselinux=false -Dlinux_apm=false -Dlinux_acpi=false \
  -Dtests=false -Ddocs=false -Dsha1=libmd \
  -Dxkb_dir=/usr/share/X11/xkb -Dxkb_bin_dir=/usr/bin \
  -Ddefault_font_path=/usr/share/fonts/X11/misc

configure_build xinit --without-xauth --without-twm --without-xclock
configure_build xterm \
  --disable-setuid --disable-setgid --disable-session-mgt \
  --disable-freetype --disable-luit --disable-tcap-fkeys --disable-tcap-query \
  --disable-desktop --disable-sixel-graphics --disable-print-graphics \
  --with-terminal-type=xterm-256color --with-own-terminfo=/usr/share/terminfo \
  --with-app-defaults=/usr/share/X11/app-defaults

mkdir -p "$STAGE/usr/bin" "$STAGE/usr/etc/X11/xinit" "$STAGE/usr/lib64"
# Avoid an intermediate symlink: VibeOS resolves final symlinks but does not
# yet walk symlinks embedded in longer pathnames such as xkb/rules/evdev.
unlink "$STAGE/usr/share/X11/xkb"
mv "$STAGE/usr/share/xkeyboard-config-2" "$STAGE/usr/share/X11/xkb"
gcc $CFLAGS -o "$STAGE/usr/bin/xhello" "$REPO_ROOT/userspace/xhello.c" \
  -I"$STAGE/usr/include" -L"$STAGE/usr/lib64" -Wl,-rpath-link,"$STAGE/usr/lib64" -lX11

cat > "$STAGE/usr/bin/startx-vibeos" <<'EOF'
#!/bin/sh
export DISPLAY=:0
exec /usr/bin/xinit /usr/bin/xterm -geometry 210x59+0+0 -ms red \
  -xrm 'XTerm*pointerColorBackground: white' -xrm 'XTerm*pointerShape: left_ptr' \
  -xrm 'XTerm*pointerMode: 0' -- \
  /usr/bin/Xfbdev :0 -nolock -nolisten tcp \
  -mouse evdev,,device=/dev/input/event0 \
  -keybd evdev,,device=/dev/input/event1,xkbmodel=pc105,xkblayout=us
EOF
chmod 755 "$STAGE/usr/bin/startx-vibeos"

rm -rf "$STAGE/usr/include" "$STAGE/usr/lib/python"* \
  "$STAGE/usr/share/aclocal" "$STAGE/usr/share/doc" "$STAGE/usr/share/man" \
  "$STAGE/usr/share/pkgconfig" "$STAGE/usr/share/xcb" "$STAGE/usr/share/locale" \
  "$STAGE/usr/lib64/pkgconfig"
rm -f "$STAGE/usr/bin/bdftruncate" "$STAGE/usr/bin/ucs2any" "$STAGE/usr/bin/startx" "$STAGE/usr/bin/resize"
find "$STAGE/usr/lib64" -type f \( -name '*.a' -o -name '*.la' \) -delete

cp -a "$STAGE/usr/." "$OUT_ROOT/"
find "$OUT_ROOT" -type f -name '*.la' -delete

for binary in "$OUT_ROOT/bin/Xfbdev" "$OUT_ROOT/bin/Xvfb" "$OUT_ROOT/bin/xinit" "$OUT_ROOT/bin/xhello" "$OUT_ROOT/bin/xterm"; do
  [[ -x "$binary" ]] || { echo "expected X11 binary missing: $binary" >&2; exit 1; }
  readelf -h "$binary" | grep -q 'Machine:.*Advanced Micro Devices X86-64'
done

echo "Built XLibre framebuffer runtime: $OUT_ROOT"
