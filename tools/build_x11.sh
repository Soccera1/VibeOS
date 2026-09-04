#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <output-usr-tree> <external-source-dir>" >&2
  exit 1
fi

OUT_ROOT="$1"
EXTERNAL="$2"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${X11_WORK_DIR:-$REPO_ROOT/build/x11-work}"
SRC="$WORK/src"
OBJ="$WORK/obj"
STAGE="$WORK/stage"
JOBS="${X11_JOBS:-$(nproc)}"

sources=(
  xorgproto xtrans libXau libXdmcp xcb-proto libxcb libX11 libXext
  libXrender libICE libSM libXt libXmu libXpm libXaw libXinerama termcap
  zlib libmd pixman freetype expat fontconfig libXft libfontenc libXfont2
  libxkbfile xkbcomp xkeyboard-config font-util font-misc-misc xlibre xinit
  xterm st
)

for source in "${sources[@]}"; do
  [[ -d "$EXTERNAL/$source-src" ]] || {
    echo "missing external source tree: $EXTERNAL/$source-src" >&2
    exit 1
  }
done

rm -rf "$WORK" "$OUT_ROOT"
mkdir -p "$SRC" "$OBJ" "$STAGE" "$OUT_ROOT"

copy_source() {
  local name="$1"
  mkdir -p "$SRC/$name"
  cp -a "$EXTERNAL/$name-src/." "$SRC/$name/"
}

for source in "${sources[@]}"; do
  copy_source "$source"
done

# Git does not preserve the release archive's timestamp ordering.  Keep xinit's
# generated Autotools files newer than their inputs so make does not require the
# exact Automake version that produced the checked-in files.
touch "$SRC/xinit/aclocal.m4" "$SRC/xinit/configure" "$SRC/xinit/config.h.in"
find "$SRC/xinit" -name Makefile.in -exec touch {} +

for patch_name in \
  004_all_termcap-compat-glibc21.patch \
  012_all_libtermcap-compat-2.0.8-fPIC.patch \
  013_all_libtermcap-compat_bcopy_fix.patch \
  014_all_libtermcap-build-settings.patch \
  015_all_libtermcap-only-shared-lib.patch; do
  (cd "$SRC/termcap" && patch -p1 < "$REPO_ROOT/tools/patches/termcap/$patch_name")
done
(cd "$SRC/xlibre" && patch -p1 < "$REPO_ROOT/tools/patches/xlibre-vibeos-no-epoll.patch")
(cd "$SRC/xlibre" && patch -p1 < "$REPO_ROOT/tools/patches/xlibre-vibeos-baseline-libgcc.patch")
(cd "$SRC/xlibre" && patch -p1 < "$REPO_ROOT/tools/patches/xlibre-vibeos-precompiled-xkb.patch")
(cd "$SRC/xlibre" && patch -p1 < "$REPO_ROOT/tools/patches/xlibre-vibeos-vt-property.patch")
(cd "$SRC/st" && patch -p1 < "$REPO_ROOT/tools/patches/st/st-vibeos-default-font.patch")
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
configure_build libXrender --without-xmlto
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
configure_build expat --without-xmlwf --without-examples --without-tests --without-docbook
meson_build fontconfig \
  -Ddoc=disabled -Dnls=disabled -Dtests=disabled -Dtools=enabled \
  -Dcache-build=disabled -Diconv=disabled -Dxml-backend=expat -Dfontations=disabled \
  -Ddefault-hinting=noinstall -Ddefault-sub-pixel-rendering=noinstall \
  -Dbitmap-conf=noinstall -Ddefault-fonts-dirs=/usr/share/fonts/X11/misc \
  -Dadditional-fonts-dirs=no -Dcache-dir=/tmp/fontconfig-cache \
  -Dbaseconfig-dir=/usr/etc/fonts -Dconfig-dir=/usr/etc/fonts/conf.d
configure_build libXft --without-xmlto
configure_build libfontenc --without-xmlto
configure_build libXfont2 --without-xmlto
meson_build libxkbfile
configure_build xkbcomp --without-xmlto
meson_build xkeyboard-config -Dcompat-rules=true
configure_build font-util --without-xmlto
configure_build font-misc-misc --without-xmlto \
  --with-fontrootdir=/usr/share/fonts/X11 --with-fontdir=/usr/share/fonts/X11/misc

# Fontconfig normally installs an active conf.d symlink farm. VibeOS resolves
# final symlinks but not symlinks embedded in longer paths, so use one regular,
# self-contained configuration file for the bundled bitmap fonts.
rm -rf "$STAGE/usr/etc/fonts/conf.d" "$STAGE/usr/share/fontconfig"
mkdir -p "$STAGE/usr/etc/fonts"
cat > "$STAGE/usr/etc/fonts/fonts.conf" <<'EOF'
<?xml version="1.0"?>
<fontconfig>
  <dir>/usr/share/fonts/X11/misc</dir>
  <cachedir>/tmp/fontconfig-cache</cachedir>
  <match target="font">
    <edit name="antialias" mode="assign"><bool>false</bool></edit>
    <edit name="hinting" mode="assign"><bool>false</bool></edit>
  </match>
  <config>
    <rescan><int>0</int></rescan>
  </config>
</fontconfig>
EOF

font_match="$(
  FONTCONFIG_SYSROOT="$STAGE" FONTCONFIG_PATH=/usr/etc/fonts FONTCONFIG_FILE=fonts.conf \
    "$STAGE/usr/bin/fc-match" --format '%{family}|%{style}|%{pixelsize}|%{antialias}|%{file}\n' \
    'Fixed:style=SemiCondensed:pixelsize=13:antialias=false:hinting=false'
)"
[[ "$font_match" == "Fixed|SemiCondensed|13|False|"* ]] || {
  echo "fontconfig did not resolve the bundled 6x13 fixed font: $font_match" >&2
  exit 1
}
[[ "$font_match" == *"/usr/share/fonts/X11/misc/"* ]] || {
  echo "fontconfig selected a font outside the bundled X11 directory: $font_match" >&2
  exit 1
}

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

make -C "$SRC/st" -j"$JOBS" \
  CC=gcc PREFIX=/usr X11INC="$STAGE/usr/include" X11LIB="$STAGE/usr/lib64" \
  PKG_CONFIG=pkg-config CPPFLAGS="$CPPFLAGS" CFLAGS="$CFLAGS" LDFLAGS="$LDFLAGS"
install -m 755 "$SRC/st/st" "$STAGE/usr/bin/st"
mkdir -p "$STAGE/usr/share/terminfo"
tic -x -o "$STAGE/usr/share/terminfo" "$SRC/st/st.info"
find "$STAGE/usr/share/terminfo" -type f -name st-256color -print -quit | grep -q . || {
  echo "st-256color terminfo entry was not generated" >&2
  exit 1
}

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
export FONTCONFIG_PATH=/usr/etc/fonts
export FONTCONFIG_FILE=fonts.conf
exec /usr/bin/xinit /usr/bin/st -g 210x58+0+0 -- \
  /usr/bin/Xfbdev :0 -nolock -nolisten tcp \
  -mouse evdev,,device=/dev/input/event0 \
  -keybd evdev,,device=/dev/input/event1,xkbmodel=pc105,xkblayout=us
EOF
chmod 755 "$STAGE/usr/bin/startx-vibeos"

cat > "$STAGE/usr/bin/startx-vibeos-xterm" <<'EOF'
#!/bin/sh
export DISPLAY=:0
exec /usr/bin/xinit /usr/bin/xterm -geometry 210x59+0+0 -ms red \
  -xrm 'XTerm*pointerColorBackground: white' -xrm 'XTerm*pointerShape: left_ptr' \
  -xrm 'XTerm*pointerMode: 0' -- \
  /usr/bin/Xfbdev :0 -nolock -nolisten tcp \
  -mouse evdev,,device=/dev/input/event0 \
  -keybd evdev,,device=/dev/input/event1,xkbmodel=pc105,xkblayout=us
EOF
chmod 755 "$STAGE/usr/bin/startx-vibeos-xterm"

rm -rf "$STAGE/usr/include" "$STAGE/usr/lib/python"* \
  "$STAGE/usr/share/aclocal" "$STAGE/usr/share/doc" "$STAGE/usr/share/man" \
  "$STAGE/usr/share/pkgconfig" "$STAGE/usr/share/xcb" "$STAGE/usr/share/locale" \
  "$STAGE/usr/share/xml/fontconfig" "$STAGE/usr/lib64/pkgconfig"
rm -f "$STAGE/usr/bin/bdftruncate" "$STAGE/usr/bin/ucs2any" "$STAGE/usr/bin/startx" \
  "$STAGE/usr/bin/resize" "$STAGE/usr/bin"/fc-*
find "$STAGE/usr/lib64" -type f \( -name '*.a' -o -name '*.la' \) -delete

cp -a "$STAGE/usr/." "$OUT_ROOT/"
find "$OUT_ROOT" -type f -name '*.la' -delete

for binary in \
  "$OUT_ROOT/bin/Xfbdev" "$OUT_ROOT/bin/Xvfb" "$OUT_ROOT/bin/xinit" \
  "$OUT_ROOT/bin/xhello" "$OUT_ROOT/bin/xterm" "$OUT_ROOT/bin/st"; do
  [[ -x "$binary" ]] || { echo "expected X11 binary missing: $binary" >&2; exit 1; }
  readelf -h "$binary" | grep -q 'Machine:.*Advanced Micro Devices X86-64'
done

for launcher in "$OUT_ROOT/bin/startx-vibeos" "$OUT_ROOT/bin/startx-vibeos-xterm"; do
  [[ -x "$launcher" ]] || { echo "expected X11 launcher missing: $launcher" >&2; exit 1; }
done

for library in libexpat.so.1 libfontconfig.so.1 libXrender.so.1 libXft.so.2; do
  [[ -e "$OUT_ROOT/lib64/$library" ]] || {
    echo "expected st runtime library missing: $OUT_ROOT/lib64/$library" >&2
    exit 1
  }
done

[[ -f "$OUT_ROOT/etc/fonts/fonts.conf" && ! -L "$OUT_ROOT/etc/fonts/fonts.conf" ]] || {
  echo "fontconfig configuration must be a regular file" >&2
  exit 1
}

readelf -l "$OUT_ROOT/bin/st" | grep -q 'Requesting program interpreter: /lib64/ld-linux-x86-64.so.2'
if readelf -d "$OUT_ROOT/bin/st" | grep -Eq '\((RPATH|RUNPATH)\)'; then
  echo "st contains an unexpected RPATH or RUNPATH" >&2
  exit 1
fi

runtime_dirs=(
  "$OUT_ROOT/lib64"
  "$REPO_ROOT/build/userspace/glibc-runtime/usr/lib64"
  "$REPO_ROOT/build/userspace/glibc-runtime/root/lib64"
)
check_needed_closure() {
  local elf="$1" line needed dir found
  while IFS= read -r line; do
    if [[ "$line" =~ Shared\ library:\ \[([^]]+)\] ]]; then
      needed="${BASH_REMATCH[1]}"
      found=0
      for dir in "${runtime_dirs[@]}"; do
        if [[ -e "$dir/$needed" ]]; then
          found=1
          break
        fi
      done
      if [[ "$found" -ne 1 ]]; then
        echo "missing runtime dependency for $elf: $needed" >&2
        exit 1
      fi
    fi
  done < <(readelf -d "$elf")
}

check_needed_closure "$OUT_ROOT/bin/st"
check_needed_closure "$OUT_ROOT/lib64/libXft.so.2"
check_needed_closure "$OUT_ROOT/lib64/libfontconfig.so.1"
check_needed_closure "$OUT_ROOT/lib64/libXrender.so.1"

echo "Built XLibre framebuffer runtime with st: $OUT_ROOT"
