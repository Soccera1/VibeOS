#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <output-dir> <man-pages-src-dir> <vibeos-overlay-dir>" >&2
  exit 1
fi

OUT_DIR="$1"
SRC_DIR="$2"
OVERLAY_DIR="$3"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "man-pages source directory not found: $SRC_DIR" >&2
  exit 1
fi

if [[ ! -d "$OVERLAY_DIR/man" || ! -f "$OVERLAY_DIR/supported-man2.txt" ]]; then
  echo "VibeOS man-pages overlay is incomplete: $OVERLAY_DIR" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT_DIR")"
OUT_DIR="$(cd "$(dirname "$OUT_DIR")" && pwd)/$(basename "$OUT_DIR")"
ABS_SRC_DIR="$(cd "$SRC_DIR" && pwd)"
ABS_OVERLAY_DIR="$(cd "$OVERLAY_DIR" && pwd)"
STAGE_ROOT="${OUT_DIR}.stage"
DESTDIR_ROOT="$STAGE_ROOT/destdir"
TMP_ROOT="$ABS_SRC_DIR/.tmp"

cleanup() {
  rm -rf "$STAGE_ROOT" "$TMP_ROOT"
}
trap cleanup EXIT

rm -rf "$STAGE_ROOT"
mkdir -p "$DESTDIR_ROOT"

make -R -C "$ABS_SRC_DIR" GNUMAKEFLAGS= install-man prefix=/usr DESTDIR="$DESTDIR_ROOT" >/dev/null

if [[ ! -d "$DESTDIR_ROOT/usr/share/man" ]]; then
  echo "Installed man directory missing: $DESTDIR_ROOT/usr/share/man" >&2
  exit 1
fi

MAN_ROOT="$DESTDIR_ROOT/usr/share/man"
SUPPORTED_MAN2="$ABS_OVERLAY_DIR/supported-man2.txt"

# Section 2 in the upstream project documents the Linux kernel, including
# hundreds of interfaces which VibeOS does not implement.  Keep only the
# pages for calls accepted by the VibeOS x86-64 dispatcher (plus useful libc
# aliases), rather than presenting an inaccurate Linux syscall catalogue.
declare -A keep_man2=()
while IFS= read -r page; do
  page="${page%%#*}"
  page="${page//[[:space:]]/}"
  [[ -n "$page" ]] || continue
  if [[ "$page" == */* || "$page" != *.2 ]]; then
    echo "Invalid entry in $SUPPORTED_MAN2: $page" >&2
    exit 1
  fi
  keep_man2["$page"]=1
done < "$SUPPORTED_MAN2"

for page_path in "$MAN_ROOT/man2"/*; do
  page="$(basename "$page_path")"
  if [[ -z "${keep_man2[$page]+x}" ]]; then
    rm -f "$page_path"
  fi
done

# Install VibeOS-authored overview pages after pruning so they take priority
# over the upstream Linux intro and syscall inventory.
cp -a "$ABS_OVERLAY_DIR/man/." "$MAN_ROOT/"

for page in "${!keep_man2[@]}"; do
  if [[ ! -f "$MAN_ROOT/man2/$page" ]]; then
    echo "Supported manual page was not installed: $page" >&2
    exit 1
  fi
done

# Alias pages consist solely of a .so request and inherit the note from their
# target.  Add a warning to every substantive retained upstream page; Linux
# semantics must not silently be advertised as complete VibeOS semantics.
for page_path in "$MAN_ROOT/man2"/*.2; do
  if grep -q '^\.TH .*"VibeOS' "$page_path" || grep -q '^\.so ' "$page_path"; then
    continue
  fi

  note_file="$STAGE_ROOT/note.$(basename "$page_path")"
  awk '
    BEGIN { inserted = 0 }
    /^\.SH SEE ALSO$/ && !inserted {
      print ".SH VIBEOS NOTES"
      print "This page is derived from the Linux man-pages project."
      print "VibeOS implements a compatibility subset of the interface described here;"
      print "Linux-specific flags and optional behavior may be unavailable."
      print "See"
      print ".BR syscalls (2)"
      print "and"
      print ".BR vibeos (7)"
      print "for the supported surface and system-wide limitations."
      inserted = 1
    }
    { print }
    END {
      if (!inserted) {
        print ".SH VIBEOS NOTES"
        print "This page is derived from the Linux man-pages project."
        print "VibeOS implements only a compatibility subset; see"
        print ".BR syscalls (2)"
        print "and"
        print ".BR vibeos (7)."
      }
    }
  ' "$page_path" > "$note_file"
  mv "$note_file" "$page_path"
done

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
cp -a "$DESTDIR_ROOT/usr/." "$OUT_DIR"/

find "$OUT_DIR" -type d -exec chmod 755 {} +
find "$OUT_DIR" -type f -exec chmod 644 {} +

echo "Staged man-pages tree: $OUT_DIR"
