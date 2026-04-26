#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$ROOT_DIR"

CXX="${CXX:-x86_64-w64-mingw32-g++}"
command -v "$CXX" >/dev/null 2>&1 || {
	echo "[ERR] mingw compiler not found: $CXX" >&2
	exit 1
}

mkdir -p ./bin/windows_amd64

REV="${REV:-manual}"

set -x
"$CXX" -o ./bin/windows_amd64/syz-executor.exe executor/executor.cc \
	-D_WIN32_WINNT=0x0A00 \
	-DWIN32_LEAN_AND_MEAN \
	-O2 \
	-g \
	-pthread \
	-Wall \
	-Wparentheses \
	-Wunused-const-variable \
	-Wframe-larger-than=16384 \
	-Wno-stringop-overflow \
	-Wno-array-bounds \
	-Wno-format-overflow \
	-Wno-unused-but-set-variable \
	-Wno-unused-command-line-argument \
	-std=c++17 \
	-static \
	-static-libgcc \
	-static-libstdc++ \
	-Wl,--disable-dynamicbase \
	-I. \
	-Iexecutor/_include \
	-DSYZ_NYX_WINDOWS_DEMO=1 \
	-DGOOS_windows=1 \
	-DGOARCH_amd64=1 \
	-DHOSTGOOS_linux=1 \
	-DGIT_REVISION="\"$REV\"" \
	-lntdll
