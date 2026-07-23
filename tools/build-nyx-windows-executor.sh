#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$ROOT_DIR"

case "${CXX:-}" in
	""|g++|c++)
		CXX="x86_64-w64-mingw32-g++"
		;;
esac
command -v "$CXX" >/dev/null 2>&1 || {
	echo "[ERR] mingw compiler not found: $CXX" >&2
	exit 1
}

mkdir -p ./bin/windows_amd64

if [[ -z "${REV:-}" ]]; then
	REV="$(git rev-parse HEAD)"
	if ! git diff --quiet --ignore-submodules -- || ! git diff --cached --quiet --ignore-submodules --; then
		REV+="+"
	fi
fi
NYX_WINDOWS_DEMO="${NYX_WINDOWS_DEMO:-0}"
NYX_WINDOWS_SPARSE_TABLE="${NYX_WINDOWS_SPARSE_TABLE:-1}"
NYX_USE_GENERIC_PATH="${NYX_USE_GENERIC_PATH:-1}"
NYX_WINDOWS_SUBMIT_CR3="${NYX_WINDOWS_SUBMIT_CR3:-1}"
NYX_TRACE_COV="${NYX_TRACE_COV:-0}"

case "$NYX_WINDOWS_DEMO" in
	0|1)
		;;
	*)
		echo "[ERR] NYX_WINDOWS_DEMO must be 0 or 1, got: $NYX_WINDOWS_DEMO" >&2
		exit 1
		;;
esac

case "$NYX_WINDOWS_SPARSE_TABLE" in
	0|1)
		;;
	*)
		echo "[ERR] NYX_WINDOWS_SPARSE_TABLE must be 0 or 1, got: $NYX_WINDOWS_SPARSE_TABLE" >&2
		exit 1
		;;
esac

case "$NYX_USE_GENERIC_PATH" in
	0|1)
		;;
	*)
		echo "[ERR] NYX_USE_GENERIC_PATH must be 0 or 1, got: $NYX_USE_GENERIC_PATH" >&2
		exit 1
		;;
esac

case "$NYX_WINDOWS_SUBMIT_CR3" in
	0|1)
		;;
	*)
		echo "[ERR] NYX_WINDOWS_SUBMIT_CR3 must be 0 or 1, got: $NYX_WINDOWS_SUBMIT_CR3" >&2
		exit 1
		;;
esac

case "$NYX_TRACE_COV" in
	0|1)
		;;
	*)
		echo "[ERR] NYX_TRACE_COV must be 0 or 1, got: $NYX_TRACE_COV" >&2
		exit 1
		;;
esac


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
	-DSYZ_NYX_WINDOWS_DEMO="$NYX_WINDOWS_DEMO" \
	-DSYZ_NYX_WINDOWS_SPARSE_TABLE="$NYX_WINDOWS_SPARSE_TABLE" \
	-DSYZ_NYX_USE_GENERIC_PATH="$NYX_USE_GENERIC_PATH" \
	-DSYZ_NYX_WINDOWS_SUBMIT_CR3="$NYX_WINDOWS_SUBMIT_CR3" \
	-DSYZ_NYX_TRACE_COV="$NYX_TRACE_COV" \
	-DSYZ_NET_INJECTION=1 \
	-DGOOS_windows=1 \
	-DGOARCH_amd64=1 \
	-DHOSTGOOS_linux=1 \
	-DGIT_REVISION="\"$REV\"" \
	-lntdll \
	-lws2_32 \
	-lmswsock \
	-liphlpapi \
	-ladvapi32 \
	-lole32 \
	-loleaut32 \
	-luuid
