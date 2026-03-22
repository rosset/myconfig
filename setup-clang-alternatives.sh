#!/usr/bin/env bash
# =============================================================================
# setup-clang-alternatives.sh
#
# this script was validated against fedora rawhide (Fedora 45 atm)
# may work on other distros with update-alternatives, but not tested
#
# Registers clang/llvm versions 20, 21, and 22 with update-alternatives so
# you can switch the entire toolchain with a single command.
#
# Usage:
#   sudo bash setup-clang-alternatives.sh          # register all versions
#   sudo bash setup-clang-alternatives.sh --remove # unregister all versions
#
# After running, switch versions with:
#   sudo update-alternatives --config clang
# =============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Priority: higher number = auto-selected when in "auto" mode
# ------------------------------------------------------------------------------
declare -A PRIORITY=( [20]=80 [21]=90 [22]=100 )

# ------------------------------------------------------------------------------
# All slave tools to link alongside the master "clang" alternative.
# Format: "generic-name versioned-binary"
# Only slaves whose versioned binary actually exists on disk are registered.
# ------------------------------------------------------------------------------
SLAVES=(
    # Compiler frontends
    "clang++            clang++"
    "clang-cpp          clang-cpp"

    # Clang tools
    "clang-format       clang-format"
    "clang-tidy         clang-tidy"
    "clang-scan-deps    clang-scan-deps"
    "clang-extdef-mapping clang-extdef-mapping"
    "clang-apply-replacements clang-apply-replacements"
    "clang-change-namespace   clang-change-namespace"
    "clang-doc          clang-doc"
    "clang-include-fixer clang-include-fixer"
    "clang-move         clang-move"
    "clang-query        clang-query"
    "clang-reorder-fields clang-reorder-fields"
    "clangd             clangd"
    "clang-check        clang-check"
    "clang-offload-bundler clang-offload-bundler"
    "clang-offload-packager clang-offload-packager"
    "clang-linker-wrapper  clang-linker-wrapper"
    "clang-pseudo        clang-pseudo"
    "clang-refactor      clang-refactor"
    "clang-rename        clang-rename"
    "clang-repl          clang-repl"

    # LLVM core tools
    "llvm-addr2line     llvm-addr2line"
    "llvm-ar            llvm-ar"
    "llvm-as            llvm-as"
    "llvm-bcanalyzer    llvm-bcanalyzer"
    "llvm-bitcode-strip llvm-bitcode-strip"
    "llvm-cat           llvm-cat"
    "llvm-cfi-verify    llvm-cfi-verify"
    "llvm-config        llvm-config"
    "llvm-cov           llvm-cov"
    "llvm-cvtres        llvm-cvtres"
    "llvm-cxxdump       llvm-cxxdump"
    "llvm-cxxfilt       llvm-cxxfilt"
    "llvm-cxxmap        llvm-cxxmap"
    "llvm-debuginfod    llvm-debuginfod"
    "llvm-debuginfod-find llvm-debuginfod-find"
    "llvm-diff          llvm-diff"
    "llvm-dis           llvm-dis"
    "llvm-dlltool       llvm-dlltool"
    "llvm-dwarfdump     llvm-dwarfdump"
    "llvm-dwarfutil     llvm-dwarfutil"
    "llvm-dwp           llvm-dwp"
    "llvm-exegesis      llvm-exegesis"
    "llvm-extract       llvm-extract"
    "llvm-gsymutil      llvm-gsymutil"
    "llvm-ifs           llvm-ifs"
    "llvm-install-name-tool llvm-install-name-tool"
    "llvm-jitlink       llvm-jitlink"
    "llvm-lib           llvm-lib"
    "llvm-libtool-darwin llvm-libtool-darwin"
    "llvm-link          llvm-link"
    "llvm-lipo          llvm-lipo"
    "llvm-lto           llvm-lto"
    "llvm-lto2          llvm-lto2"
    "llvm-mc            llvm-mc"
    "llvm-mca           llvm-mca"
    "llvm-modextract    llvm-modextract"
    "llvm-mt            llvm-mt"
    "llvm-nm            llvm-nm"
    "llvm-objcopy       llvm-objcopy"
    "llvm-objdump       llvm-objdump"
    "llvm-opt-report    llvm-opt-report"
    "llvm-otool         llvm-otool"
    "llvm-pdbutil       llvm-pdbutil"
    "llvm-PerfectShuffle llvm-PerfectShuffle"
    "llvm-profdata      llvm-profdata"
    "llvm-profgen       llvm-profgen"
    "llvm-ranlib        llvm-ranlib"
    "llvm-rc            llvm-rc"
    "llvm-readelf       llvm-readelf"
    "llvm-readobj       llvm-readobj"
    "llvm-reduce        llvm-reduce"
    "llvm-remark-size-diff llvm-remark-size-diff"
    "llvm-remarkutil    llvm-remarkutil"
    "llvm-rtdyld        llvm-rtdyld"
    "llvm-sim           llvm-sim"
    "llvm-size          llvm-size"
    "llvm-split         llvm-split"
    "llvm-stress        llvm-stress"
    "llvm-strings       llvm-strings"
    "llvm-strip         llvm-strip"
    "llvm-symbolizer    llvm-symbolizer"
    "llvm-tblgen        llvm-tblgen"
    "llvm-tli-checker   llvm-tli-checker"
    "llvm-undname       llvm-undname"
    "llvm-windres       llvm-windres"
    "llvm-xray          llvm-xray"

    # Optimizer / assembler
    "opt                opt"
    "llc                llc"
    "lli                lli"
    "FileCheck          FileCheck"
    "bugpoint           bugpoint"
    "count              count"
    "not                not"

    # LLD linker
    "lld                lld"
    "ld.lld             ld.lld"
    "ld64.lld           ld64.lld"
    "lld-link           lld-link"
    "wasm-ld            wasm-ld"

    # LLDB debugger
    "lldb               lldb"
    "lldb-argdumper     lldb-argdumper"
    "lldb-instr         lldb-instr"
    "lldb-server        lldb-server"
    "lldb-vscode        lldb-vscode"

    # Sanitizer / analysis
    "scan-build         scan-build"
    "scan-view          scan-view"
    "analyze-build      analyze-build"
    "intercept-build    intercept-build"

    # Misc
    "run-clang-tidy     run-clang-tidy"
    "pp-trace           pp-trace"
    "modularize         modularize"
)

# ------------------------------------------------------------------------------
BINDIR=/usr/bin
MASTER_NAME="clang"
MASTER_GENERIC="$BINDIR/clang"

# ------------------------------------------------------------------------------
remove_all() {
    echo "==> Removing all clang/llvm alternatives..."
    for VER in 20 21 22; do
        MASTER_BIN="$BINDIR/clang-$VER"
        update-alternatives --remove "$MASTER_NAME" "$MASTER_BIN" 2>/dev/null \
            && echo "    Removed version $VER" \
            || echo "    Version $VER was not registered (skipping)"
    done
    echo "Done."
}

# ------------------------------------------------------------------------------
register_all() {
    for VER in 20 21 22; do
        MASTER_BIN="$BINDIR/clang-$VER"
        PRIO=${PRIORITY[$VER]}

        if [[ ! -x "$MASTER_BIN" ]]; then
            echo "==> [SKIP] clang-$VER not found at $MASTER_BIN — install clang$VER first"
            continue
        fi

        echo ""
        echo "==> Registering clang-$VER (priority $PRIO)..."

        # Build slave arguments dynamically — only for binaries that exist
        SLAVE_ARGS=()
        for entry in "${SLAVES[@]}"; do
            GENERIC=$(echo "$entry" | awk '{print $1}')
            TOOL=$(echo "$entry"    | awk '{print $2}')
            VERSIONED="$BINDIR/$TOOL-$VER"

            if [[ -x "$VERSIONED" ]]; then
                SLAVE_ARGS+=(--slave "$BINDIR/$GENERIC" "$GENERIC" "$VERSIONED")
                echo "    + slave: $GENERIC -> $TOOL-$VER"
            fi
        done

        update-alternatives --install \
            "$MASTER_GENERIC" "$MASTER_NAME" "$MASTER_BIN" "$PRIO" \
            "${SLAVE_ARGS[@]}"

        echo "    OK"
    done
}

# ------------------------------------------------------------------------------
print_usage() {
    echo ""
    echo "Usage: sudo bash $0 [--remove]"
    echo ""
    echo "  (no args)  Register clang/llvm 20, 21, 22 alternatives"
    echo "  --remove   Unregister all three versions"
    echo ""
    echo "After registering, switch versions with:"
    echo "  sudo update-alternatives --config clang"
    echo ""
    echo "Check current state:"
    echo "  update-alternatives --display clang"
    echo ""
}

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

case "${1:-}" in
    --remove)
        remove_all
        ;;
    --help|-h)
        print_usage
        ;;
    "")
        register_all
        echo ""
        echo "=============================="
        echo " All done! Switch version with:"
        echo "   sudo update-alternatives --config clang"
        echo "=============================="
        ;;
    *)
        echo "Unknown option: $1"
        print_usage
        exit 1
        ;;
esac
