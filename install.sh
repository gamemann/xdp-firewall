#!/bin/bash
set -euo pipefail
LIBXDP=0
INSTALL=1
CLEAN=0
OBJDUMP=0
HELP=0
STATIC=1

while [[ $# -gt 0 ]]; do
    key="$1"

    case $key in
        --libxdp)
            LIBXDP=1

            shift
            ;;

        --no-install)
            INSTALL=0

            shift
            ;;

        --clean)
            CLEAN=1

            shift
            ;;

        --no-static)
            STATIC=0
            
            shift
            ;;

        --objdump)
            OBJDUMP=1

            shift
            ;;

        --help)
            HELP=1

            shift
            ;;
        *)

            shift
            ;;
        esac
done

if [ "$HELP" -gt 0 ]; then
    echo "Usage: install.sh [OPTIONS]"
    echo
    echo "Options:"
    echo "  --libxdp       Build and install LibXDP before building the tool."
    echo "  --no-install   Build the tool and/or LibXDP without installing them."
    echo "  --clean        Remove build files for the tool and LibXDP."
    echo "  --no-static    Do not statically link LibXDP and LibBPF object files when building the tool and rely on shared libraries (-lbpf and -lxdp flags)."
    echo "  --objdump      Dumps the XDP/BPF object file using 'llvm-objdump' to Assemby into 'objdump.asm'."
    echo "  --help         Display this help message."

    exit 0
fi

if [ "$CLEAN" -gt 0 ]; then
    if [ "$LIBXDP" -gt 0 ]; then
        echo "Cleaning LibXDP..."

        ./scripts/libxdp_clean.sh
    fi

    echo "Cleaning up tool..."

    ./scripts/clean.sh

    exit 0
fi

if [ "$OBJDUMP" -gt 0 ]; then
    echo "Dumping object file..."

    ./scripts/objdump.sh

    exit 0
fi

if [ "$LIBXDP" -gt 0 ]; then
    echo "Building LibXDP..."

    ./scripts/libxdp_build.sh

    if [ "$INSTALL" -gt 0 ]; then
        echo "Installing LibXDP..."

        sudo ./scripts/libxdp_install.sh
    fi
fi

echo "Building tool..."

./scripts/build.sh $STATIC

if [ "$INSTALL" -gt 0 ]; then
    echo "Installing tool..."

    sudo ./scripts/install.sh
fi