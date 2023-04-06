__setup_musl_fn__() {
    local DIST=bionic
    local BITS=64

    local RISCV_MUSL_GCC="riscv$BITS-unknown-linux-musl-gcc"

    local TOOLCHAIN_MUSL_7Z_FILE="riscv-musl-toolchain-lp64d-rv64gc-2021.04.$DIST.7z"

    if ( $(command -v "${RISCV_MUSL_GCC}" > /dev/null) )
    then
        echo "RISCV MUSL tools are already installed" >&2
        echo "Setting up enviroment vars...done" >&2
        export RISCV_MUSL="$(realpath "$(dirname "$(which "${RISCV_MUSL_GCC}")")/..")"
        return 0
    else
        : ${RISCV_MUSL:="$(pwd)/riscv$BITS-musl/riscv-musl"}
    fi

    if [[ ! -f "${RISCV_MUSL}/bin/${RISCV_MUSL_GCC}" ]]; then
        echo "Downloading Prebuilt RISC-V MUSL Toolchain... " >&2

        wget -nc "https://keystone-enclave.eecs.berkeley.edu/files/$TOOLCHAIN_MUSL_7Z_FILE"

        # Check tool integrity
        echo "Verifying prebuilt toolchain integrity..." >&2

        sha256sum -c .prebuilt_tools_shasums --status --ignore-missing

        if [[ $? != 0 ]]; then
            echo "Toolchain binary download incomplete or corrupted. You can build the toolchain locally or try again." >&2
            unset RISCV_MUSL
            return 1
        else
            echo "Extracting Toolchain" >&2
            7za x -y $TOOLCHAIN_MUSL_7Z_FILE -o"$(dirname "${RISCV_MUSL}")"

            rm $TOOLCHAIN_MUSL_7Z_FILE
            # rm .prebuilt_tools_shasums
            echo "Toolchain has been installed in $RISCV_MUSL" >&2

        fi
    fi

    echo "Setting up enviroment vars...done" >&2
    export RISCV_MUSL="$(realpath -e "${RISCV_MUSL}")"
    export PATH="$RISCV_MUSL/bin:$PATH"
}

if __setup_musl_fn__; then
    unset -f __setup_musl_fn__
    return 0
else
    unset -f __setup_musl_fn__
    return 1
fi
