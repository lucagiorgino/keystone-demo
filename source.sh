#!/bin/bash

export LIBSODIUM_CLIENT_DIR=$(pwd)/libsodium_builds/libsodium_client/src/libsodium
export LIBSODIUM_DIR=$(pwd)/libsodium_builds/libsodium_server/src/libsodium

# DEMO CHANGES
############################################################
# Automatically setup environment for the Keystone         #
# framework for this project.                              #
#                                                          #
# This is meant to be enabled after adjusting the path to  #
# the Keystone SDK folder, which is set to ../keystone/    #
# in the example below.                                    #
#                                                          #
# If this is enabled, it should be possible to fully       #
# configure a new session with the required environment    #
# variables for this project by just sourcing the current  #
# file.                                                    #
############################################################
## source ../keystone/source.sh


# Here we assume KEYSTONE_SDK_DIR has this structure and the keystone build dir is build
export KEYSTONE_BUILD_DIR="$(realpath -e "$KEYSTONE_SDK_DIR/../../build")"



############################################################
# MUSL toolchain                                           #
#                                                          #
# Some applications might require using musl libc to avoid #
# problems caused by the default threading model of glibc. #
# Read more details about this in `README.md`              #
#                                                          #
# This optional section can be enabled, on a per-project   #
# basis, to automatically source `setup_musl.sh` when      #
# sourcing this file, for convenience.                     #
#                                                          #
# By default the script will download and install the      #
# toolchain locally under the current folder.              #
# Assuming several projects might require using this       #
# toolchain, it is possible to set `RISCV_MUSL` to an      #
# external path to share the same toolchain across         #
# projects.                                                #
#                                                          #
# If RISCV_MUSL is set, but the expected binaries are not  #
# found inside of it, the script will try to download and  #
# install the toolchain at the indicated path: in this     #
# case, ensure proper writing permissions are in place.    #
############################################################
## RISCV_MUSL="/opt/riscv-musl-toolchain-lp64d-rv64gc-2021.04.bionic/riscv-musl"
## source ./setup_musl.sh
# END DEMO CHANGES