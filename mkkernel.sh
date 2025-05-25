#!/bin/bash

set -e

cd "$(dirname $0)"

rm -rf kbuild
mkdir -p kbuild/build kbuild/install
cd kbuild/build

cmake -DCROSS_COMPILER_PREFIX= -DCMAKE_INSTALL_PREFIX=../install \
    -DCMAKE_TOOLCHAIN_FILE=../../../seL4/gcc.cmake -G Ninja \
    -C ../../X64_dev.cmake ../../../seL4/
ninja all
ninja install
