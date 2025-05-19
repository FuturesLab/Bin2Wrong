#!/bin/bash

sudo apt-get update
sudo apt-get install -y cmake
sudo apt-get install -y ninja-build
sudo apt-get install -y python3
sudo apt-get install -y python3-pip

wget https://github.com/llvm/llvm-project/archive/refs/tags/llvmorg-18.1.0.zip
unzip llvmorg-18.1.0.zip
mv llvm-project-llvmorg-18.1.0/ llvm-project/

cp -rf src/compilation-mutators/ llvm-project/clang-tools-extra/
cp -rf src/mutation-module/ llvm-project/clang-tools-extra/
cp -rf src/code-mutators/ llvm-project/clang-tools-extra/
cp -rf src/utils-fuzzer/ llvm-project/clang-tools-extra/

echo "add_subdirectory(compilation-mutators)" >> llvm-project/clang-tools-extra/CMakeLists.txt
echo "add_subdirectory(mutation-module)" >> llvm-project/clang-tools-extra/CMakeLists.txt
echo "add_subdirectory(code-mutators)" >> llvm-project/clang-tools-extra/CMakeLists.txt
echo "add_subdirectory(utils-fuzzer)" >> llvm-project/clang-tools-extra/CMakeLists.txt

cd llvm-project/
mkdir build && cd build
cmake -G Ninja ../llvm -DLLVM_ENABLE_PROJECTS="clang;clang-tools-extra" -DCMAKE_BUILD_TYPE=Release
ninja
