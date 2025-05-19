This README contains the instructions to set up each decompiler for using Bin2Wrong.

## Angr
Install Angr:
```
sudo apt install python3 pip3
pip3 install angr
```

Since Angr is writtern in Python, AFL++ cannot get the code coverage of it.

To fuzz it with Bin2Wrong in black box mode, use a wrapper [script](angr) along with AFL++ non-instrumented mode (-n).


## Binary Ninja
Binary Ninja is a commercial decompiler requiring a license: https://binary.ninja/purchase/.

A wrapper [program](bn-cli/src/bn_decompile.cpp) is needed to allow Binary Ninja to decompile programs without launching its GUI.

To build this program, use the following commands:
```
git clone https://github.com/Vector35/binaryninja-api.git
cd binaryninja-api
git checkout [apt_commit_hash]   ## replace this with the commit hash in [BinaryNinjaDir]/api_REVISION.txt
git submodule update --init --recursive
cp -rf [Bin2WrongPath]/decompilers/bn-cli examples/
cp -rf ../CMakeLists.txt examples/
cmake -S . -B build -DBN_INSTALL_DIR=[BinaryNinjaDir] -DBN_API_BUILD_EXAMPLES=ON -DHEADLESS=ON
cmake --build build -j12
```

Check if a `bn_cli` program exists in `[binaryninja-api]/build/out/bin/`

QEMU mode (-Q) needs to be used to get its code coverage in Bin2Wrong's grey box mode (set 'qemu' to 'true' in [config files](../configs/README.md)).

## R2Ghidra

Clone Radare2's repo: 
```
git clone https://github.com/radareorg/radare2
```

Since its source code is available, we can instrument it with AFL++.

In `configure` file of Radare2, add the following before `echo "int main(int argc, char **argv){return 0;}" > test.c`

```
CC=[AFLPLUSPLUS]/afl-clang-fast
```
Build Radare2 and R2Ghidra:
```
radare2/sys/install.sh
r2pm update
r2pm -ci r2ghidra
```

## Reko

Download Reko binaries from its releases: https://github.com/uxmal/reko/releases.

QEMU mode (-Q) needs to be used to get its code coverage in Bin2Wrong's grey box mode (set 'qemu' to 'true' in [config files](../configs/README.md))..

## Relyze

Download Relyze installer to a Windows machine: https://www.relyze.com/download.html.

After installing it in Windows, copy its installation folder to the machine where Bin2Wrong is located.

[WineHQ](https://wiki.winehq.org/Download) needs to be installed to run relyze on Linux.

To run Relyze withou lauching it GUI, use a wrapper [script](relyze) along with AFL++ non-instrumented mode (-n).

## RetDec

Clone Radare2's repo: 
```
git clone https://github.com/avast/retdec
```

Since its source code is available, we can instrument it with AFL++.

```
cd retdec
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=<retdec_path> -DCMAKE_C_COMPILER=[AFLPLUSPLUS]/afl-clang-fast -DCMAKE_CXX_COMPILER=[AFLPLUSPLUS]/afl-clang-fast++
make -j$(nproc)
make install
```
## Revng

Follow Revng's documentaion to install it: https://docs.rev.ng/user-manual/initial-setup/.

QEMU mode (-Q) needs to be used to get its code coverage in Bin2Wrong's grey box mode (set 'qemu' to 'true' in [config files](../configs/README.md)).