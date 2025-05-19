# Modify Bin2Wrong fuzzing configurations

This folder contains the configiguration files for fuzzing different decompilers.

## What need to be modified

(1) Bin2Wrong.path<br />
(2) Bin2Wrong.fuzzingDir<br />
(3) Bin2Wrong.qemu<br />
(4) decompile.decompilerpath<br />
(5) compile.compiler<br />

if MSVC is used:<br />
(6) msvc<br />
(7) msvcinc<br />
(8) msvclib<br />
(9) win2lin<br />

## Full description of config files
```
config
   │
   ├───── Bin2Wrong
   │       ├── path: the full path to Bin2Wrong directory
   │       │
   │       ├── fuzzingDir: the relative path to fuzzing folder, "fuzz_dir/retdec/"
   │       │
   │       ├── mutator: the relative path to Bin2Wrong Mutator, "mutation/libBin2WrongMutator.so"
   │       │
   │       ├── postdecDir: the relative path to the directory of post decompilation script, "post_decompilation/"
   │       │
   │       ├── postdecName: the file name of post decompilation script, "post_dec"
   │       │
   │       └── qemu: set to "true" to use QEMU mode
   │ 
   ├───── decompile  
   │       ├── decompiler: the name of the decompiler to be fuzzed, "retdec", "r2ghidra", etc.
   │       │
   │       ├── decompilerpath: the path to the decompiler
   │       │
   │       └── declib: the relative path to extern library (omitting file extension) for re-compilation if needed, "post_decompilation/dec_libs/retdec/retdec"      
   │       
   └───── compile      
           ├── compiler: the compiler(s) to be used for compilation, "clang", "gcc", etc.;
           │             when there are muiltiple compilers, each compiler will be chosen randomly during fuzzing
           │
           ├── clangflags: the relative path to the optimization flags text file of Clang/AppleClang
           │
           ├── gccflags: the relative path to the optimization flags text file of GCC
           │
           ├── tccflags: the relative path to the optimization flags text file of Tiny C Compiler
           │
           ├── icxflags: the relative path to the optimization flags text file of Intel oneAPI DPC++/C++ Compiler (icx)
           │
           ├── msvcflags: the relative path to the optimization flags text file of Microsoft C/C++ Compiler (msvc)
           │
           ├── csmith: the relative path to the directory of csmith runtime files, "post_decompilation/csmith_install/include/"
           │
           ├── gnu: the path to the directory of Linux GNU header files, "/usr/include/x86_64-linux-gnu/"
           │
           ├── msvc: the path to the CLI program of MSVC
           │
           ├── msvcinc: the includes folder of MSVC
           │
           ├── msvclib: the libs folder of MSVC
           │
           └── win2lin: the application to run Windows programs in Linux

```