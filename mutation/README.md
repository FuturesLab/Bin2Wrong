# Bin2Wrong Mutator

Bin2Wrong Mutator is built based upon AFL++ [custom mutator](https://aflplus.plus/docs/custom_mutators/) and [ClangTool](https://clang.llvm.org/docs/LibASTMatchersTutorial.html). It contains a C source code mutator (with several mutation techniques), a compilation optimization mutator and a AFL++ custom mutator module that connects Bin2Wrong with AFL++.

The full structure:
```
Bin2Wrong Mutator
│
└────── AFL++ Custom Mutator Module (mutation-module/)
        │
        ├── C Source Code Mutator (srccode-mutators/)
        │   ├── AssignmentMutator
        │   ├── ConstantMutator
        │   ├── DeleteMutator
        │   ├── DuplicateMutator
        │   ├── ExpressionMutator
        │   ├── JumpMutator
        │   ├── StringMutator
        │   └── ...
        │
        ├── Compilation Optimization Mutator (compilation-mutators/) // mutate compiler and corresponding optimizations
        │
        └── Utils (utils-fuzzer/)
```

## How To Build Bin2Wrong Mutator

```
./build_mutator.sh
```

This script will download LLVM project, copy Bin2Wrong Mutator source code into `llvm-project/clang-tools-extra/` and then build the mutator as a ClangTool.

When this script finishes, a `libBin2WrongMutator.so` file should be in `llvm-project/build/lib/`. Copy this file to this `mutation/` folder.
