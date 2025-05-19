set(LLVM_LINK_COMPONENTS support)

add_clang_library(compMutation
  CompilationMutators.cpp
  )