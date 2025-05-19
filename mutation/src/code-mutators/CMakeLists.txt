set(LLVM_LINK_COMPONENTS support)

add_clang_library(codeMutators
  CodeMutators.cpp
  )
target_link_libraries(codeMutators
  PRIVATE
  clangTooling
  clangBasic
  clangASTMatchers
  utils-fuzzer
  )
