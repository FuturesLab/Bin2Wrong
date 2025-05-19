set(LLVM_LINK_COMPONENTS support)

add_clang_library(Bin2WrongMutator
  SHARED
  MutationModule.c
  )
target_link_libraries(Bin2WrongMutator
  PRIVATE
  codeMutators
  compMutation
  )
include_directories(
  ${CMAKE_CURRENT_LIST_DIR}/../../../../AFLplusplus/include/
)
