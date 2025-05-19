#ifndef __CODE_MUTATORS_H
#define __CODE_MUTATORS_H

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Tooling/Tooling.h"
#include "clang/Rewrite/Core/Rewriter.h"

#include "../utils-fuzzer/GrayCCustomRandom.h"
#include "../utils-fuzzer/GrayCUtils.h"

#include <iostream>
#include <random>
#include <string>
#include <vector>

using namespace std;
using namespace clang;


enum cType {
  cChar,
  cShort,
  cInt,
  cLong,
  cLongLong,
  cUChar,
  cUShort,
  cUInt,
  cULong,
  cULongLong,
};
#define MAX_CONST_TYPE ((cType)(cULongLong + 1))

// Control fuzzing aggressiveness
#define _MUTATOR_MAX_EXPR_SIZE 50
#define _MUTATOR_MAX_SUB_EXPR_SIZE 30
#define _MUTATOR_EXPR_SIZE 5
#define _MUTATOR_SUB_EXPR_SIZE 10
#define _MUTATOR_DATA_TYPE_SIZE 3
#define _MUTATOR_FLOAT_OP_SIZE 3
#define _MUTATOR_INT_OP_SIZE 6







#endif