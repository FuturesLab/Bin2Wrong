#include "CodeMutators.h"

string mutationChosen;
string reWrittenStr;
bool gotRewritten = false;
bool inCaseStmt = false;

vector<string> _mutator_options = {
    "AssignmentMutator", "ConstantMutator", "DeleteMutator", 
    "DuplicateMutator",  "ExpressionMutator", "JumpMutator",
    "StringMutator", "SwitchMutator", "GotoMutator"};

class CodeMutatorsVisitor
  : public RecursiveASTVisitor<CodeMutatorsVisitor> {
private:
    Rewriter *reWriter; 
    ASTContext *astContext;

    int jump_latest_loop_start = -99;
    int jump_latest_loop_end = -99;
    int constant_latest_array_line_no = -99;
    double constant_array_size = -99;
    int duplicate_tmp_latest_loop_line = -99;
    //SourceLocation duplicate_last_sloc;

    vector<string> expr_to_add;
    vector<int> visited_node_IDs;
    string float_operator_bank[_MUTATOR_FLOAT_OP_SIZE] = {"+", "-", "*"};
    string data_types[_MUTATOR_DATA_TYPE_SIZE] = {"int", "long", "short"};
    string int_operator_bank[_MUTATOR_INT_OP_SIZE] = {"<<", ">>", "&", "^",  "%",  "|"};

    vector<StringRef> gotoLabels;
public:
  explicit CodeMutatorsVisitor(ASTContext *context, Rewriter *rewriter)
    : reWriter(rewriter), astContext(context)
    {
        reWriter->setSourceMgr(astContext->getSourceManager(), astContext->getLangOpts());
    }

  bool VisitSwitchStmt(SwitchStmt *stmt){
    if(mutationChosen == "SwitchMutator"){
        if(!stmt){
            return true;
        }

        vector<string> caseExprs;

        Expr *cond = stmt->getCond();
        if(!cond){
            return true;
        }

        CharSourceRange condRange = CharSourceRange::getTokenRange(cond->getBeginLoc(), cond->getEndLoc());
        if(condRange.isInvalid()){
            return true;
        }

        if (Stmt *Body = stmt->getBody()) {
            for (Stmt *Child : Body->children()) {
                if (!Child) continue;

                if (auto *CS = dyn_cast<clang::CaseStmt>(Child)) {
                    clang::Expr *CaseExpr = CS->getLHS();
                    if (CaseExpr) {
                        CharSourceRange caseRange = CharSourceRange::getTokenRange(CaseExpr->getBeginLoc(), CaseExpr->getEndLoc());
                        string caseStr = string(Lexer::getSourceText(caseRange, astContext->getSourceManager(), astContext->getLangOpts()));
                        caseExprs.push_back(caseStr);
                    }
                }
            }
        }

        reWriter->ReplaceText(condRange, caseExprs[GrayCCustomRandom::GetInstance()->rnd_dice(caseExprs.size())]);
        return true;
    }
    else{
        return true;
    }
  }

  bool VisitCaseStmt(CaseStmt *CS) {
    if(mutationChosen == "ConstantMutator"){
      inCaseStmt = true;
      return true;
    }
    else{
      return true;
    }
  }

  bool VisitGotoStmt(GotoStmt *gs) {
    if(mutationChosen == "GotoMutator"){
      if(!gs){
        return true;
      }

      CharSourceRange gotoRange = CharSourceRange::getTokenRange(gs->getBeginLoc(), gs->getEndLoc());
      int numGotoLabels = gotoLabels.size();

      if(numGotoLabels != 0){

        int label_chosen_index = GrayCCustomRandom::GetInstance()->rnd_dice(numGotoLabels-1); // exclude the last label
        StringRef label_chosen = gotoLabels[label_chosen_index];
        string new_goto = "goto " + string(label_chosen);

        reWriter->ReplaceText(gotoRange, new_goto);
      }
      return true;
    }
    else{
      return true;
    }
  }

  bool VisitLabelStmt(LabelStmt *ls){
    if(mutationChosen == "GotoMutator"){
      if(!ls){
        return true;
      }

      LabelDecl *label = ls->getDecl();
      StringRef labelStrRef = label->getName();

      gotoLabels.push_back(labelStrRef);

      return true;
    }
    else{
      return true;
    }
  }

  // Mutate while statements with DeleteMutator or JumpMutator
  bool VisitWhileStmt(WhileStmt *stmt){
    if(mutationChosen == "DeleteMutator"){
      if(!stmt || GrayCCustomRandom::GetInstance()->rnd_yes_no(0.7)){
        return true;
        }
      Expr *cond = stmt->getCond();
      if(!cond){
          return true;
      }
      CharSourceRange condRange = CharSourceRange::getTokenRange(cond->getBeginLoc(),cond->getEndLoc());
      if(condRange.isInvalid()){
          return true;
      }

      reWriter->InsertTextBefore(stmt->getBody()->getEndLoc(), "\nbreak;\n");
      int node_id = stmt->getID(*astContext);

      auto str_ref = Lexer::getSourceText(condRange, astContext->getSourceManager(), astContext->getLangOpts());
      if(str_ref.empty()){
          return true;
      }

      string cond_call_expr_str = string(str_ref);
      if (cond_call_expr_str.empty()){
          return true;
      }

      reWriter->InsertTextBefore(stmt->getBeginLoc(), "\nint while_condition_" + to_string(node_id) + " = " + cond_call_expr_str + ";\n");
      reWriter->ReplaceText(condRange, "while_condition_" + to_string(node_id));
      return true;
    }
    else if(mutationChosen == "JumpMutator"){
      if(!stmt || astContext->getSourceManager().isInExternCSystemHeader(stmt->getBeginLoc())){
        return true;
      }

      int node_id_loop = stmt->getID(*astContext);
      int line_no = (astContext->getSourceManager()).getSpellingLineNumber(stmt->getBeginLoc());
      if(line_no >= jump_latest_loop_start && line_no <= jump_latest_loop_end){
        return true;
      }

      string loop_break_var = "loop_break_" + to_string(node_id_loop);
      string loop_break_decl = "\nint " + loop_break_var + " = 0;\n";
      string jump_construct = pick_break_or_continue();
      int loop_break_limit = GrayCCustomRandom::GetInstance()->rnd_dice() + 1;
      string loop_break_block = loop_break_var + "++;\n" + "if(" + loop_break_var + "<=" + to_string(loop_break_limit) + "){\n"
          + jump_construct + ";\n}\n";
      if (stmt->getBeginLoc().isInvalid()){
        return true;
      }

      reWriter->InsertTextBefore(stmt->getBeginLoc(), loop_break_decl);
      Stmt *body = stmt->getBody();
      for(Stmt::child_iterator j_se = body->child_begin(), e = body->child_end(); j_se != e; ++j_se){
        Stmt *currStmt = *j_se;
        if (currStmt && !isa<ForStmt>(currStmt) && !isa<WhileStmt>(currStmt) && currStmt->getBeginLoc().isValid()){
          reWriter->InsertTextAfter(currStmt->getBeginLoc(), "\n" + loop_break_block + "\n");
          break;
        }
      }
      jump_latest_loop_start = ((astContext->getSourceManager()).getSpellingLineNumber(stmt->getBeginLoc()));
      jump_latest_loop_end = ((astContext->getSourceManager()).getSpellingLineNumber(stmt->getEndLoc()));
      return true;
    }
    else if(mutationChosen == "DuplicateMutator"){
      duplicate_tmp_latest_loop_line = (astContext->getSourceManager()).getSpellingLineNumber(stmt->getBeginLoc());
      return true;
    }
    else{
      return true;
    }
  }

  // Mutate if statements with DeleteMutator or ExpressionMutator
  bool VisitIfStmt(IfStmt *stmt) {
    if(mutationChosen == "DeleteMutator"){
      if(!stmt){
        return true;
      }
      float randomValue = GrayCCustomRandom::GetInstance()->rnd_probability();
      if(!(randomValue < 0.5)){
        return true;
      }

      Expr *expr = stmt->getCond();
      if(!expr){
        return true;
      }

      CharSourceRange conditionRange = CharSourceRange::getTokenRange(expr->getBeginLoc(), expr->getEndLoc());
      if(conditionRange.isInvalid()){
        return true;
      }

      llvm::StringRef condition_str = Lexer::getSourceText(conditionRange, astContext->getSourceManager(), astContext->getLangOpts());
      if(condition_str.empty()){
        return true;
      }

      string condition_type_str = expr->getType().getAsString();
      if (condition_str.empty() || condition_type_str.empty()){
        return true;
      }

      reWriter->ReplaceText(conditionRange, ((randomValue >= 0.75) ? "1" : "0"));

      return true;
      }
    else if(mutationChosen == "ExpressionMutator"){
      if (!stmt){
        return true;
        }
      Expr *cond = stmt->getCond();
      if (!cond){
        return true;
        }
        
      CharSourceRange cond_range = CharSourceRange::getTokenRange(cond->getBeginLoc(), cond->getEndLoc());
      if (cond_range.isInvalid()){
        return true;
        }
        
      auto str_ref = Lexer::getSourceText(cond_range, astContext->getSourceManager(), astContext->getLangOpts());
      if (str_ref.empty()){
        return true;
        }
        
      string cond_str = string(str_ref);
      if (cond_str.empty()){
        return true;
        }
        
      Stmt *sub_stmt = cast<Stmt>(cond);
      if (!sub_stmt){
        return true;
        }
        
      expr_to_add.clear();
      if (isa<BinaryOperator>(cond)) {
        BinaryOperator *cond_bop = cast<BinaryOperator>(cond);
        collect_sub_expressions(cond_bop);
        } 
      else {
        for (Stmt::child_iterator j_se = sub_stmt->child_begin(), e = sub_stmt->child_end(); j_se != e; ++j_se) {
          Stmt *currStmt = *j_se;
          // Deal with nested call expressions within binary operators on the RHS expression.
          if (isa<BinaryOperator>(currStmt)) {
            BinaryOperator *sub_bop = cast<BinaryOperator>(currStmt);
            if (!sub_bop){
              return true;
              }
            if (sub_bop->isAssignmentOp()){
              return true;
              }
              
            int node_id_args = (sub_bop)->getID(*astContext);
            visited_node_IDs.push_back(node_id_args);
            collect_sub_expressions(sub_bop);
            } // End of if stmt
          } // End of For loop
        } // End of ELSE
        
      if (expr_to_add.size()) {
        // Check if the expression is not too big
        unsigned expr_length = (GrayCCustomRandom::GetInstance()->rnd_dice() % _MUTATOR_SUB_EXPR_SIZE) + 1;
        if ((expr_length + visited_node_IDs.size()) > _MUTATOR_MAX_SUB_EXPR_SIZE){
          return true; /* Limit the size of the expression we can create */
          }
         
        // Mutate
        string expr_append = cond_str + " + 41";
        for (unsigned i = 0; i < expr_length; i++){
          expr_append += " " + get_float_random_op() + " ((" + get_random_dtype() + ")(" + generate_random_expr() + "))";
          }
        expr_append = "((int)" + expr_append + ")";
        reWriter->ReplaceText(cond_range, expr_append);
        }
      return true;
    }
    else{
      return true;
  }
  }

  // Mutate for statements with JumpMutator
  bool VisitForStmt(ForStmt *stmt){
    if(mutationChosen == "JumpMutator"){
      if(!stmt || astContext->getSourceManager().isInExternCSystemHeader(stmt->getBeginLoc())){
        return true;
        }
        
      int line_no = (astContext->getSourceManager()).getSpellingLineNumber(stmt->getBeginLoc());
      if(line_no >= jump_latest_loop_start && line_no <= jump_latest_loop_end){
        return true;
        }
      int node_id_loop = stmt->getID(*astContext);
      string loop_break_var = "loop_break_" + to_string(node_id_loop);
      string loop_break_decl = "\nint " + loop_break_var + " = 0;\n";
      
      int loop_break_limit = GrayCCustomRandom::GetInstance()->rnd_dice() + 1;
      string jump_construct = pick_break_or_continue();
      string loop_break_block = loop_break_var + "++;\n" + "if(" + loop_break_var + "<=" + to_string(loop_break_limit) + "){\n" +
        jump_construct + ";\n}\n";
      if(stmt->getBeginLoc().isInvalid()){
        return true;
        }
        
      reWriter->InsertTextBefore(stmt->getBeginLoc(), loop_break_decl);
      Stmt *body = stmt->getBody();
      for(Stmt::child_iterator j_se = body->child_begin(), e = body->child_end(); j_se != e; ++j_se){
        Stmt *currStmt = *j_se;
        if(currStmt && !isa<ForStmt>(currStmt) && !isa<WhileStmt>(currStmt) && currStmt->getBeginLoc().isValid()){
          reWriter->InsertTextAfter(currStmt->getBeginLoc(), "\n" + loop_break_block + "\n");
          break;
        }
      }
      jump_latest_loop_start = ((astContext->getSourceManager()).getSpellingLineNumber(stmt->getBeginLoc()));
      jump_latest_loop_end = ((astContext->getSourceManager()).getSpellingLineNumber(stmt->getEndLoc()));
      //string reWritten = reWriter->getRewrittenText(CharSourceRange::getTokenRange(stmt->getBeginLoc(),stmt->getEndLoc()));
      //llvm::outs() << "jump for\n"+ reWritten + "\n";
      return true;
    }
    else if(mutationChosen == "DuplicateMutator"){
      duplicate_tmp_latest_loop_line = (astContext->getSourceManager()).getSpellingLineNumber(stmt->getBeginLoc());
      return true;
    }
    else{
      return true;
    }
  }

  // Mutate unary operators with AssginmentMutator
  bool VisitUnaryOperator(UnaryOperator *stmt){
    if(mutationChosen == "AssignmentMutator"){
      if(!stmt){
        return true;
      }

      CharSourceRange decl_range = CharSourceRange::getTokenRange(stmt->getBeginLoc(), stmt->getEndLoc());
      if(decl_range.isInvalid()){
        return true;
      }

      auto str_ref = Lexer::getSourceText(decl_range, astContext->getSourceManager(), astContext->getLangOpts());
      if(str_ref.empty()){
        return true;
      }

      string decl_str = string(str_ref);
      if(decl_str.empty()){
        return true;
      }

      if(stmt->isIncrementOp()){
        reWriter->ReplaceText(stmt->getExprLoc(), string("--"));
      }
      else if(stmt->isDecrementOp()){
        reWriter->ReplaceText(stmt->getExprLoc(), string("++"));
      }
      //string reWritten = reWriter->getRewrittenText(CharSourceRange::getTokenRange(stmt->getBeginLoc(),stmt->getEndLoc()));
      //llvm::outs() << "unary assignment\n"+ reWritten + "\n";
      return true;
    }
    else{
      return true;
    }
  }

  // Mutate statements and expressions mixed declarations with AssignmentMutator
  bool VisitDeclStmt(DeclStmt *stmt){
    if(mutationChosen == "AssignmentMutator"){
      if(!stmt || !stmt->isSingleDecl()){
        return true;
      }

      VarDecl *vd = cast<VarDecl>(stmt->getSingleDecl());
      if(!vd){
        return true;
      }

      CharSourceRange decl_range = CharSourceRange::getTokenRange(stmt->getBeginLoc(), stmt->getEndLoc());
      if(decl_range.isInvalid()){
        return true;
      }

      auto str_ref = Lexer::getSourceText(decl_range, astContext->getSourceManager(), astContext->getLangOpts());
      if(str_ref.empty() || str_ref.find("__") != string::npos){
        return true;
      }

      QualType qt = vd->getType();
      if(qt.isNull() || qt->isArrayType() || !qt.isTrivialType(*astContext)){
        return true;
      }

      string type = qt.getAsString();
      if(!type.empty() && (type == "int" || type == "short")){
        CharSourceRange declRange = CharSourceRange::getTokenRange(stmt->getBeginLoc(), stmt->getEndLoc());
        if(declRange.isInvalid()){
          return true;
        }

        string decl_str = string(str_ref);
        if(decl_str.empty()){
          return true;
        }

        if (GrayCUtils::getAssignmentNos(decl_str) > 1){
          return true;
        }

        string var_name = vd->getQualifiedNameAsString();
        if(var_name.empty()){
          return true;
        }

        reWriter->ReplaceText(declRange, type + " " + var_name + " = 8;");
      }
      //string reWritten = reWriter->getRewrittenText(CharSourceRange::getTokenRange(stmt->getBeginLoc(),stmt->getEndLoc()));
      //llvm::outs() << "decl assignment\n"+ reWritten + "\n";
      return true;
    }
    else{
      return true;
    }
  }

  bool VisitVarDecl(VarDecl *D){
    if(mutationChosen == "ConstantMutator"){
      //string reWritten = reWriter->getRewrittenText(CharSourceRange::getTokenRange(D->getBeginLoc(),D->getEndLoc()));
      //llvm::outs() << "orig\n"+ reWritten + "\n";
      if(!D){
        return true;
      }
      if (auto t = dyn_cast_or_null<ConstantArrayType>(D->getType().getTypePtr())) {
        constant_latest_array_line_no = ((astContext->getSourceManager()).getSpellingLineNumber(D->getBeginLoc()));
        constant_array_size = (t->getSize()).roundToDouble();
        }
      //reWritten = reWriter->getRewrittenText(CharSourceRange::getTokenRange(D->getBeginLoc(),D->getEndLoc()));
      //llvm::outs() << "var constant\n"+ reWritten + "\n";
      return true;
    }
    else{
      return true;
    }
  }

  bool VisitFloatingLiteral(FloatingLiteral *flit) {
    if(mutationChosen == "ConstantMutator"){
      //string reWritten = reWriter->getRewrittenText(CharSourceRange::getTokenRange(flit->getBeginLoc(),flit->getEndLoc()));
      //llvm::outs() << "orig\n"+ reWritten + "\n";
      if(!flit){
        return true;
        }
      if(!reWriter->isRewritable(flit->getBeginLoc()) || !reWriter->isRewritable(flit->getEndLoc())){
        return true;
        }
        
      CharSourceRange const_range = CharSourceRange::getTokenRange(flit->getBeginLoc(), flit->getEndLoc());
      if (const_range.isInvalid()){
        return true;
        }
          
      auto str_ref = Lexer::getSourceText(const_range, astContext->getSourceManager(), astContext->getLangOpts());
      if (str_ref.empty()){
        return true;
        }
          
      string const_str = string(str_ref);
      if (const_str.empty()){
        return true;
        }
          
      size_t point_loc = const_str.find(".");
      if (point_loc != string::npos && (point_loc + 1) <= const_str.length()){
        string mutated_float = to_string(mutate_constant_float()) + "." + to_string(mutate_constant_float());
        reWriter->ReplaceText(const_range, "(" + mutated_float + ")");
        }
      //reWritten = reWriter->getRewrittenText(CharSourceRange::getTokenRange(flit->getBeginLoc(),flit->getEndLoc()));
      //llvm::outs() << "float constant\n"+ reWritten + "\n";
      return true;
    }
    else{
      return true;
    }
    }

  bool VisitIntegerLiteral(IntegerLiteral *ilit){
    if(mutationChosen == "ConstantMutator"){
      //string reWritten = reWriter->getRewrittenText(CharSourceRange::getTokenRange(ilit->getBeginLoc(),ilit->getEndLoc()));
      //llvm::outs() << "orig\n"+ reWritten + "\n";
      if(!ilit){
        return true;
        }
      if(inCaseStmt){ // do not mutate case statements
        inCaseStmt = false;
        return true;
      }
      CharSourceRange const_range = CharSourceRange::getTokenRange(ilit->getBeginLoc(), ilit->getEndLoc());
      if(const_range.isInvalid()){
        return true;
      }
      
      auto str_ref = Lexer::getSourceText(const_range, astContext->getSourceManager(), astContext->getLangOpts());
      if(str_ref.empty()){
        return true;
      }
      
      string const_str = string(str_ref);
      if(const_str.empty()){
        return true;
      }
      
      if (const_str != "" && is_number(const_str)){
        int array_line_no = ((astContext->getSourceManager()).getSpellingLineNumber(ilit->getBeginLoc()));
        const Expr *expr_un = cast<Expr>(ilit);
        if (!expr_un){
          return true;
        }
        
        bool allow_bad_access = GrayCCustomRandom::GetInstance()->rnd_yes_no(__CONSTANT_MUTATOR_ALLOW_NEG_NUM_MEMORY_ACCESS_CONST);
        bool allow_bad_size = GrayCCustomRandom::GetInstance()->rnd_yes_no(__CONSTANT_MUTATOR_ALLOW_BIG_NUM_MEMORY_CONST);
        bool is_array_decl = (!isInArraySubsrcipt(*expr_un) && ((array_line_no != constant_latest_array_line_no) || (array_line_no < 0)));
        
        if (!is_array_decl || (allow_bad_access && allow_bad_size)){
          int line_no = (astContext->getSourceManager()).getSpellingLineNumber(ilit->getBeginLoc());
          int line_no_next = line_no + 1;
          if (line_no < 0){
            return true;
            }
            
          SourceLocation thisline = (astContext->getSourceManager()).translateLineCol((astContext->getSourceManager()).getMainFileID(), line_no, 1);
          if (thisline.isInvalid()){
            return true;
            }
            
          SourceLocation nextline = (astContext->getSourceManager()).translateLineCol((astContext->getSourceManager()).getMainFileID(), line_no_next, 1);
          if (nextline.isInvalid()){
            return true;
            }
            
          SourceRange srange(thisline, nextline);
          if (srange.isInvalid()){
            return true;
            }
            
          string string_to_rewrite = string(Lexer::getSourceText(CharSourceRange::getTokenRange(srange), astContext->getSourceManager(), astContext->getLangOpts(), 0));
          
          bool allow_bad = (is_array_decl && allow_bad_access && allow_bad_size) || (!is_array_decl && allow_bad_access);
          if (!string_to_rewrite.empty() && (allow_bad || !GrayCUtils::is_bad_line(string_to_rewrite))) {
            reWriter->ReplaceText(const_range, "(" + mutate_constant_integers(const_str) + ")");
            }
          }
        else{
          string to_append = "(" + mutate_constant_integers(const_str, ((array_line_no == constant_latest_array_line_no) ? 1 : 0),
              allow_bad_size ? UINT_MAX : SHRT_MAX) + ")";
          reWriter->ReplaceText(const_range, to_append);
          }
      }
      //reWritten = reWriter->getRewrittenText(CharSourceRange::getTokenRange(ilit->getBeginLoc(),ilit->getEndLoc()));
      //llvm::outs() << "integer constant\n"+ reWritten + "\n";
      return true;
    }
    else{
      return true;
    }
  }

  bool VisitBinaryOperator(BinaryOperator *stmt) {
    if(mutationChosen == "DuplicateMutator"){
      if (!stmt || stmt->getExprLoc().isInvalid() || !stmt->isAssignmentOp()){
        return true;
        }
        
      SourceLocation b_sloc = stmt->getBeginLoc();
      if (b_sloc.isInvalid()){
        return true;
        }
    
        
      int line_no = (astContext->getSourceManager()).getSpellingLineNumber(stmt->getBeginLoc());
      if (duplicate_tmp_latest_loop_line == line_no){
        return true;
        }
        
      if (!reWriter->isRewritable(stmt->getBeginLoc()) || !reWriter->isRewritable(stmt->getEndLoc())){
        return true;
        }
        
      if (pick_delete_or_duplicate() == "duplicate") {
        CharSourceRange binop_range = CharSourceRange::getTokenRange(stmt->getBeginLoc(), stmt->getEndLoc());
        if (binop_range.isInvalid()){
          return true;
          }
          
        auto str_ref = Lexer::getSourceText(binop_range, astContext->getSourceManager(), astContext->getLangOpts()); 
        if (str_ref.empty()){
          return true;
          }
          
        string bstmt_str = string(str_ref);
        if (bstmt_str.empty()){
          return true;
          }
        if (GrayCUtils::getAssignmentNos(bstmt_str) > 1){
          return true;
          }
          
        int line_no_check = (astContext->getSourceManager()).getSpellingLineNumber(stmt->getBeginLoc());
        if (line_no_check < 0){
          return true;
          }
          
        SourceLocation thisline = (astContext->getSourceManager()).translateLineCol((astContext->getSourceManager()).getMainFileID(),
                line_no_check, 1);
        if (thisline.isInvalid()){
          return true;
          }
          
        SourceLocation nextline = (astContext->getSourceManager()).translateLineCol((astContext->getSourceManager()).getMainFileID(),
                line_no_check + 1, 1);
        if (nextline.isInvalid()){
          return true;
          }
          
        SourceRange srange(thisline, nextline);
        if (srange.isInvalid()){
          return true;
          }
          
        string string_to_rewrite = string(Lexer::getSourceText(CharSourceRange::getTokenRange(srange),astContext->getSourceManager(), astContext->getLangOpts(), 0));
        if ((string_to_rewrite.empty()) || GrayCUtils::is_bad_line(string_to_rewrite)) {
          return true;
          }
          
        if (bstmt_str.empty()){
          return true;
          }
          
        reWriter->InsertTextBefore(stmt->getBeginLoc(), "\n;" + bstmt_str + ";\n");
        }
      else if (stmt->isAssignmentOp()) {
        CharSourceRange binop_range_for_deletion = CharSourceRange::getTokenRange(stmt->getBeginLoc(), stmt->getEndLoc());
        if (binop_range_for_deletion.isInvalid()){
          return true;
          }
          
        if (GrayCCustomRandom::GetInstance()->rnd_yes_no(__DUPLICATE_MUTATOR_REMOVE_RHS_OR_LHS)) {
          Expr *rhs_expr = stmt->getRHS();
          if (!rhs_expr){
            return true;
            }
            
          CharSourceRange rhs_range = CharSourceRange::getTokenRange(rhs_expr->getBeginLoc(), rhs_expr->getEndLoc());\
          if (rhs_range.isInvalid()){
            return true;
            }
            
          string rhs_str = string(Lexer::getSourceText(rhs_range, astContext->getSourceManager(), astContext->getLangOpts(), 0));
          reWriter->ReplaceText(binop_range_for_deletion, rhs_str);
          }
        else {
          Expr *lhs_expr = stmt->getLHS();
          if (!lhs_expr){
            return true;
            }
          
          CharSourceRange lhs_range = CharSourceRange::getTokenRange(lhs_expr->getBeginLoc(), lhs_expr->getEndLoc());
          if (lhs_range.isInvalid()){
            return true;
            }
            
          string lhs_str = string(Lexer::getSourceText(lhs_range, astContext->getSourceManager(), astContext->getLangOpts(), 0));
          reWriter->ReplaceText(binop_range_for_deletion, lhs_str);
          }
        } // If not assignement, we do it somewhere else (in expression mutator)


      if (stmt->getBeginLoc().isInvalid()){
        return true;
      }
      //duplicate_last_sloc = stmt->getBeginLoc();
      return true;
      }
    else if(mutationChosen == "ExpressionMutator"){
      if (!stmt || !stmt->isAssignmentOp()){
        return true;
        }
        
      // Randomly skip to avoid replacing the expression - higher more aggressive
      if (GrayCCustomRandom::GetInstance()->rnd_yes_no(__EXPRESSION_MUTATOR_REPLACE_BIN_OP_SUB_EXPR)){
        return true;
        }
        
      // Check if visited
      int binary_op_node_id = (stmt)->getID(*astContext);
      if (find(visited_node_IDs.begin(), visited_node_IDs.end(), binary_op_node_id) != visited_node_IDs.end()){
        return true;
        }
        
      int line_no_check = (astContext->getSourceManager()).getSpellingLineNumber(stmt->getBeginLoc());
      int line_no_next = line_no_check + 1;
      
      // Extract the current line as a text
      SourceLocation thisline = (astContext->getSourceManager()).translateLineCol((astContext->getSourceManager()).getMainFileID(),
                            line_no_check, 1); // get the beginning of line line_no
      SourceLocation nextline = (astContext->getSourceManager()).translateLineCol((astContext->getSourceManager()).getMainFileID(),
                            line_no_next, 1); // get the beginning of line line_no+1
      SourceRange srange(thisline, nextline);
      if (srange.isInvalid()){
        return true;
        }
        
      // Check if it is a bad line - do not edit
      string string_to_rewrite = string(Lexer::getSourceText(CharSourceRange::getTokenRange(srange), astContext->getSourceManager(),
                              astContext->getLangOpts(), 0));
      if (string_to_rewrite.empty() || GrayCUtils::is_bad_line(string_to_rewrite)) {
        return true;
        }
        
      // if (stmt->isAssignmentOp() && !isVisited) ==> then mutate
      CharSourceRange binop_range = CharSourceRange::getTokenRange(stmt->getBeginLoc(), stmt->getEndLoc());
      if (binop_range.isInvalid()){
        return true; // if no decl, exit
        }
        
      auto str_ref = Lexer::getSourceText(binop_range, astContext->getSourceManager(), astContext->getLangOpts());
      if (str_ref.empty()){
        return true; // if no decl, exit
        }
      
      string bstmt_str = string(str_ref);
      if (bstmt_str.empty()){
        return true; // if no decl, exit
        }
      if (GrayCUtils::getAssignmentNos(bstmt_str) > 1) {
        return true; // if got multiple assignement, return
        }
        
      expr_to_add.clear();
      collect_sub_expressions(stmt);
      if (expr_to_add.empty()){
        return true;
        }
        
      // Check if the expression is not too big
      unsigned expr_length = (GrayCCustomRandom::GetInstance()->rnd_dice() % _MUTATOR_EXPR_SIZE) + 1;
      if (expr_length < 1){
        return true;
        }  
      if ((expr_length + visited_node_IDs.size()) > _MUTATOR_MAX_EXPR_SIZE){
        return true; /* Limit the size of the expression we can create */
        }
        
      // Mutate
      string expr_append = bstmt_str + " + 42";
      for (unsigned i = 0; i < expr_length; i++){
        expr_append += " " + get_float_random_op() + " ((" + get_random_dtype() + ")(" + generate_random_expr() + "))";}
      reWriter->ReplaceText(stmt->getBeginLoc(), bstmt_str.length(), expr_append);
      //string reWritten = reWriter->getRewrittenText(CharSourceRange::getTokenRange(stmt->getBeginLoc(),stmt->getEndLoc()));
      //llvm::outs() << "binary expression\n"+ reWritten + "\n";
      return true;
    }
    else{
      return true;
    }
  }

  bool VisitStringLiteral(const StringLiteral *SL) {
    if(mutationChosen == "StringMutator"){
      if (!SL){
        return true;
      }

      StringRef slStrnRef = SL->getString();

      if((slStrnRef.find("%")) != string::npos){
        return true;
      }

      SourceLocation b_sloc = SL->getBeginLoc();
      SourceLocation e_sloc = SL->getEndLoc();
      if (b_sloc.isInvalid()){
        return true;
        }
      if (e_sloc.isInvalid()){
        return true;
        }

      unsigned int str_len = SL->getLength();

      string slStr = string(slStrnRef);

      if(pick_replace_or_append() == "replace"){
        int ascii_code = 48 + GrayCCustomRandom::GetInstance()->rnd_dice(126-48);
        char mutate_char = static_cast<char>(ascii_code);
        int mutate_index = GrayCCustomRandom::GetInstance()->rnd_dice(str_len);

        slStr[mutate_index] = mutate_char;
        string to_replace = "\"" + slStr + "\"";

        reWriter->ReplaceText(b_sloc, str_len+2, to_replace);
      }
      else{
        string to_append = "\"" + slStr + "appended by Bin2Wrong;\"";
        if(to_append.length() > __STRING_MUTATOR_STRN_MAX_LEN){
          return true;
        }
        reWriter->ReplaceText(b_sloc, str_len+2, to_append);
      }

      return true;
    }
    else{
      return true;
    }
  }

  string pick_replace_or_append() {
    return (GrayCCustomRandom::GetInstance()->rnd_yes_no(__STRING_MUTATOR_REP_OR_APP) ? "replace" : "append");
  }

  string mutate_constant_integers(string constant, int b_lower = 0, int b_upper = 0) {
    if (constant.empty()){
      return "-0";
      }
    
    bool is_array_sub_script = (b_lower < b_upper);
    
    if (is_array_sub_script){
      return to_string(GrayCCustomRandom::GetInstance()->rnd_dice(b_upper - b_lower) + b_lower);
    }
    
    if (GrayCCustomRandom::GetInstance()->rnd_yes_no(__CONSTANT_MUTATOR_INTEGER_EDITS_CONST)){
      return ((GrayCCustomRandom::GetInstance()->rnd_yes_no(__CONSTANT_MUTATOR_INTEGER_EDITS_CONST))
                ? bit_flip(constant) : sign_flip(constant));
                }
    else{
      return ((GrayCCustomRandom::GetInstance()->rnd_yes_no(__CONSTANT_MUTATOR_INTEGER_EDITS_CONST))
                ? replace2hex(constant.length()) : replace1char(constant));
    }
}


  // randomly choose 'break' or 'continue' for While of For statements in JumpMutator
  string pick_break_or_continue() {
    return (GrayCCustomRandom::GetInstance()->rnd_yes_no(0.5) ? "break" : "continue");
    }
  // Check if a constant is an array subscript in ConstantMutator
  bool isInArraySubsrcipt(const clang::Expr &expr) {
    const auto &parents = astContext->getParents(expr);
    if (parents.empty())
      return false;

    auto it = parents.begin();
    if (it->get<clang::ArraySubscriptExpr>())
      return true;

    const clang::Expr *aStmt = it->get<clang::Expr>();
    return (aStmt) ? isInArraySubsrcipt(*aStmt) : false;
  }

  // Guess the type of a constant in ConstantMutator
  cType guessType(string const_str, bool is_sign_flip = 0) {
    if (const_str.empty()){
      return cUChar;
    }
    
    if (const_str.compare("0") == 0) {
      return ((cType)(GrayCCustomRandom::GetInstance()->rnd_dice() % MAX_CONST_TYPE));
      }
      
    bool is_neg = (const_str.find("-") != string::npos);
    if (is_neg || is_sign_flip) {
      char *endptr;
      errno = 0;
      const char *nptr = const_str.c_str();
      long long number = strtoll(nptr, &endptr, 10);
      if ((number == 0) || (nptr == endptr) || (errno == EINVAL) || (errno == ERANGE)) {
        return cChar;
        }
        
      if ((numeric_limits<char>::min() <= number) && (numeric_limits<char>::max() >= number)){
        return cChar;
        }
      if ((numeric_limits<short>::min() <= number) && (numeric_limits<short>::max() >= number)){
        return cShort;
        }
      if ((numeric_limits<int>::min() <= number) && (numeric_limits<int>::max() >= number)){
        return cInt;
        }
      if ((numeric_limits<long>::min() <= number) && (numeric_limits<long>::max() >= number)){
        return cLong;
        }
      return cLongLong;
      }
    else {
      char *endptr;
      errno = 0;
      const char *nptr = const_str.c_str();
      unsigned long long number = strtoull(nptr, &endptr, 10);
      if ((number == 0) || (nptr == endptr) || (errno == EINVAL) || (errno == ERANGE)) {
        return cUChar;
        }
        
      if ((numeric_limits<unsigned char>::min() <= number) && (numeric_limits<unsigned char>::max() >= number)){
        return cUChar;
        }
      if ((numeric_limits<unsigned short>::min() <= number) && (numeric_limits<unsigned short>::max() >= number)){
        return cUShort;
        }
      if ((numeric_limits<unsigned int>::min() <= number) && (numeric_limits<unsigned int>::max() >= number)){
        return cUInt;
        }
      if ((numeric_limits<unsigned long>::min() <= number) && (numeric_limits<unsigned long>::max() >= number)){
        return cULong;
        }
      
      return cULongLong;
      }
    }

  bool is_number(const string &s){
    if(s.empty()){
      return false;
      }

    string::const_iterator it = s.begin();
    while(it != s.end() && (std::isdigit(*it) || (*it == '-') || (*it == '+'))){
      ++it;
    }
    return (!s.empty() && it == s.end());
  }

  char bit_flip_char(char constant){
    bitset<numeric_limits<char>::digits> bits(constant);
    unsigned bit_flip_location = GrayCCustomRandom::GetInstance()->rnd_dice(bits.size());
    return static_cast<char>(bits.flip(bit_flip_location).to_ulong());
    }
    
  unsigned char bit_flip_uchar(unsigned char constant){
    bitset<numeric_limits<unsigned char>::digits> bits(constant);
    unsigned bit_flip_location = GrayCCustomRandom::GetInstance()->rnd_dice(bits.size());
    return static_cast<unsigned char>(bits.flip(bit_flip_location).to_ulong());
    }
    
  short bit_flip_short(short constant){
    bitset<numeric_limits<short>::digits> bits(constant);
    unsigned bit_flip_location = GrayCCustomRandom::GetInstance()->rnd_dice(bits.size());
    return static_cast<short>(bits.flip(bit_flip_location).to_ulong());
   }
  unsigned short bit_flip_ushort(unsigned short constant){
    bitset<numeric_limits<unsigned short>::digits> bits(constant);
    unsigned bit_flip_location = GrayCCustomRandom::GetInstance()->rnd_dice(bits.size());
    return static_cast<unsigned short>(bits.flip(bit_flip_location).to_ulong());
    }
    
  int bit_flip_int(int constant){
    bitset<numeric_limits<int>::digits> bits(constant);
    unsigned bit_flip_location = GrayCCustomRandom::GetInstance()->rnd_dice(bits.size());
    return static_cast<int>(bits.flip(bit_flip_location).to_ulong());
    }
    
  unsigned bit_flip_uint(unsigned constant){
    bitset<numeric_limits<unsigned>::digits> bits(constant);
    unsigned bit_flip_location = GrayCCustomRandom::GetInstance()->rnd_dice(bits.size());
    return static_cast<unsigned>(bits.flip(bit_flip_location).to_ulong());
    }
      
  long bit_flip_long(long constant){
    bitset<numeric_limits<long>::digits> bits(constant);
    unsigned bit_flip_location = GrayCCustomRandom::GetInstance()->rnd_dice(bits.size());
    return static_cast<long>(bits.flip(bit_flip_location).to_ulong());
    }
      
  unsigned long bit_flip_ulong(unsigned long constant){
    bitset<numeric_limits<unsigned long>::digits> bits(constant);
    unsigned bit_flip_location = GrayCCustomRandom::GetInstance()->rnd_dice(bits.size());
    return (bits.flip(bit_flip_location).to_ulong());
    }
      
  long long bit_flip_long_long(long long constant){
    bitset<numeric_limits<long long>::digits> bits(constant);
    unsigned bit_flip_location = GrayCCustomRandom::GetInstance()->rnd_dice(bits.size());
    return static_cast<long long>(bits.flip(bit_flip_location).to_ulong());
    }
      
  unsigned long long bit_flip_ulong_long(unsigned long long constant){
    bitset<numeric_limits<unsigned long long>::digits> bits(constant);
    unsigned bit_flip_location = GrayCCustomRandom::GetInstance()->rnd_dice(bits.size());
    return static_cast<unsigned long long>(bits.flip(bit_flip_location).to_ulong());
    }
      
  string sign_flip(string constant){
    if (constant.empty()){
       return "-0";
       }
      
    char *endptr;
    errno = 0;
    long long number = strtoll(constant.c_str(), &endptr, 10);
    switch(guessType(constant, 1)){
      case cChar:
        return to_string(sign_flip_char(static_cast<char>(number)));
      case cShort:
        return to_string(sign_flip_short(static_cast<short>(number)));
      case cInt:
        return to_string(sign_flip_int(static_cast<int>(number)));
      case cLong:
        return to_string(sign_flip_long(static_cast<long>(number)));
      case cLongLong:
        return to_string(sign_flip_long_long(static_cast<long long>(number)));
      default:
        return constant;
        }
      }
      
  string bit_flip(string constant) {
    if(constant.empty()){
      return "-0";
      }
        
    cType t = guessType(constant);
    long long number = 0;
    unsigned long long unumber = 0;
    switch (t) {
      case cChar:
      case cShort:
      case cInt:
      case cLong:
      case cLongLong:
        char *endptr_0;
        errno = 0;
        number = strtoll(constant.c_str(), &endptr_0, 10);
        break;
      default:
        char *endptr_1;
        errno = 0;
        unumber = strtoll(constant.c_str(), &endptr_1, 10);
        }
    switch (t) {
      case cChar:
        return to_string(bit_flip_char(static_cast<char>(number)));
      case cShort:
        return to_string(bit_flip_short(static_cast<short>(number)));
      case cInt:
        return to_string(bit_flip_int(static_cast<int>(number)));
      case cLong:
        return to_string(bit_flip_long(static_cast<long>(number)));
      case cLongLong:
        return to_string(bit_flip_long_long(static_cast<long long>(number)));
      case cUChar:
        return to_string(bit_flip_uchar(static_cast<unsigned char>(unumber)));
      case cUShort:
        return to_string(bit_flip_ushort(static_cast<unsigned short>(unumber)));
      case cUInt:
        return to_string(bit_flip_uint(static_cast<unsigned>(unumber)));
      case cULong:
        return to_string(bit_flip_ulong(static_cast<unsigned long>(unumber)));
      case cULongLong:
        return to_string(bit_flip_ulong_long(static_cast<unsigned long long>(unumber)));
        }
      return constant;
      }
      
  string replace1char(string const_str) {
    if (const_str.empty()){
      return "-0";
      }
        
    static string dec_characters = "0123456789";
    unsigned len = const_str.length();
    for (unsigned i = 1; i < len; i++) {
      if (isdigit(const_str[i]) && GrayCCustomRandom::GetInstance()->rnd_yes_no(__CONSTANT_MUTATOR_FLIP_CHARS_CONST)){
        const_str[i] = dec_characters[GrayCCustomRandom::GetInstance()->rnd_dice(dec_characters.size())];
        return const_str;
        }
        }
    return const_str;
    }
      
  string replace2hex(unsigned length) {
    if (length < 1){
      return "0";
    }
      
    static string hex_characters = "0123456789ABCDEF";
    string rand_str = "0x";
    unsigned new_length = (length + GrayCCustomRandom::GetInstance()->rnd_dice(5)) % hex_characters.size();
    for (unsigned i = 0; i < new_length; i++){
      rand_str.append(hex_characters, GrayCCustomRandom::GetInstance()->rnd_dice(hex_characters.size()), 1);
    }
    return rand_str;
    }
      
  int mutate_constant_float() {
    return GrayCCustomRandom::GetInstance()->rnd_dice(10) + 1;
    }

  static char sign_flip_char(char constant) {
    return (~constant); }
  static short sign_flip_short(short constant) { 
    return (~constant); }
  static int sign_flip_int(int constant) { 
    return (~constant); }
  static long sign_flip_long(long constant) {
    return (~constant); }
  static long long sign_flip_long_long(long long constant) {
    return (~constant); }
   
  bool isInNestedAssignment(const Expr &expr) {
    auto it = astContext->getParents(expr).begin();
    if (it == astContext->getParents(expr).end()){
      return false;
      }

    const BinaryOperator *aDecl = it->get<BinaryOperator>();
    if (aDecl && aDecl->isAssignmentOp()){
      return false;
      }
      
    const Expr *aStmt = it->get<Expr>();
    if (!aStmt){
      return false;
      }

    aStmt = aStmt->IgnoreImpCasts();
    if (aStmt){
      return isInNestedAssignment(*aStmt);
      }

    return false;
}

  string pick_delete_or_duplicate() {
    return (GrayCCustomRandom::GetInstance()->rnd_yes_no(__DUPLICATE_MUTATOR_DUP_OR_DEL) ? "duplicate" : "delete");
  }

  string generate_random_expr() {
    string expr_lhs = expr_to_add[GrayCCustomRandom::GetInstance()->rnd_dice() % expr_to_add.size()];
    string expr_rhs = expr_to_add[GrayCCustomRandom::GetInstance()->rnd_dice() % expr_to_add.size()];
    bool lhs_pointer = (expr_lhs.find("*") != string::npos) || (expr_lhs.find("[") != string::npos);
    bool rhs_pointer = (expr_rhs.find("*") != string::npos) || (expr_rhs.find("[") != string::npos);
    string random_expr = (GrayCCustomRandom::GetInstance()->rnd_yes_no(0.5) && !lhs_pointer && !rhs_pointer)
          ? "((double)(" + expr_lhs + ")) " + get_float_random_op() + " ((double)(" + expr_rhs + "))"
          : "((int)(" + expr_lhs + ")) " + get_int_random_op() + " ((int)(" + expr_rhs + "))";
    return ("(" + random_expr + ")");
    }

  string get_float_random_op() {
    return (float_operator_bank[GrayCCustomRandom::GetInstance()->rnd_dice() % _MUTATOR_FLOAT_OP_SIZE]);
    }
    
  string get_int_random_op() {
    return (int_operator_bank[GrayCCustomRandom::GetInstance()->rnd_dice() % _MUTATOR_INT_OP_SIZE]);
    }
  
  string get_random_dtype() {
    return (data_types[GrayCCustomRandom::GetInstance()->rnd_dice() % _MUTATOR_DATA_TYPE_SIZE]);
    }

  void collect_sub_expressions(BinaryOperator *stmt) {
    if (!stmt){
      return;
      }
    
    CharSourceRange stmt_range = CharSourceRange::getTokenRange(stmt->getBeginLoc(), stmt->getEndLoc());
    if (stmt_range.isInvalid()){
      return;
      }
    
    if (reWriter->getRangeSize(stmt_range) > __EXPRESSION_MUTATOR_EXPR_MAX_LEN){
      return;
      }
      
    if (!stmt->isCommaOp() && !stmt->isPtrMemOp()) {
      Expr *sub_expr_l = stmt->getLHS();
      if (!sub_expr_l){
        return;
        }
        
      Expr *sub_expr_r = stmt->getRHS();
      if (!sub_expr_r){
        return;
        }
        
      Stmt *sub_stmt = cast<Stmt>(stmt);
      if (!sub_stmt){
        return;
        }
        
      CharSourceRange sub_declRange_r = CharSourceRange::getTokenRange(sub_expr_r->getBeginLoc(), sub_expr_r->getEndLoc());
      if (sub_declRange_r.isInvalid()){
        return;
        }
        
      auto str_ref = Lexer::getSourceText(sub_declRange_r, astContext->getSourceManager(), astContext->getLangOpts());
      if (str_ref.empty()){
        return;
        }
        
      string sub_decl_str_r = string(str_ref);
      if (sub_decl_str_r.empty()){
        return;
        }
        
      CharSourceRange sub_declRange_l = CharSourceRange::getTokenRange(sub_expr_l->getBeginLoc(), sub_expr_l->getEndLoc());
      if (sub_declRange_l.isInvalid()){
        return;
        }
        
      str_ref = Lexer::getSourceText(sub_declRange_l, astContext->getSourceManager(), astContext->getLangOpts());
      if (str_ref.empty()){
        return;
        }
        
      string sub_decl_str_l = string(str_ref);
      if (sub_decl_str_r.empty()){
        return;
        }
        
      bool is_rhs_arithmetic = sub_expr_r->getType()->isArithmeticType();
      if (is_rhs_arithmetic) {
        if (sub_decl_str_r.empty()){
          return;
          }
        expr_to_add.push_back(sub_decl_str_r);
        }
        
      bool is_lhs_arithmetic = sub_expr_l->getType()->isArithmeticType();
      if (is_lhs_arithmetic) {
        if (sub_decl_str_l.empty()){
          return;
          }
        expr_to_add.push_back(sub_decl_str_l);
        }
        
      for (Stmt::child_iterator j_se = sub_stmt->child_begin(), e = sub_stmt->child_end(); j_se != e; ++j_se) {
        Stmt *currStmt = *j_se;
        // Deal with nested call expressions within binary operators on the RHS expression.
        if (isa<BinaryOperator>(currStmt)) {
          BinaryOperator *sub_bop = cast<BinaryOperator>(currStmt);
          int node_id_args = (sub_bop)->getID(*astContext);
          visited_node_IDs.push_back(node_id_args);
          collect_sub_expressions(sub_bop);
        }
      }
  }
}


};

class CodeMutatorsConsumer : public clang::ASTConsumer {
private:
  CodeMutatorsVisitor *Visitor;

public:
  explicit CodeMutatorsConsumer(ASTContext *context, Rewriter *rewriter)
    : Visitor(new CodeMutatorsVisitor(context, rewriter)) {}

  virtual void HandleTranslationUnit(clang::ASTContext &Context) override{
    Visitor->TraverseDecl(Context.getTranslationUnitDecl());
  }

  virtual ~CodeMutatorsConsumer() {delete Visitor;}
};

class CodeMutatorsAction : public clang::ASTFrontendAction {
private:
    Rewriter *reWriter = new Rewriter();
    ASTContext *astContext = 0;
public:
  virtual std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
    clang::CompilerInstance &Compiler, llvm::StringRef InFile) override{
        astContext = (&(Compiler.getASTContext()));
        return std::make_unique<CodeMutatorsConsumer>(astContext, reWriter);
  }

  virtual ~CodeMutatorsAction() {
    delete reWriter;
    astContext = 0;
  }

  void EndSourceFileAction() override{
    SourceManager &SM = reWriter->getSourceMgr();

    auto rewrittenBuffer = reWriter->getRewriteBufferFor(SM.getMainFileID());
    if(rewrittenBuffer){
      gotRewritten = true;
      reWrittenStr = string(rewrittenBuffer->begin(), rewrittenBuffer->end());
    }
    else{
    }
  }
};

extern "C"{
  void src_code_mutation(uint8_t *buf, size_t buf_size, char *pointer){
    string data = (char *)buf;
    if(data.length() > buf_size){
      data = data.substr(0, buf_size);
    }

    // Generate the seed for GrayCCustomRandom
    mt19937_64 rng(std::random_device{}());
    uniform_int_distribution<unsigned long> distribution(0, std::numeric_limits<unsigned long>::max());
    unsigned long Seed = distribution(rng);

    GrayCCustomRandom::CreateInstance(Seed, _mutator_options.size());
    mutationChosen =_mutator_options[GrayCCustomRandom::GetInstance()->rnd_dice()];
    GrayCCustomRandom::DeleteInstance(Seed);

    GrayCCustomRandom::CreateInstance(Seed, 6);
    const vector<string> no_warning_flag = {"--no-warnings", "-x", "c", "-I/usr/local/lib/clang/18/include/", "-I/usr/local/include/", "-I/usr/lib/gcc/x86_64-linux-gnu/11/include/", "-I/usr/include/x86_64-linux-gnu/", "-I/usr/include/", "-I/usr/include/linux"};
    clang::tooling::runToolOnCodeWithArgs(std::make_unique<CodeMutatorsAction>(), data, no_warning_flag);
    GrayCCustomRandom::DeleteInstance(Seed);

    if(gotRewritten == true){
      size_t reWrittenLen = reWrittenStr.length();
      strncpy(pointer, reWrittenStr.c_str(), reWrittenLen);
      if(strlen(pointer) > reWrittenLen){
        pointer[reWrittenLen] = '\0';
      }
    }
    else{
      size_t dataLen = data.length();
      strncpy(pointer, data.c_str(), dataLen);
      if(strlen(pointer) > dataLen){
        pointer[dataLen] = '\0';
      }
    }
  }
}