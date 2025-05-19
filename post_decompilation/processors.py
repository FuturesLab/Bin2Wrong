import re
from modifiers import *

def get_target_pos(orig_code, dec_code, target_func):

    orig_target_decl = find_fun_with_name(orig_code, target_func)
    orig_decl_start = orig_target_decl.start()
    orig_decl_end = orig_target_decl.end()
    if orig_code[orig_decl_end - 1] == '{':
        orig_end_pos = find_function_body(orig_code, orig_decl_end)
    
    dec_target_decl = find_fun_with_name(dec_code, target_func)
    dec_decl_start = dec_target_decl.start()
    dec_decl_end = dec_target_decl.end()

    if dec_code[dec_decl_end - 1] == '{':
        dec_end_pos = find_function_body(dec_code, dec_decl_end)

    return orig_decl_start, orig_decl_end, orig_end_pos, dec_decl_start, dec_decl_end, dec_end_pos

def Retdec_pre_process(code, compiler='', func=''):
    if 'msvc' in compiler or 'MSVC' in compiler: 
        code = RetdecModifier.modifyMsvcDec(code, orig_num_funcs=3, target_func_ordi=2, target_func_name=func)

    code = RetdecModifier.fix_target_func_code(code, func)
    code = RetdecModifier.rename_func(code, 'set_var')
    code = RetdecModifier.fix_func_names(code, ['func_1', 'set_var', 'printf'])

    return code

def Retdec_post_process(code, pos, compiler=''):
    code = RetdecModifier.add_extern(code, pos)

    code = RetdecModifier.rename_str(code, compiler)
    code = RetdecModifier.rename_int(code, compiler)
    code = RetdecModifier.rename_short(code, compiler)
    code = RetdecModifier.rename_long(code, compiler)
    code = RetdecModifier.fix_printf(code, compiler, mark='printf("%s")')
    #code = RetdecModifier.fix_printf(code, compiler, mark='__printf_chk(')
    #code = code.replace('__printf_chk(1, "%s"', 'printf("%s"')
    code = RetdecModifier.fix_printf(code, compiler, mark='printf("%s", g')
    code = RetdecModifier.fix_printf(code, compiler, mark='printf("%s", v')
    code = RetdecModifier.fix_printf(code, compiler, mark='printf("%s", (char *)*(int64_t *)g')
    code = RetdecModifier.fix_printf(code, compiler, mark='printf("%s", (int64_t)')
    code = RetdecModifier.fix_asm(code)
    code = RetdecModifier.delete_lines(code, '__asm_pxor')
    code = RetdecModifier.delete_lines(code, '__asm_stmxcsr')
    code = RetdecModifier.delete_lines(code, '__asm_ldmxcsr')
    code = RetdecModifier.delete_lines(code, 'OUTLINED_FUNCTION_0();')
    #code = RetdecModifier.delete_lines(code, '__asm_lfence(')
    #code = RetdecModifier.fix_glb_var_types(code, compiler)
    code = RetdecModifier.fix_func_args(code, func='func_1')
    code = code.replace('true', '1')

    return code

def R2ghidra_pre_process(code, compiler='', func=''):
    code = code.replace('unkint3', 'int')
    code = R2ghidraModifier.delete_lines(code, '__x86.')
    code = code.replace('CONCAT31', '')
    #code = R2ghidraModifier.delete_lines(code, 'CONCAT')
    code = code.replace('ZEXT14', '')
    code = code.replace('SEXT14', '')
    code = code.replace('SEXT24', '')
    code = code.replace('SUB41', '')
    #code = code.replace('SBORROW4', '')
    code = R2ghidraModifier.delete_lines(code, 'ZEXT')
    code = R2ghidraModifier.delete_lines(code, 'SEXT')
    code = R2ghidraModifier.delete_lines(code, 'SUB')
    #code = R2ghidraModifier.delete_lines(code, 'SBORROW')
    code = R2ghidraModifier.delete_lines(code, '// WARNING')
    code = R2ghidraModifier.delete_lines(code, '// signed')
    code = R2ghidraModifier.delete_lines(code, "*(&stack")

    code = R2ghidraModifier.modify_sym(code)
    code = R2ghidraModifier.modify_undefined(code, 'undefined4')
    code = R2ghidraModifier.modify_undefined(code, 'undefined2')
    code = R2ghidraModifier.modify_undefined(code, 'undefined')

    code = code.replace('bool', 'int')
    code = code.replace('true', '1')
    code = code.replace('false', '0')
    code = re.sub(r"\.\s*_[0-9]_[0-9]_", '', code)

    code = R2ghidraModifier.fix_target_func_name(code, func)
    code = R2ghidraModifier.fix_target_func_code(code, func)

    code = R2ghidraModifier.fix_func_names(code, ['func_1', 'set_var', 'printf'])

    code = R2ghidraModifier.fix_func_args(code, func)
    return code

def R2ghidra_post_process(code, pos, compiler=''):
    code = R2ghidraModifier.add_extern(code, pos)

    code = code.replace('_obj.', '')
    code = code.replace('imp.', '')
    code = code.replace('(*_reloc.printf)', 'printf')
    code = code.replace('*_reloc.', '')
    code = R2ghidraModifier.fix_str(code, compiler)
    code = R2ghidraModifier.fix_printf(code, compiler)
    code = R2ghidraModifier.fix_printf_2(code, compiler)
    code = R2ghidraModifier.fix_func(code, 'set_var')
    code = R2ghidraModifier.rename_func(code, 'set_var')
    code = R2ghidraModifier.delete_lines(code, '*0x')
    code = code.replace('true', '1')

    return code

def Reko_pre_process(code, compiler='', func=''):
    if 'msvc' in compiler or 'MSVC' in compiler: 
        code = RekoModifier.modifyMsvcDec(code, orig_num_funcs=3, target_func_ordi=2, target_func_name=func)
    code = RekoModifier.fix_target_func_code(code, func)
    code = RekoModifier.rename_func(code, 'set_var')
    global_code = RekoModifier.find_global_code(code, "//GLOBAL")

    return code, global_code

def Reko_post_process(code, pos, compiler='', global_code=''):
    code = RekoModifier.add_extern(code, pos, global_code)
    code = RekoModifier.fix_printf(code, compiler)
    code = code.replace('*s 0x', '* 0x')
    code = code.replace('true', '1')
    return code

def Relyze_pre_process(code, compiler='', func=''):
    if 'msvc' in compiler or 'MSVC' in compiler: 
        code = RelyzeModifier.modifyMsvcDec(code, orig_num_funcs=3, target_func_ordi=2, target_func_name=func)
    code = code.replace('__cdecl ', '')
    code = RelyzeModifier.fix_target_func_code(code, func)
    code = RelyzeModifier.fix_vars(code)

    return code

def Relyze_post_process(code, pos, compiler=''):
    #code = RelyzeModifier.add_extern(code, pos)
    code = RelyzeModifier.fix_printf(code)
    code = RelyzeModifier.fix_glbl_str(code, compiler)
    code = RelyzeModifier.fix_glbl_vars(code, compiler)
    code = RelyzeModifier.delete_lines(code, '__lfence();')
    code = RelyzeModifier.delete_lines(code, 'OUTLINED_FUNCTION_1')
    code = code.replace('true', '1')
    
    return code

def Binaryninja_pre_process(code, compiler='', func=''):
    if 'msvc' in compiler or 'MSVC' in compiler: 
        code = BinaryninjaModifier.modifyMsvcDec(code, orig_num_funcs=3, target_func_ordi=2, target_func_name=func)
    code = BinaryninjaModifier.fix_target_func_code(code, func)
    code = BinaryninjaModifier.fix_func_names(code, ['func_1', 'set_var', 'printf'])
    code = BinaryninjaModifier.fix_var_names(code, ['i', 's', 'l', 'str'])
    return code

def Binaryninja_post_process(code, pos, compiler=''):
    code = BinaryninjaModifier.add_extern(code, pos)
    code = BinaryninjaModifier.fix_local_str_type(code, compiler)
    code = BinaryninjaModifier.fix_str(code, compiler)
    code = BinaryninjaModifier.fix_printf(code, compiler)
    code = BinaryninjaModifier.rename_func(code, 'set_var')
    code = BinaryninjaModifier.fix_faulty_ptr(code, compiler)
    #code = code.replace('void* const', 'int')
    code = code.replace('true', '1')

    return code

def Revng_pre_process(code, compiler='' ,func=''):
    if 'msvc' in compiler or 'MSVC' in compiler: 
        code = RevngModifier.modifyMsvcDec(code, orig_num_funcs=3, target_func_ordi=2, target_func_name=func)
    code = RevngModifier.fix_target_func_code(code, func)
    #code = AngrModifier.fix_target_func_code(code, func)
    #code = AngrModifier.fix_func_args(code, func)
    #code = AngrModifier.rename_func(code, 'set_var')
    #print(code)
    code = RevngModifier.fix_struct(code, compiler)
    code = RevngModifier.rename_func(code, 'set_var')
    
    return code

def Revng_post_process(code, pos, compiler=''):
    #print(code)
    code = RevngModifier.fix_struct(code, compiler)
    code = RevngModifier.fix_str(code, compiler)
    code = RevngModifier.add_extern(code, pos, compiler)
    code = RevngModifier.fix_printf(code, compiler)
    code = RevngModifier.fix_setvar_args(code)
    code = code.replace('true', '1')
    #print(code)

    #code = AngrModifier.fix_local_str_type(code)
    #code = AngrModifier.fix_printf(code, compiler)
    return code


def Angr_pre_process(code, compiler='' ,func=''):
    if 'msvc' in compiler or 'MSVC' in compiler: 
        code = AngrModifier.modifyMsvcDec(code, orig_num_funcs=3, target_func_ordi=2, target_func_name=func)
    code = AngrModifier.fix_target_func_code(code, func)
    code = AngrModifier.fix_func_args(code, func)
    code = AngrModifier.rename_func(code, 'set_var')
    return code

def Angr_post_process(code, pos, compiler=''):
    code = AngrModifier.add_extern(code, pos, compiler)

    code = AngrModifier.fix_local_str_type(code)
    code = AngrModifier.fix_printf(code, compiler)
    code = AngrModifier.delete_lines(code, '[D] MBusEvent-Imbe_Fence')
    code = AngrModifier.delete_lines(code, 'OUTLINED_FUNCTION_0();')
    code = code.replace('true', '1')
    return code