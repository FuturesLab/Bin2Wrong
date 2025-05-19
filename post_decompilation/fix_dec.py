import sys

sys.path.append('../post_decompilation/')
from processors import *
from post_utils import status

def read_file(file_name):
    f = open(file_name)
    if f:
        txt = f.read()
        f.close()
        return txt
    return ''

def save_file(file_name, code):
    with open(file_name, "w") as file:
        file.write(code)

def replace_function(orig_code_path, dec_default_code_path, fixed_code_path, decompiler, compiler, target_func=''):

    orig_code = read_file(orig_code_path)
    dec_code = read_file(dec_default_code_path)

    if dec_code == '':
        return status.NODEC
    
    if decompiler == 'retdec':
        dec_code = Retdec_pre_process(dec_code, compiler, target_func)
    elif decompiler == 'r2ghidra':
        dec_code = R2ghidra_pre_process(dec_code, compiler, target_func)
    elif decompiler == 'reko':
        dec_code, global_code = Reko_pre_process(dec_code, compiler, target_func)
    elif decompiler == 'relyze':
        dec_code = Relyze_pre_process(dec_code, compiler, target_func)
    elif decompiler == 'revng':
        dec_code = Revng_pre_process(dec_code, compiler, target_func)
    elif decompiler == 'bn':
        dec_code = Binaryninja_pre_process(dec_code, compiler, target_func)
    elif decompiler == 'angr':
        dec_code = Angr_pre_process(dec_code, compiler, target_func)
    else:
        print('decompiler not supported, edit modifiers and processors')
        return status.ERROR

    orig_decl_start, orig_decl_end, orig_end_pos, dec_decl_start, dec_decl_end, dec_end_pos = get_target_pos(orig_code, dec_code, target_func)
    target_code = dec_code[dec_decl_start:dec_end_pos]
    pos = dec_decl_end - dec_decl_start
    
    if decompiler == 'retdec':
        target_code = Retdec_post_process(target_code, pos, compiler)
    elif decompiler == 'r2ghidra':
        target_code = R2ghidra_post_process(target_code, pos, compiler)
    elif decompiler == 'reko':
        target_code = Reko_post_process(target_code, pos, compiler, global_code)
    elif decompiler == 'relyze':
        target_code = Relyze_post_process(target_code, pos, compiler)
    elif decompiler == 'revng':
        target_code = Revng_post_process(target_code, pos, compiler)
    elif decompiler == 'bn':
        target_code = Binaryninja_post_process(target_code, pos, compiler)
    elif decompiler == 'angr':
        target_code = Angr_post_process(target_code, pos, compiler)
    else:
        print('decompiler not supported, edit modifiers and processors')
        return status.ERROR

    fixed_code = orig_code[0:orig_decl_start] + target_code + orig_code[orig_end_pos:]
    save_file(fixed_code_path, fixed_code)
    return status.OKAY

if __name__ == '__main__':

    replace_function(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], "func_1")
