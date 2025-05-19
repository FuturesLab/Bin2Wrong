import os
import sys
from typing import List

import angr
from angr.analyses import CFGFast, Decompiler
from angr.knowledge_plugins import Function

import warnings
warnings.filterwarnings('ignore')

def save_to_file(txt, path):

    with open(path, 'w') as file:
        file.write(txt)

def decompile(t, path=str(os.environ.get('DECOM_CODE_PATH')), target_func="func_1"):

    p = angr.Project(t, auto_load_libs=False, load_debug_info=False)
    cfg: CFGFast = p.analyses.CFGFast(
        normalize=True,
        resolve_indirect_jumps=True,
        data_references=True,
    )
    p.analyses.CompleteCallingConventions(
        cfg=cfg.model, recover_variables=True, analyze_callsites=True
    )

    ret_code = ''
    func_names = []

    funcs_to_decompile: List[Function] = [
        func
        for func in cfg.functions.values()
        if not func.is_plt and not func.is_simprocedure and not func.alignment
    ]

    for func in funcs_to_decompile:
        func_names.append(func.name)
        try:
            decompiler: Decompiler = p.analyses.Decompiler(func, cfg=cfg.model)

            if decompiler.codegen is None:
                if func.name != target_func:
                    ret_code += """
void """+func.name+"""(){
    // None
    }
            """
                else:
                    ret_code = ""
                    break
            else:
                ret_code += decompiler.codegen.text
            
        except Exception as e:
            if func.name != target_func:
                ret_code += """\nvoid """+func.name+"""(){\n\t// Exception thrown: """+str(e)+"""\n\t\n}"""
            else:
                ret_code = ""

    save_to_file(ret_code, path)


if __name__ == "__main__":

    if len(sys.argv) == 2:
        decompile(sys.argv[1])
    elif len(sys.argv) == 3:
        decompile(sys.argv[1], sys.argv[2])
    elif len(sys.argv) == 4:
        decompile(sys.argv[1], sys.argv[2], sys.argv[3])