import os
import subprocess
import random
from timeout_decorator import timeout
import shutil
import time

from post_utils import *
from fix_dec import replace_function, read_file
from get_dec_code import *
from enhanCer import add_state_tracking

def init(seed):
    random.seed(seed)

def deinit():
    pass

# compile the decompiled code
def comp_decomp(comp_log_file, target_code, target_exec, used_flags, compiler_chosen, decompiler, result_folder, win2lin, msvcinc, msvclib, dec_lib):
    if 'msvc' in compiler_chosen or 'MSVC' in compiler_chosen:
        orig_dir = os.getcwd()
        os.chdir(result_folder)

        dec_compile_cmd = '(timeout 30s ' + win2lin + ' ' + used_flags + ' '
        dec_compile_cmd += os.path.basename(target_code) + ' ' + msvcinc + ' ' + msvclib
        if dec_lib != '':
            dec_compile_cmd += ' Z:' + dec_lib + '.obj'
        dec_compile_cmd += ')'

        with open(comp_log_file,'w') as f:
            subprocess.call(dec_compile_cmd, shell=True, stderr=f, stdout=f)

        os.chdir(orig_dir)

    elif compiler_chosen == "o64-clang":
        dec_compile_cmd = 'timeout 15s ' + used_flags + ' '
        if dec_lib != '':
            dec_compile_cmd += dec_lib + '_macho.o '
            
        dec_compile_cmd += target_code + ' -o ' + target_exec
        with open(comp_log_file,'w') as f:
            subprocess.call(dec_compile_cmd, shell=True, stderr=f, stdout=f)

    else:
        dec_compile_cmd = 'timeout 15s ' + used_flags + ' '
        if dec_lib != '':
            dec_compile_cmd += dec_lib + '.o '
            
        dec_compile_cmd += target_code + ' -o ' + target_exec

        if decompiler == 'bn':
            dec_compile_cmd += ' -lm'

        with open(comp_log_file,'w') as f:
            subprocess.call(dec_compile_cmd, shell=True, stderr=f, stdout=f)

# run instrumented code and return its output
@timeout(30)
def run_state_exec(file_path, exec_type, win2lin=None):
    if exec_type == 'PE':
        try:
            disable_fixme_env = os.environ.copy()
            disable_fixme_env["WINEDEBUG"] = "fixme-all" 
            ret = subprocess.run([win2lin, file_path], env=disable_fixme_env, stdout=subprocess.PIPE, timeout=28)
        except subprocess.TimeoutExpired:
            ret = None
        except Exception as e:
            ret = None

    elif exec_type == 'Mach-O':
        try:
            ret = subprocess.run(['darling', 'shell', '/Volumes/SystemRoot'+file_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=28)
        except subprocess.TimeoutExpired:
            ret = None
        except Exception as e:
            ret = None

    else:
        try:
            ret = subprocess.run(file_path, stdout=subprocess.PIPE, timeout=28)
        except subprocess.TimeoutExpired:
            ret = None
        except Exception as e:
            ret = None
    return ret
       
def post_run():
    ret = 0
    try:
        ret = post_dec()
    except Exception as e:
        #print(f"An error occurred in post_dec.py: {e}")
        pass
    return ret

# function to patch and instrument decompiled code, and compare its execution result with the original instrumented program
# if divergent, return `1` to `fuzz_run_target()` in AFLplusplus/src/afl-fuzz-run.c, which will mark the testcase as CRASH
@timeout(70)
def post_dec():

    current_timestamp = str(time.time())
    
    csmith = str(os.environ.get('CSMITH_RUNTIME'))
    gnu = " " + str(os.environ.get('GNU'))
    msvc = str(os.environ.get('MSVC'))

    msvcinc = str(os.environ.get('MSVCINC'))
    msvclib = str(os.environ.get('MSVCLIB'))
    win2lin = str(os.environ.get('WIN2LIN'))

    flags_path = str(os.environ.get('USED_FLAGS_PATH'))

    decompiler = str(os.environ.get('DECOMPILER'))
    dec_lib = str(os.environ.get('DECLIB'))

    tmp_folder = str(os.environ.get('TMP_FOLDER'))

    orig = c_code()
    dec = c_code()

    orig.c_code = str(os.environ.get('ORIGINAL_CODE_PATH'))
    orig.c_exec = str(os.environ.get('ORIGINAL_EXEC_PATH'))
    orig.state_code = os.path.join(tmp_folder, "orig_state.c")
    orig.state_exec = os.path.join(tmp_folder, "orig_state_exec")

    dec.dec_default_code = str(os.environ.get('DECOM_CODE_PATH'))
    dec.c_code = str(os.environ.get('DECOM_CODE_FIXED_PATH'))
    dec.state_code = os.path.join(tmp_folder, "dec_state.c")
    dec.state_exec = os.path.join(tmp_folder, "dec_state_exec")

    dec_non_patched_exec = os.path.join(tmp_folder, "dec_no_patch_exec")

    dec.c_exec = tmp_folder + "/dec_exec"

    afl_out_dir = str(os.environ.get('AFLOUTPUT'))

    recomp_fail_folder = os.path.join(afl_out_dir, "recomp_fail")
    if os.path.exists(recomp_fail_folder) == False:
        os.makedirs(recomp_fail_folder)
    
    gen_code_log = os.path.join(afl_out_dir, "gen_code.log")
    gen_programs_log = os.path.join(afl_out_dir, "gen_programs.log")
    decomp_log = os.path.join(afl_out_dir, "decomp.log")
    patched_recomp_fail_folder = os.path.join(afl_out_dir, "patched_recomp_fail")
    if os.path.exists(patched_recomp_fail_folder) == False:
        os.makedirs(patched_recomp_fail_folder)
    divergent_log = os.path.join(afl_out_dir, "div.log")

    if decompiler == 'angr':
        f = open(dec.dec_default_code)
        if f:
            txt = f.read()
            f.close()
            if "args' length must all be equal" in txt:
                clear_dir(tmp_folder)
                return 0
    elif decompiler == 'reko':
        reko(orig.c_exec, dec.dec_default_code)
    elif decompiler == 'revng':
        ptml_path = tmp_folder + "/dec.ptml"
        if os.path.exists(ptml_path) == False:
            clear_dir(tmp_folder)
            return 0
        revng_artifact_path = str(os.environ.get('REVNG_ARTIFACT_PATH'))
        if revng_artifact_path != '' and (os.path.exists(dec.dec_default_code) == False):
            revng(ptml_path, revng_artifact_path, dec.dec_default_code)
    
    if (os.path.exists(flags_path)):
        with open(flags_path, 'r') as flags_file:
            used_flags = flags_file.read()
    else:
        clear_dir(tmp_folder)
        return 0
    
    if (os.path.exists(orig.c_code)) == False:
        clear_dir(tmp_folder)
        return 0
    else:
        with open(gen_code_log, "a") as gen_code_log_f:
            gen_code_log_f.write("Source code is generated at {}.\n".format(current_timestamp))
    
    if (os.path.exists(orig.c_exec)) == False:
        clear_dir(tmp_folder)
        return 0
    else:
        with open(gen_programs_log, "a") as gen_log_f:
            gen_log_f.write("A program is generated at {}.\n".format(current_timestamp))

    if (os.path.exists(dec.dec_default_code) == False):
        clear_dir(tmp_folder)
        return 0
    elif (read_file(dec.dec_default_code) == ''):
        clear_dir(tmp_folder)
        return 0
    
    else:
        with open(decomp_log, "a") as decomp_log_f:
            decomp_log_f.write("A program is decompiled at {}.\n".format(current_timestamp))
    
    compiler_chosen = used_flags.split(maxsplit=1)[0]

    extern_lib = ''
    if compiler_chosen == "tcc":
        extern_lib = csmith + "../tcc.o"
    elif "msvc" in compiler_chosen or "MSVC" in compiler_chosen:
        orig.c_exec = orig.c_exec.replace('_exec', '.exe')
        dec.c_exec = dec.c_exec.replace('_exec', '.exe')
        orig.state_exec = orig.state_exec.replace('_exec', '.exe')
        dec.state_exec = dec.state_exec.replace('_exec', '.exe')

    # apply recompilation syntax patching to decompiled code
    try:
        fix_dec_code = replace_function(orig.c_code, dec.dec_default_code, dec.c_code, decompiler, compiler_chosen, 'func_1')
    except:
        clear_dir(tmp_folder)
        return 0

    if fix_dec_code != status.OKAY:
        clear_dir(tmp_folder)
        return 0
    if os.path.exists(dec.c_code) != True:
        clear_dir(tmp_folder)
        return 0
    
    patched_log_file = os.path.join(tmp_folder, "patched.log")
    non_patched_log_file = os.path.join(tmp_folder, "non_patched.log")
    
    comp_decomp(non_patched_log_file, dec.dec_default_code, dec_non_patched_exec, used_flags, compiler_chosen, decompiler, tmp_folder, win2lin, msvcinc, msvclib, dec_lib)
    comp_decomp(patched_log_file, dec.c_code, dec.c_exec, used_flags, compiler_chosen, decompiler, tmp_folder, win2lin, msvcinc, msvclib, dec_lib)
    
    cur_testcase_1 = afl_out_dir + "/default/.cur_input"
    cur_testcase_2 = afl_out_dir + ".cur_input"

    if os.path.exists(dec_non_patched_exec) != True:
        if os.path.exists(cur_testcase_1):
            shutil.copy2(cur_testcase_1, recomp_fail_folder+"/"+current_timestamp)
        if os.path.exists(cur_testcase_2):
            shutil.copy2(cur_testcase_2, recomp_fail_folder+"/"+current_timestamp)

    if os.path.exists(dec.c_exec) != True:
        shutil.copy2(patched_log_file, patched_recomp_fail_folder+"/"+current_timestamp)
        clear_dir(tmp_folder)
        return 0
    
    codes = [orig, dec]
    for i in range(2):

        # instrument code with state-tracking code
        enhancer_status = add_state_tracking(codes[i].c_code, codes[i].state_code, " -I"+csmith+" -I"+gnu)
        if enhancer_status != status.OKAY:
            clear_dir(tmp_folder)
            return 0
        
        if 'msvc' in compiler_chosen or 'MSVC' in compiler_chosen:

            orig_dir = os.getcwd()
            os.chdir(tmp_folder)

            codes[i].comp_state_cmd = '(timeout 30s ' + win2lin + ' ' + used_flags + ' '
            codes[i].comp_state_cmd += os.path.basename(codes[i].state_code) + ' ' + msvcinc + ' /I ' + csmith + ' ' + msvclib
            if i == 1 and dec_lib != '':
                codes[i].comp_state_cmd += ' Z:' + dec_lib + '.obj'
            codes[i].comp_state_cmd += ') > /dev/null 2>&1'

            codes[i].comp_state_status = os.system(codes[i].comp_state_cmd)
            os.chdir(orig_dir)
            if os.path.exists(codes[i].state_exec) != True:
                clear_dir(tmp_folder)
                return 0

            codes[i].subprocess_ret = run_state_exec(codes[i].state_exec, 'PE', win2lin)
        
        elif compiler_chosen == "o64-clang":

            codes[i].comp_state_cmd = 'timeout 15s ' + used_flags + ' '
            if i == 1 and dec_lib != '':
                codes[i].comp_state_cmd += dec_lib + '_macho.o '
            
            codes[i].comp_state_cmd += codes[i].state_code + ' ' + extern_lib + ' -o ' + codes[i].state_exec + ' -I' + csmith + ' > /dev/null 2>&1'
            codes[i].comp_state_status = os.system(codes[i].comp_state_cmd)
            if os.path.exists(codes[i].state_exec) != True:
                clear_dir(tmp_folder)
                return 0

            codes[i].subprocess_ret = run_state_exec(codes[i].state_exec, 'Mach-O')

        else:

            codes[i].comp_state_cmd = 'timeout 15s ' + used_flags + ' '
            if i == 1 and dec_lib != '':
                codes[i].comp_state_cmd += dec_lib + '.o '
            
            codes[i].comp_state_cmd += codes[i].state_code + ' ' + extern_lib + ' -o ' + codes[i].state_exec + ' -I' + csmith + ' > /dev/null 2>&1'
            codes[i].comp_state_status = os.system(codes[i].comp_state_cmd)
            if os.path.exists(codes[i].state_exec) != True:
                clear_dir(tmp_folder)
                return 0

            codes[i].subprocess_ret = run_state_exec(codes[i].state_exec, 'ELF')
        
        if codes[i].subprocess_ret == None:
            clear_dir(tmp_folder)
            return 0
        
        if codes[i].subprocess_ret.returncode != 0:
            clear_dir(tmp_folder)
            return 0
        else:
            codes[i].exec_result = codes[i].subprocess_ret.stdout
            codes[i].exec_result_str = rm_result_mark(codes[i].exec_result.decode())
            codes[i].exec_result_checksum = get_checksum(codes[i].exec_result_str)
    
    # compare the execution output between decompiled code and original code
    # if there is divergence between the checksums, mark the test case as crash
    if orig.exec_result_checksum != dec.exec_result_checksum:
        output = show_divergence_outputs(orig.exec_result_str, dec.exec_result_str, compiler_chosen)
        with open(divergent_log, "a") as divergent_log_f:
            divergent_log_f.write("A divergent test case is found at {}.\n".format(current_timestamp))
            divergent_log_f.write(output)
        
        clear_dir(tmp_folder)
        return 1
    
    clear_dir(tmp_folder)
    return 0