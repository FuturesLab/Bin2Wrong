import os.path, subprocess
import shutil
from enum import Enum

class status(Enum):
    OKAY = 1
    NODEC = 2
    ERROR = 3

def clear_dir(dir):
    if os.path.isdir(dir):
        for item in os.listdir(dir):
            item_path = os.path.join(dir, item)
            if os.path.isfile(item_path):
                os.remove(item_path)
            elif os.path.isdir(item_path):
                shutil.rmtree(item_path)

def create_folder_for_program(folder, cnt=0):
    folder_name = f"{folder}_{cnt}"
    if os.path.exists(folder_name):
        return create_folder_for_program(folder, cnt + 1)
    else:
        os.makedirs(folder_name)
    return folder_name

def comp_decomp(comp_log_file, target_code, target_exec, compiler_chosen, decompiler, msvc, result_folder, win2lin, comp_flags, msvcinc, msvclib, bin2wrong_path, dec_lib, extern_lib):
    if compiler_chosen == msvc:
        orig_dir = os.getcwd()
        os.chdir(result_folder)

        comp_state_cmd = '(' + win2lin + ' ' + compiler_chosen + ' ' + comp_flags + ' '
        comp_state_cmd += os.path.basename(target_code) + ' ' + msvcinc + ' ' + msvclib
        if dec_lib != '':
            comp_state_cmd += ' Z:' + bin2wrong_path+dec_lib + '.obj'
        comp_state_cmd += ')'

        #os.system(comp_state_cmd)
        with open(comp_log_file,'w') as f:
            subprocess.call(comp_state_cmd, shell=True, stderr=f, stdout=f)
        os.chdir(orig_dir)

        disable_fixme_env = os.environ.copy()
        disable_fixme_env["WINEDEBUG"] = "fixme-all" 

    elif compiler_chosen == "o64-clang":

        comp_state_cmd = compiler_chosen + ' ' + comp_flags + ' '
        if dec_lib != '':
            comp_state_cmd += bin2wrong_path+dec_lib + '_macho.o '
            
        comp_state_cmd += target_code + ' ' + extern_lib + ' -o ' + target_exec #+ ' > /dev/null 2>&1'
        #os.system(comp_state_cmd)
        with open(comp_log_file,'w') as f:
            subprocess.call(comp_state_cmd, shell=True, stderr=f, stdout=f)

    else:

        comp_state_cmd = compiler_chosen + ' ' + comp_flags + ' '
        if dec_lib != '':
            comp_state_cmd += bin2wrong_path+dec_lib + '.o '
            
        comp_state_cmd += target_code + ' ' + extern_lib + ' -o ' + target_exec

        if decompiler == 'bn':
            comp_state_cmd += ' -lm'

        #comp_state_cmd += ' > {}'.format(comp_log_file) #' > /dev/null 2>&1'
            
        #os.system(comp_state_cmd)
        with open(comp_log_file,'w') as f:
            subprocess.call(comp_state_cmd, shell=True, stderr=f, stdout=f)

def rm_result_mark(text):
    mark = "End of program"
    pos = text.find(mark)
    if pos != -1:
        text = text[:pos]
        if text.endswith('\r\n'):
            return text[:-2]
        elif text.endswith('\n'):
            return text[:-1]
    return text

def get_checksum(str):

    ret_str = str

    if ' ' in str:
        str = str.split(' ')
        ret_str = str[-3] + ' ' + str[-2] + ' ' + str[-1]

    return ret_str

def show_divergence_outputs(src_str, dec_str, compiler_chosen):

    output = "\n"
    output += "Compiler used: " + compiler_chosen + " "*50 + "\n"
    output += "Original code output:   \n"
    output += src_str + " "*100 + "\n"
    output += "Decompiled code output: \n"
    output += dec_str + " "*100 + "\n"
    output += "\n"

    print(output)
    return output


class c_code:
    def __init__(self):
        self.c_code = None
        self.state_code = None
        self.dir = None
        self.c_exec = None
        self.state_exec = None
        self.subprocess_ret = None
        self.exec_result = None
        self.exec_result_str = None
        self.exec_result_checksum = None

        self.add_state_cmd = None
        self.comp_state_cmd = None
        self.comp_state_status = None

        self.dec_default_code = None