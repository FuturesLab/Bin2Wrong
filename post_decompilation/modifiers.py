import re

type_reg_exp = r"(void|int|char|short|long|long\slong|int8_t|uint8_t|int16_t|uint16_t|int32_t|uint32_t|int64_t|uint64_t|struct|union|word32|word64|generic32_t|generic64_t)"

id_reg_exp = r"([A-Za-z_]+[A-Za-z_0-9]*)"

# the regular expression used to match parameters
par_dec_reg = (r"("
               r"(unsigned\s+){0,1}" +   # unsigned
               type_reg_exp +   # type
               r"(\s*\**\s*)" +   # pointer
               id_reg_exp +   # var name
               r"(\s*(\[[0-9]*\]){0,1})"  # array
               r",{0,1}\s*"  # comma
               r")")
void_par_reg = r"((void){0,1})"

# the regular expression used to match function type
fun_type_reg = (r"("
                r"(static\s+){0,1}" +   # static
                r"((signed|unsigned)\s+){0,1}" +   # signed | unsigned
                type_reg_exp +   # type
                r"(\s+[A-Za-z0-9_]*\s+){0,1}" +
                r"(\s+\**\s*)"  # pointer
                r")")

def find_fun_with_name(code, fun_name):
    reg_exp = (fun_type_reg +
               fun_name +
               r"\((\s*" + par_dec_reg + '|' + void_par_reg + "\s*)*\)\s*\\n*{"
               )
    pattern = re.compile(reg_exp)
    match = pattern.search(code)
    if match and __name__ == '__main__':
        #print('reg exp: %s' % reg_exp)
        #print(match.group(0))
        #print('from %d to %d' % (match.start(), match.end()))
        #print('function name: %s' % fun_name)
        pass
    return match

def find_function_body(code, body_start_pos):
    brace_num = 0
    length = len(code)
    last_right_brace = -1
    if code[body_start_pos-1]=='{':
        brace_num += 1
        # body_start_pos += 1
    while brace_num != 0:
        # in case { in a string: '{'
        # this may happen in Radare2
        if body_start_pos >= length:
            return last_right_brace + 1

        if code[body_start_pos]=='{':
            if code[body_start_pos - 1] != r"'" or code[body_start_pos + 1] != r"'":
                brace_num += 1
        elif code[body_start_pos]=='}':
            if code[body_start_pos - 1] != r"'" or code[body_start_pos + 1] != r"'":
                brace_num -= 1
            last_right_brace = body_start_pos
        body_start_pos += 1
    body_end_pos = body_start_pos
    return body_end_pos

def line_begin(code, pos):
    while code[pos] != '\n' and pos > 0:
        pos -= 1
    return pos

def line_end(code, pos):
    while code[pos] != '\n':
        pos += 1
    return pos

class RetdecModifier:
    @staticmethod
    def add_extern(code, pos):
        extern = """
        
    typedef int64_t int128_t;
    extern float __asm_movss(float a);
    extern float __asm_movaps(float a);
    extern double __asm_movsd(double a);
    extern double __asm_mulsd(double a, double b);
    extern int64_t __asm_movq(int64_t a);
    extern int32_t __asm_cvttsd2si(double a);
    extern int64_t __asm_xorps(int64_t a, int64_t b);
    extern double __asm_cvtsi2sd(int64_t a);
    extern double __asm_cvtss2sd(float a);
    extern double __asm_addsd(double a, double b);
    extern double __asm_subsd(double a, double b);
    #define __asm_lfence() __asm__ __volatile__("lfence")
    #define __addvsi3(x, y) x+y
    #define __addvdi3(x, y) x+y

    """
        if extern in code:
            return code
        else:
            return code[0:pos] + extern + code[pos:]

    @staticmethod
    def delete_lines(code='', mark=''):
        pos = code.find(mark)
        while pos != -1:
            beg_pos = line_begin(code, pos)
            end_pos = line_end(code, pos)
            code = code[0:beg_pos] + code[end_pos:]
            pos = code.find(mark)
        return code
    
    @staticmethod
    def modify_true_value(code=''):
        code = code.replace('true', '1')
        return code
    
    @staticmethod
    def rename_str(code='', compiler=''):
        defect_str = r'\*\(int64_t\s*\*\)&?g\d+\s*=\s*\(int64_t\)'
        defect_str_glbl = r'\(\*g\d+\)\[\d+\]\s*=\s*\"'
        match = re.search(defect_str, code)
        if match:
            #if compiler == 'icx':
            #    match_glbl = re.search(defect_str_glbl, code)
            #    if match_glbl:
            #        code = code.replace(match_glbl.group(), '*str = "')
            code = code.replace(match.group(), 'str = ')
        return code
    
    @staticmethod
    def rename_int(code='', compiler=''):
        if "MSVC" in compiler or "msvc" in compiler:
            return code
        else:
            defect = r'(\*\(int32_t\s*\*\)&?g\d+\s*=\s*)(-?\d+)'
            match = re.search(defect, code)
            if match:
                code = code.replace(match.group(1), 'i = ')
            else:
                defect = r'\*\(int32_t\s*\*\)&?g\d+\s*=\s*\(int32_t\)'
                match = re.search(defect, code)
                if match:
                    code = code.replace(match.group(), 'i = ')
            return code
    
    @staticmethod
    def rename_short(code='', compiler=''):
        if "MSVC" in compiler or "msvc" in compiler:
            return code
        else:
            defect = r'(\*\(int16_t\s*\*\)&?g\d+\s*=\s*)(-?\d+)'
            match = re.search(defect, code)
            if match:
                code = code.replace(match.group(1), 's = ')
            else:
                defect = r'\*\(int16_t\s*\*\)&?g\d+\s*=\s*\(int16_t\)'
                match = re.search(defect, code)
                if match:
                    code = code.replace(match.group(), 's = ')
            return code
    
    @staticmethod
    def rename_long(code='', compiler=''):
        if "MSVC" in compiler or "msvc" in compiler:
            defect = r'(\*\(int32_t\s*\*\)&?g\d+\s*=\s*)(\d+)'
        else:
            defect = r'(g\d+\s*=\s*)(0x[0-9a-fA-F]+)'
        
        match = re.search(defect, code)
        if match:
            code = code.replace(match.group(1), 'l = ')
        else:
            defect = r'(g\d+\s*=\s*)(-?\d+)'
            match = re.search(defect, code)
            if match:
                code = code.replace(match.group(), 'l = ')
            else:
                if "set_var" not in code:
                    defect = r'(g\d+\s*=\s*)(v\d+)'
                    match = re.search(defect, code)
                    if match:
                        code = code.replace(match.group(1), 'l = ')
                    else:
                        defect = r'(g\d+\s*=\s*)(__asm_)'
                        match = re.search(defect, code)
                        if match:
                            code = code.replace(match.group(1), 'l = ')
        return code
    
    @staticmethod
    def fix_printf(code, compiler, mark):

        if mark not in code:
            return code
        
        #if 'msvc' in compiler or 'MSVC' in compiler:
        #    code = code.replace(mark, 'printf("%s", ')

        #else:
        b_pos = code.find(mark)
        e_pos = b_pos

        while code[e_pos] != ';':
            e_pos += 1

        code = code[0:b_pos] + 'printf("%s", str)' + code[e_pos:]
        return code
    
    @staticmethod
    def fix_asm(code):
        asm_reg = r'(?:movss|movaps|movsd|mulsd|cvttsd2si|xorps|cvtsi2sd|cvtss2sd|addsd|subsd)\_\d+'

        asm_matches_all = re.findall(asm_reg, code)
        if len(asm_matches_all) == 0:
            return code
        
        asm_matches = list(dict.fromkeys(asm_matches_all))
        for m in asm_matches:
            code = code.replace(m, m.split('_')[0])

        return code
    
    @staticmethod
    def fix_func_names(code, funcs:list):
        for func in funcs:
            if '_'+func+'(' in code:
                code = code.replace('_'+func+'(', func+'(')
        return code

    @staticmethod
    def fix_func_args(code, func):
        if func == '':
            return code
        
        if func == 'func_1':
            func_loc = code.find(func)
            
            if func_loc != -1:
                code_after_func = code[func_loc+len(func):]
                args_start = code_after_func.find('(')
                args_end = args_start

                l_brace_cnt = 1
                r_brace_cnt = 0
                while l_brace_cnt != r_brace_cnt:
                    args_end += 1
                    if code_after_func[args_end] == ')':
                        r_brace_cnt += 1
                    if code_after_func[args_end] == '(':
                        l_brace_cnt += 1
                
                code = code[:func_loc+len(func)] + code_after_func[:args_start+1] + code_after_func[args_end:]

        return code
    
    @staticmethod
    def fix_glb_var_types(code, compiler=''):
        if 'icx' in compiler:
            types = r'int\d+_t'
            names = r'g\d+'

            local = r'\*\(int\d+_t\s*\*\)&g\d+\s*=\s'
            local_matches = re.findall(local, code)

            if len(local_matches) == 0:
                return code

            l_m = []
            for m in local_matches:
                l_m.append([re.compile(types).search(m).group(0), re.compile(names).search(m).group(0)])

            for l in l_m:
                glbl = r'int\d+_t\s' + re.escape(l[1])
                glbl_match = re.compile(glbl).search(code)
                if glbl_match:
                    code = code[:glbl_match.start()] + l[0] + ' ' + l[1] + code[glbl_match.end():]
        return code
    
    @staticmethod
    def fix_target_func_code(code='', func=''):
        main_dec_name = 'main'

        if func == '' or func in code or (main_dec_name not in code and 'start(' not in code):
            return code

        defect_reg = r'function_[0-9a-fA-F]+'
        
        find_main = find_fun_with_name(code, main_dec_name)
        main_dec_start = find_main.start()
        main_dec_end = find_function_body(code, find_main.end())
        main_dec = code[main_dec_start:main_dec_end]

        match = re.compile(defect_reg).search(main_dec)
        if match:
            func_dec_name = match.group(0)
            code = code.replace(func_dec_name, func)

        return code
    
    @staticmethod
    def rename_func(code='', func=''):

        if func == '' or func in code:
            return code

        defect_reg = r'function_[0-9a-fA-F]+'

        matches = re.findall(defect_reg, code)

        if len(matches) == 0:
            return code

        for m in matches:
            if m+'("' not in code:
                code = code.replace(m, func)

        return code
    
    @staticmethod
    def modifyMsvcDec(dec_code, orig_num_funcs=0, target_func_ordi=0, target_func_name=''):
        if orig_num_funcs == 0 or target_func_ordi == 0:
            return dec_code
            
        indicator = '// ------------------------ Functions -------------------------'
        funcs_pos = dec_code.find(indicator)
        if funcs_pos == -1:
            return dec_code

        funcs_pos += len(indicator)
        dec_code = dec_code[funcs_pos:]

        defect_reg = r'function_[0-9a-fA-F]+'

        matches = re.findall(defect_reg, dec_code)

        if len(matches) == 0 or len(matches) < orig_num_funcs:
            return dec_code

        matches = list(dict.fromkeys(matches))
        unique_matches = []
        defect_printf = []
        for m in matches:
            if m+'("' in dec_code:
                defect_printf.append(m)
                continue
                
            if m not in unique_matches and m+'("' not in dec_code:
                    unique_matches.append(m)

        defect_funcs_names = unique_matches[:orig_num_funcs]

        find_last_func = find_fun_with_name(dec_code, defect_funcs_names[-1])
        last_func_end = find_function_body(dec_code, find_last_func.end())
        dec_code = dec_code[:last_func_end]
        dec_code = dec_code.replace(defect_funcs_names[target_func_ordi-1], target_func_name)
        if len(defect_printf) != 0:
            dec_code = dec_code.replace(defect_printf[0], 'printf')
        return dec_code
    
class R2ghidraModifier:
    @staticmethod
    def add_extern(code, pos):
        extern = """
        
    typedef uint32_t uint;
    typedef unsigned short ushort;
    typedef unsigned long ulong;
    typedef unsigned char uchar;
    #define SBORROW4(a, b) a < b
    #define CONCAT44(a, b) b
        
    """
        if extern in code:
            return code
        else:
            return code[0:pos] + extern + code[pos:]

    @staticmethod
    def delete_lines(code='', mark=''):
        pos = code.find(mark)
        while pos != -1:
            beg_pos = line_begin(code, pos)
            end_pos = line_end(code, pos)
            code = code[0:beg_pos] + code[end_pos:]
            pos = code.find(mark)
        return code
    
    @staticmethod
    def modify_undefined(code='', mark=''):
        code = code.replace(mark, 'int')  # undefined4 is the unrecognized type
        return code

    @staticmethod
    def modify_sym(code=''):
        code = code.replace('_sym.', '')
        code = code.replace('sym.', '')
        return code
    
    @staticmethod
    def fix_str(code='', compiler=''):
        #code = code.replace('*str', 'str')
        code = code.replace('_str', 'str')

        return code

    @staticmethod
    def fix_printf(code='', compiler=''):

        if 'msvc' in compiler or 'MSVC' in compiler:
            l_var_reg = r'char\s\*[a-z]+Stack\_\d+'
            l_var_matches = re.findall(l_var_reg, code)
            
            if len(l_var_matches) == 0:
                return code
            
            l_vars = []
            g_vars = []
            for l_m in l_var_matches:
                l_var = l_m.split('*')[-1]
                if l_var not in l_vars:
                    l_vars.append(l_var)

                    g_expr_reg = r'\*0x\d+\s=\s'+l_var
                    g_expr_matches = re.findall(g_expr_reg, code)

                    if len(g_expr_matches) != 0:
                        for g_m in g_expr_matches:
                            g_var = g_m.split(' ')[0]
                            if g_var not in g_vars:
                                g_vars.append(g_var)

            if len(g_vars) <= 1:
                if len(g_vars) == 0:
                    printf_reg = r'fcn.[0-9a-fA-F]+\(0x[0-9a-fA-F]+\,\s\*0x[0-9a-fA-F]+\)'
                    printf_matches = re.findall(printf_reg, code)
                else:
                    defect_g_var = g_vars[0]
                    code = code.replace(defect_g_var, 'str')

                    printf_reg = r'fcn.[0-9a-fA-F]+\(0x[0-9a-fA-F]+\,\sstr\)'
                    printf_matches = re.findall(printf_reg, code)
                
                if len(printf_matches) != 0:
                    for defect_printf in printf_matches:
                        code = code.replace(defect_printf, 'printf("%s", str)')

        else:
            if compiler == 'tcc':
                mark=r'fcn.[0-9a-fA-F]+\(0x[0-9a-fA-F]+, pcVar\d+\)'
                mark_replace = 'printf("%s", str)'

            else:
                mark=r'printf\(0x[0-9a-fA-F]+\,'
                mark_replace = 'printf("%s",'

            mark_matches = re.findall(mark, code)

            if len(mark_matches) == 0:
                return code
                
            for m in mark_matches:
                b_pos = code.find(m)
                e_pos = b_pos + len(m)
                code = code[0:b_pos] + mark_replace + code[e_pos:]
        
        if "extraout" in code:

            b_pos = code.find(", extraout")
            e_pos = b_pos

            while code[e_pos] != ';':
                e_pos += 1

            code = code[0:b_pos] + ')' + code[e_pos:]

        return code
    
    @staticmethod
    def fix_printf_2(code='', compiler=''):
        pattern = r"(__printf_chk\(1, )0x[0-9a-fA-F]+"
        code = re.sub(pattern, r'\1"%s", str', code)
        
        return code
    
    @staticmethod
    def fix_func(code='', func=''):
        if func == '':
            return code

        mark=r'fcn\.[0-9a-fA-F]+\((?:uVar\d+|iVar\d+)(?:,\s(?:uVar\d+|iVar\d+))*\)'
        mark=r'fcn\.[0-9a-fA-F]+\((?:uVar\d+|iVar\d+)(?:,\s*(?:uVar\d+|iVar\d+))*\s*'
        mark_matches = re.findall(mark, code)

        if len(mark_matches) == 0:
            return code
            
        for m in mark_matches:
                
            b_pos = code.find(m)
            e_pos = b_pos + len(m)

            func_expr = code[b_pos:e_pos]
            after_func = code[e_pos:]

            i = 0
            while func_expr[i] != "(":
                i += 1
            func_expr = func + func_expr[i:]

            j = 0
            while (after_func[j] != ")" and after_func[j+1] != ";"):
                j += 1
            after_func = after_func[j:]

            code = code[:b_pos] + func_expr + after_func
        
        return code
    
    @staticmethod
    def fix_target_func_name(code, func):
        if '_'+func in code:
            code = code.replace('_'+func, func)
        return code
    
    @staticmethod
    def fix_target_func_code(code='', func=''):
        main_dec_name = 'main'

        if func == '' or func in code or (main_dec_name not in code and 'start(' not in code):
            return code

        defect_reg = r'fcn.[0-9a-fA-F]+'
        
        find_main = find_fun_with_name(code, main_dec_name)
        main_dec_start = find_main.start()
        main_dec_end = find_function_body(code, find_main.end())
        main_dec = code[main_dec_start:main_dec_end]

        match = re.compile(defect_reg).search(main_dec)
        if match:
            func_dec_name = match.group(0)
            code = code.replace(func_dec_name, func)

        return code
    
    @staticmethod
    def rename_func(code='', func=''):

        if func == '' or func in code:
            return code

        defect_reg = r'fcn.[0-9a-fA-F]+'

        matches = re.findall(defect_reg, code)

        if len(matches) == 0:
            return code

        for m in matches:
            if m+'("' not in code:
                code = code.replace(m, func)

        return code
    
    @staticmethod
    def fix_func_names(code, funcs:list):
        for func in funcs:
            if '_'+func+'(' in code:
                code = code.replace('_'+func+'(', func+'(')
        return code

    @staticmethod
    def fix_func_args(code, func):
        if func == '':
            return code
        
        if func == 'func_1':
            func_loc = code.find(func)
            
            if func_loc != -1:
                code_after_func = code[func_loc+len(func):]
                args_start = code_after_func.find('(')
                args_end = args_start

                l_brace_cnt = 1
                r_brace_cnt = 0
                while l_brace_cnt != r_brace_cnt:
                    args_end += 1
                    if code_after_func[args_end] == ')':
                        r_brace_cnt += 1
                    if code_after_func[args_end] == '(':
                        l_brace_cnt += 1
                
                code = code[:func_loc+len(func)] + code_after_func[:args_start+1] + code_after_func[args_end:]

        return code

class BinaryninjaModifier:
    @staticmethod
    def add_extern(code, pos):
        extern = """
        
    extern double real_truncf(double a);
    #define truncf(a, b) real_truncf(a)
        
    """
        if extern in code:
            return code
        else:
            return code[0:pos] + extern + code[pos:]

    @staticmethod
    def delete_lines(code='', mark=''):
        pos = code.find(mark)
        while pos != -1:
            beg_pos = line_begin(code, pos)
            end_pos = line_end(code, pos)
            code = code[0:beg_pos] + code[end_pos:]
            pos = code.find(mark)
        return code

    @staticmethod
    def fix_printf(code='', compiler=''):

        if 'msvc' in compiler or 'MSVC' in compiler:
            l_var_reg = r'char\s\*var\_\d+'
            l_var_matches = re.findall(l_var_reg, code)
            
            if len(l_var_matches) == 0:
                return code
            
            l_vars = []
            g_vars = []
            for l_m in l_var_matches:
                l_var = l_m.split('*')[-1]
                if l_var not in l_vars:
                    l_vars.append(l_var)

                    g_expr_reg = r'data_[0-9a-fA-F]+\s=\s'+l_var
                    g_expr_matches = re.findall(g_expr_reg, code)

                    if len(g_expr_matches) != 0:
                        for g_m in g_expr_matches:
                            g_var = g_m.split(' ')[0]
                            if g_var not in g_vars:
                                g_vars.append(g_var)
            
            if len(g_vars) == 1:
                defect_g_var = g_vars[0]
                code = code.replace(defect_g_var, 'str')

                printf_reg = r'sub_[0-9a-fA-F]+\(\&data_[0-9a-fA-F]+\,\sstr\)'
                printf_matches = re.findall(printf_reg, code)
                
                if len(printf_matches) != 0:
                    for defect_printf in printf_matches:
                        code = code.replace(defect_printf, 'printf("%s", str)')
        
        elif "o64-clang" in compiler:
            mark = r'printf\(&data_[0-9a-fA-F]+\)'
            mark_replace = 'printf("%s", str)'
            mark_matches = re.findall(mark, code)

            if len(mark_matches) == 0:
                return code
                
            for m in mark_matches:
                b_pos = code.find(m)
                e_pos = b_pos + len(m)
                code = code[0:b_pos] + mark_replace + code[e_pos:]
                
        else:
            pattern = r"(__printf_chk\(1, )&data_[0-9a-fA-F]+"
            code = re.sub(pattern, r'\1"%s", str', code)

            mark = r'printf\(&data_[0-9a-fA-F]+,'
            mark_replace = 'printf("%s",'
            mark_matches = re.findall(mark, code)

            if len(mark_matches) == 0:
                return code
                
            for m in mark_matches:
                b_pos = code.find(m)
                e_pos = b_pos + len(m)
                code = code[0:b_pos] + mark_replace + code[e_pos:]
        
        return code

    @staticmethod
    def fix_faulty_ptr(code='', compiler=''):
        if compiler == "o64-clang" or compiler == "clang" or compiler == "icx":
            pattern = r"(char const\* const )(rax_[0-9a-fA-F]+)"
            code = re.sub(pattern, r"int \2", code)

            pattern = r"(void\* )(rax_[0-9a-fA-F]+)"
            code = re.sub(pattern, r"int16_t \2", code)

            pattern = r"(void\* const )(rax_[0-9a-fA-F]+)"
            code = re.sub(pattern, r"int \2", code)

        return code
    
    @staticmethod
    def fix_local_str_type(code='', compiler = ''):
        pattern = r"void\*\s*const\s+(r\d+(?:_\d+)*)\s*=\s*\""
        code = re.sub(pattern, r'char *\1 = "', code)

        pattern = r"void\*\s*const\s+(rdx_\d+(?:_\d+)*)\s*=\s*\""
        code = re.sub(pattern, r'char *\1 = "', code)
        
        pattern = r"void\*\s*const\s+(var_\d+(?:_\d+)*)\s*=\s*\""
        code = re.sub(pattern, r'char *\1 = "', code)

        pattern = r"char const\* const (var_\d+(?:_\d+)*)\s*=\s*\""
        code = re.sub(pattern, r'char *\1 = "', code)

        return code

    @staticmethod
    def fix_str(code='', compiler=''):
        code = code.replace('*str', 'str')
        code = code.replace('_str', 'str')

        return code

    @staticmethod
    def fix_target_func_code(code='', func=''):
        main_dec_name = 'main'

        if func == '' or func in code or (main_dec_name not in code and 'start(' not in code):
            return code

        defect_reg = r'sub_[0-9a-fA-F]+'
        
        find_main = find_fun_with_name(code, main_dec_name)
        main_dec_start = find_main.start()
        main_dec_end = find_function_body(code, find_main.end())
        main_dec = code[main_dec_start:main_dec_end]

        match = re.compile(defect_reg).search(main_dec)
        if match:
            func_dec_name = match.group(0)
            code = code.replace(func_dec_name, func)

        return code

    @staticmethod
    def rename_func(code='', func=''):

        if func == '' or func in code:
            return code

        defect_reg = r'sub_[0-9a-fA-F]+'

        matches = re.findall(defect_reg, code)

        if len(matches) == 0:
            return code

        for m in matches:
            if m+'("' not in code:
                code = code.replace(m, func)

        return code
    
    @staticmethod
    def modifyMsvcDec(dec_code, orig_num_funcs=0, target_func_ordi=0, target_func_name=''):
        if orig_num_funcs == 0 or target_func_ordi == 0:
            return dec_code
            
        defect_reg = r'sub_[0-9a-fA-F]+'

        defect_main = 'main'
        if defect_main not in dec_code:
            defect_main = 'post_pgo_initialization'
        matches = re.findall(defect_reg, dec_code)
        if len(matches) == 0 or len(matches) < orig_num_funcs:
            return dec_code

        if len(matches) == 0 or len(matches) < orig_num_funcs:
            return dec_code

        matches = list(dict.fromkeys(matches))
        unique_matches = []
        for m in matches:            
            if m not in unique_matches and m+'("' not in dec_code:
                    unique_matches.append(m)

        defect_funcs_names = unique_matches[:orig_num_funcs-1]
        defect_funcs_names.append(defect_main)

        find_last_func = find_fun_with_name(dec_code, defect_funcs_names[-1])
        last_func_end = find_function_body(dec_code, find_last_func.end())
        dec_code = dec_code[:last_func_end]
        dec_code = dec_code.replace(defect_funcs_names[target_func_ordi-1], target_func_name)

        return dec_code

    @staticmethod
    def fix_func_names(code, funcs:list):
        for func in funcs:
            if '_'+func+'(' in code:
                code = code.replace('_'+func+'(', func+'(')
        return code
    
    @staticmethod
    def fix_var_names(code, vars:list):
        for var in vars:
            if '_'+var+' ' in code:
                code = code.replace('_'+var+' ', var+' ')
            if ' = *'+var+';' in code:
                code = code.replace(' = *'+var+';', ' = '+var+';')
        return code

class RekoModifier:
    @staticmethod
    def add_extern(code, pos, global_code):
        extern = """
        
    typedef int16_t int16;
    typedef int32_t int32;
    typedef int64_t int64;
    typedef int16_t word16;
    typedef int32_t word32;
    typedef int64_t word64;
    typedef int16_t cui16;
    typedef int32_t cui32;
    typedef int64_t cui64;
    typedef int16_t real16;
    typedef int32_t real32;
    typedef int64_t real64;
    typedef int8_t byte;
    typedef uint32_t uint32;
    typedef uint32_t uint32;
    typedef uint64_t uint64;
    typedef void* ptr64;
    #define __lfence() 0
    #define __addvsi3(x, y) x+y
    #define __addvdi3(x, y) x+y
        
    """
        if extern in code:
            return code
        else:
            return code[0:pos] + extern + global_code + code[pos:]

    @staticmethod
    def delete_lines(code='', mark=''):
        pos = code.find(mark)
        while pos != -1:
            beg_pos = line_begin(code, pos)
            end_pos = line_end(code, pos)
            code = code[0:beg_pos] + code[end_pos:]
            pos = code.find(mark)
        return code
    
    @staticmethod
    def fix_printf(code='', compiler=''):

        mark = r'fn[0-9a-fA-F]+\("%s"\)'
        
        mark_replace = 'printf("%s", str)'

        mark_matches = re.findall(mark, code)

        if len(mark_matches) == 0:
            return code
            
        for m in mark_matches:
            b_pos = code.find(m)
            e_pos = b_pos + len(m)
            code = code[0:b_pos] + mark_replace + code[e_pos:]
        
        return code
    
    @staticmethod
    def fix_target_func_code(code='', func=''):
        main_dec_name = 'main'

        if func == '' or func in code or (main_dec_name not in code and 'start(' not in code):
            return code

        defect_reg = r'fn[0-9a-fA-F]+'
        
        find_main = find_fun_with_name(code, main_dec_name)
        main_dec_start = find_main.start()
        main_dec_end = find_function_body(code, find_main.end())
        main_dec = code[main_dec_start:main_dec_end]

        match = re.compile(defect_reg).search(main_dec)
        if match:
            func_dec_name = match.group(0)
            code = code.replace(func_dec_name, func)

        return code
    
    @staticmethod
    def find_global_code(code, mark):
        pattern = r"//GLOBAL(.*?)//GLOBAL"
        match = re.search(pattern, code, re.DOTALL)

        result = ''
        if match:
            result = match.group(1)
        return result
    
    @staticmethod
    def rename_func(code='', func=''):

        if func == '' or func in code:
            return code

        defect_reg = r'fn[0-9a-fA-F]+'

        matches = re.findall(defect_reg, code)

        if len(matches) == 0:
            return code

        for m in matches:
            if m+'("' not in code:
                code = code.replace(m, func)

        return code
    
    @staticmethod
    def modifyMsvcDec(dec_code, orig_num_funcs=0, target_func_ordi=0, target_func_name=''):
        if orig_num_funcs == 0 or target_func_ordi == 0:
            return dec_code
            
        defect_reg = r'fn[0-9a-fA-F]+'
        matches = re.findall(defect_reg, dec_code)
        if len(matches) == 0 or len(matches) < orig_num_funcs:
            return dec_code
        
        matches = list(dict.fromkeys(matches))
        unique_matches = []

        for m in matches:
            if m not in unique_matches:
                unique_matches.append(m)

        defect_funcs_names = unique_matches[:orig_num_funcs]

        find_last_func = find_fun_with_name(dec_code, defect_funcs_names[-1])
        last_func_end = find_function_body(dec_code, find_last_func.end())
        dec_code = dec_code[:last_func_end]
        dec_code = dec_code.replace(defect_funcs_names[target_func_ordi-1], target_func_name)
        return dec_code
    
class RelyzeModifier:
    @staticmethod
    def add_extern(code, pos):
        if '__asm.' not in code:
            return code

        code = code.replace('__asm.', '__asm_')
        extern = """

    extern float __asm_movss(float a);
    extern float __asm_movaps(float a);
    extern double __asm_movsd(double a);
    extern double __asm_mulsd(double a, double b);
    extern int64_t __asm_movq(int64_t a);
    extern int32_t __asm_cvttsd2si(double a);
    extern int64_t __asm_xorps(int64_t a, int64_t b);
    extern double __asm_cvtsi2sd(int64_t a);
    extern double __asm_cvtss2sd(float a);
    extern double __asm_addsd(double a, double b);
    extern double __asm_subsd(double a, double b);
        
    """
        if extern in code:
            return code
        else:
            return code[0:pos] + extern + code[pos:]

    @staticmethod
    def delete_lines(code='', mark=''):
        pos = code.find(mark)
        while pos != -1:
            beg_pos = line_begin(code, pos)
            end_pos = line_end(code, pos)
            code = code[0:beg_pos] + code[end_pos:]
            pos = code.find(mark)
        return code
    
    @staticmethod
    def fix_glbl_str(code='', compiler=''):
        if 'msvc' in compiler or 'MSVC' in compiler:
            l_var_reg = r'local_0x[0-9a-fA-F]+\s=\s\"'
            l_var_matches = re.findall(l_var_reg, code)

            if len(l_var_matches) == 0:
                return code
            
            l_vars = []
            for l_m in l_var_matches:
                l_var = l_m.split(' ')[0]
                if l_var not in l_vars:
                    l_vars.append(l_var)

            
            if len(l_vars) != 0:
                g_vars = []
                for l_v in l_vars:

                    declare_reg = r'\b(?:int|short|long|int8_t|uint8_t|int16_t|uint16_t|int32_t|uint32_t|int64_t|uint64_t)\b\s'+l_v
                    declare_matches = re.findall(declare_reg, code)
                    
                    for d_m in declare_matches:
                        code = code.replace(d_m, 'char* '+l_v)

                    g_var_reg = r'data_0x[0-9a-fA-F]+\s=\s'+l_v
                    g_var_matches = re.findall(g_var_reg, code)

                    if len(g_var_matches) != 0:
                        for g_m in g_var_matches:
                            g_var = g_m.split(' ')[0]
                            if g_var not in g_vars:
                                g_vars.append(g_var)

            if len(g_vars) == 1:
                code = code.replace(g_vars[0], 'str')
        return code
    
    @staticmethod
    def fix_glbl_vars(code='', compiler=''):
        if 'msvc' in compiler or 'MSVC' in compiler:
            expr_reg = r'data_0x[0-9a-fA-F]+\s=\s(?:|\(int\)|\(short\)|\(long\)|\(int8_t\)|\(uint8_t\)|\(int16_t\)|\(uint16_t\)|\(int32_t\)|\(uint32_t\)|\(int64_t\)|\(uint64_t\))local_0x[0-9a-fA-F]+'
            expr_matches = re.findall(expr_reg, code)

            if len(expr_matches) == 0:
                return code
            
            expr_locs = []
            set_var_func = 'set_var('
            for e_m in expr_matches:
                expr_locs.append(code.find(e_m))
                set_var_func += e_m.split(' ')[-1] + ', '
                code = code.replace(e_m+';', '')

            set_var_func = set_var_func[:-2] + ');'
            
            code = code[:expr_locs[0]] + set_var_func + code[expr_locs[0]:]

        return code
    
    @staticmethod
    def fix_printf(code=''):
        mark = r'printf_\d+\('
        mark_replace = 'printf('

        mark_matches = re.findall(mark, code)

        if len(mark_matches) == 0:
            return code
            
        for m in mark_matches:
            b_pos = code.find(m)
            e_pos = b_pos + len(m)
            code = code[0:b_pos] + mark_replace + code[e_pos:]
        
        return code
    
    @staticmethod
    def fix_vars(code=''):
        defect = '_1[0]'
        code = code.replace(defect, '')

        return code
    
    @staticmethod
    def fix_target_func_code(code='', func=''):
        main_dec_name = 'main'

        if func == '' or func in code or (main_dec_name not in code and 'start(' not in code):
            return code

        defect_reg = r'func_0x[0-9a-fA-F]+'
        
        find_main = find_fun_with_name(code, main_dec_name)
        main_dec_start = find_main.start()
        main_dec_end = find_function_body(code, find_main.end())
        main_dec = code[main_dec_start:main_dec_end]

        match = re.compile(defect_reg).search(main_dec)
        if match:
            func_dec_name = match.group(0)
            code = code.replace(func_dec_name, func)

        return code
    
    @staticmethod
    def modifyMsvcDec(dec_code, orig_num_funcs=0, target_func_ordi=0, target_func_name=''):
        if orig_num_funcs == 0 or target_func_ordi == 0:
            return dec_code
            
        dec_code = dec_code.replace('__cdecl ', '')

        defect_reg = r'func_0x[0-9a-fA-F]+'

        matches = re.findall(defect_reg, dec_code)

        if len(matches) == 0 or len(matches) < orig_num_funcs:
            return dec_code


        matches = list(dict.fromkeys(matches))
        unique_matches = []
        defect_printf = []
        for m in matches:
            if m+'( "' in dec_code:
                defect_printf.append(m)
                continue
            
            if m not in unique_matches and m+'( "' not in dec_code:
                unique_matches.append(m)

        defect_funcs_names = unique_matches[:orig_num_funcs]

        find_last_func = find_fun_with_name(dec_code, defect_funcs_names[-1])
        last_func_end = find_function_body(dec_code, find_last_func.end())
        dec_code = dec_code[:last_func_end]
        dec_code = dec_code.replace(defect_funcs_names[target_func_ordi-1], target_func_name)
        if len(defect_printf) != 0:
            dec_code = dec_code.replace(defect_printf[0], 'printf')
        return dec_code
    
class RevngModifier:
    @staticmethod
    def add_extern(code, pos, compiler):
        if 'msvc' in compiler or 'MSVC' in compiler:
            extern = """
        
    typedef int8_t generic8_t;
    typedef int16_t generic16_t;
    typedef int32_t generic32_t;
    typedef int64_t generic64_t;
    #pragma pack(push, 1)
        
    """
        else:

            extern = """
        
    typedef int8_t generic8_t;
    typedef int16_t generic16_t;
    typedef int32_t generic32_t;
    typedef int64_t generic64_t;
        
    """
        if extern in code:
            return code
        else:
            #print(code[0:pos])
            #print("-------------")
            #print(code[pos:])
            return code[0:pos] + extern + code[pos:]
        
    @staticmethod
    def fix_struct(code, compiler):
        if 'msvc' in compiler or 'MSVC' in compiler:
            code = code.replace('_PACKED', '')
        else:
            code = code.replace('_PACKED', '__attribute__((__packed__))')

        return code
    
    @staticmethod
    def fix_str(code, compiler):
        reg = r'_segment.*\.str'
        matches = re.findall(reg, code)

        for m in matches:
            code = code.replace(m, 'str')
        
        return code
    
    @staticmethod
    def fix_printf(code='', compiler=''):

        code = code.replace('printf_((int8_t const *) "%s")', 'printf("%s", str)')
        return code
    
    @staticmethod
    def modifyMsvcDec(dec_code, orig_num_funcs=0, target_func_ordi=0, target_func_name=''):
        if orig_num_funcs == 0 or target_func_ordi == 0:
            return dec_code

        defect_reg = r'_function_0x[0-9a-fA-F]+_Code_x86_64'

        matches = re.findall(defect_reg, dec_code)

        if len(matches) == 0 or len(matches) < orig_num_funcs:
            return dec_code

        matches = list(dict.fromkeys(matches))
        unique_matches = []
        for m in matches:
            if m not in unique_matches:
                    unique_matches.append(m)

        defect_funcs_names = unique_matches[:orig_num_funcs]
        #print(defect_funcs_names)

        find_last_func = find_fun_with_name(dec_code, defect_funcs_names[-1])
        last_func_end = find_function_body(dec_code, find_last_func.end())
        dec_code = dec_code[:last_func_end]
        dec_code = dec_code.replace(defect_funcs_names[target_func_ordi-1], target_func_name)
        return dec_code
    
    @staticmethod
    def fix_target_func_code(code='', func=''):
        main_dec_name = 'main'

        defect_call = "func_1(generic64_t _register_xmm2 _REG(xmm2_x86_64))"
        if defect_call in code:
            code = code.replace(defect_call, 'func_1()')
            return code
        
        if func == '' or func in code or (main_dec_name not in code and 'start(' not in code):
            return code

        defect_reg = r'_function_0x[0-9a-fA-F]+_Code_x86_64'
        #if main_dec_name + '(' not in code or '_' + main_dec_name + '(' not in code:
        #    main_dec_name = '_start'    # when using o64-clang
        
        find_main = find_fun_with_name(code, main_dec_name)
        main_dec_start = find_main.start()
        main_dec_end = find_function_body(code, find_main.end())
        main_dec = code[main_dec_start:main_dec_end]

        match = re.compile(defect_reg).search(main_dec)
        if match:
            func_dec_name = match.group(0)
            code = code.replace(func_dec_name, func)

        return code
    
    @staticmethod
    def rename_func(code='', func=''):

        if func == '' or func in code:
            return code

        defect_reg = r'_function_0x[0-9a-fA-F]+_Code_x86_64'

        matches = re.findall(defect_reg, code)

        if len(matches) == 0:
            return code

        for m in matches:
            if m+'("' not in code:
                code = code.replace(m, func)

        return code
    
    @staticmethod
    def fix_setvar_args(code=''):

        defect_reg = r"(_struct_\d+\s(_var_\d+);)"
        matches = re.findall(defect_reg, code)

        if len(matches) == 0:
            return code

        for full, var in matches:
            defect = ", "+var+")"
            if defect in code:
                code = code.replace(defect, ')')
                code = code.replace(full, '')
        return code


class AngrModifier:
    @staticmethod
    def add_extern(code, pos, compiler):
        extern = ""
        if compiler != 'tcc' and ('msvc' not in compiler and 'MSVC' not in compiler):
            extern = """
        
    typedef unsigned __int128 uint128_t;
    #define __addvsi3(x, y) x+y
    #define __addvdi3(x, y) x+y
        
    """
        if extern in code:
            return code
        else:
            return code[0:pos] + extern + code[pos:]
        
    @staticmethod
    def delete_lines(code='', mark=''):
        pos = code.find(mark)
        while pos != -1:
            beg_pos = line_begin(code, pos)
            end_pos = line_end(code, pos)
            code = code[0:beg_pos] + code[end_pos:]
            pos = code.find(mark)
        return code
        
    @staticmethod
    def fix_local_str_type(code=''):
        local_str_var = r'v\d+\s=\s"'
        local_matches = re.findall(local_str_var, code)

        if len(local_matches) == 0:
            return code

        for m in local_matches:
            str_var_name = m[:-4]
            name_b_pos = code.find(str_var_name)
            type_b_pos = name_b_pos
            while code[type_b_pos] != '\n':
                type_b_pos -= 1
            
            code = code[0:type_b_pos] + "\n\tchar *" + code[name_b_pos:]
        return code
    
    @staticmethod
    def fix_printf(code='', compiler=''):
        '''
        if 'icx' in compiler:
            mark = r'printf\("%s", &g_\d+\)'
            mark_replace = 'printf("%s", str)'

        else:
            mark = r'printf\("%s",\s\(unsigned int\)'
            mark_replace = 'printf("%s", '
        '''
        if compiler == 'o64-clang' or 'msvc' in compiler or 'MSVC' in compiler:
            l_var_reg = r'v\d+'
            l_var_matches = re.findall(l_var_reg, code)
            
            if len(l_var_matches) == 0:
                return code
            
            l_vars = []
            g_vars = []
            for l_m in l_var_matches:
                l_var = l_m.split('*')[-1]
                if l_var not in l_vars:
                    l_vars.append(l_var)

                    g_expr_reg = r'g_[0-9a-fA-F]+\s=\s'+l_var
                    g_expr_matches = re.findall(g_expr_reg, code)

                    if len(g_expr_matches) != 0:
                        for g_m in g_expr_matches:
                            g_var = g_m.split(' ')[0]
                            if g_var not in g_vars:
                                g_vars.append(g_var)
            
            correct_printf = 'printf("%s", str'
            if len(g_vars) == 1:
                defect_g_var = g_vars[0]
                code = code.replace(defect_g_var, 'str')

                printf_reg = r'sub_[0-9a-fA-F]+\(\"\%s\",\sstr'
                printf_matches = re.findall(printf_reg, code)
                
                if len(printf_matches) != 0:
                    for defect_printf in printf_matches:
                        code = code.replace(defect_printf, correct_printf)

            loc = code.find(correct_printf)
            
            if loc != -1:
                code_after_str = code[loc+len(correct_printf):]
                if code_after_str.startswith(', '):
                    printf_end = 0

                    l_brace_cnt = 1
                    r_brace_cnt = 0
                    while l_brace_cnt != r_brace_cnt:
                        printf_end += 1
                        if code_after_str[printf_end] == ')':
                            r_brace_cnt += 1
                        if code_after_str[printf_end] == '(':
                            l_brace_cnt += 1
                    
                    code = code[:loc+len(correct_printf)] + code_after_str[printf_end:]
         
        else:

            mark = r'printf\("%s",\s\(unsigned int\)'
            mark_replace = 'printf("%s", '

            mark_matches = re.findall(mark, code)

            if len(mark_matches) == 0:
                return code
                
            for m in mark_matches:
                b_pos = code.find(m)
                e_pos = b_pos + len(m)
                code = code[0:b_pos] + mark_replace + code[e_pos:]
        
        return code
    
    @staticmethod
    def fix_target_func_code(code='', func=''):
        main_dec_name = 'main'

        if func == '' or func in code or (main_dec_name not in code and 'start(' not in code):
            return code

        defect_reg = r'sub_[0-9a-fA-F]+'
        if main_dec_name + '(' not in code or '_' + main_dec_name + '(' not in code:
            main_dec_name = '_start'    # when using o64-clang
        
        find_main = find_fun_with_name(code, main_dec_name)
        main_dec_start = find_main.start()
        main_dec_end = find_function_body(code, find_main.end())
        main_dec = code[main_dec_start:main_dec_end]

        match = re.compile(defect_reg).search(main_dec)
        if match:
            func_dec_name = match.group(0)
            code = code.replace(func_dec_name, func)

        return code
    
    @staticmethod
    def rename_func(code='', func=''):

        if func == '' or func in code:
            return code

        defect_reg = r'sub_[0-9a-fA-F]+'

        matches = re.findall(defect_reg, code)

        if len(matches) == 0:
            return code

        for m in matches:
            if m+'("' not in code:
                code = code.replace(m, func)

        return code

    @staticmethod
    def fix_func_args(code, func):
        if func == '':
            return code
        
        if func == 'func_1':
            func_loc = code.find(func)
            
            if func_loc != -1:
                code_after_func = code[func_loc+len(func):]
                args_start = code_after_func.find('(')
                args_end = args_start

                l_brace_cnt = 1
                r_brace_cnt = 0
                while l_brace_cnt != r_brace_cnt:
                    args_end += 1
                    if code_after_func[args_end] == ')':
                        r_brace_cnt += 1
                    if code_after_func[args_end] == '(':
                        l_brace_cnt += 1
                
                code = code[:func_loc+len(func)] + code_after_func[:args_start+1] + code_after_func[args_end:]

        return code

    @staticmethod
    def modifyMsvcDec(dec_code, orig_num_funcs=0, target_func_ordi=0, target_func_name=''):
        if orig_num_funcs == 0 or target_func_ordi == 0:
            return dec_code

        defect_reg = r'sub_[0-9a-fA-F]+'

        matches = re.findall(defect_reg, dec_code)

        if len(matches) == 0 or len(matches) < orig_num_funcs:
            return dec_code

        matches = list(dict.fromkeys(matches))
        unique_matches = []
        defect_printf = []
        for m in matches:
            if m+'("' in dec_code:
                defect_printf.append(m)
                continue
                
            if m not in unique_matches and m+'("' not in dec_code:
                    unique_matches.append(m)

        defect_funcs_names = unique_matches[:orig_num_funcs]

        find_last_func = find_fun_with_name(dec_code, defect_funcs_names[-1])
        last_func_end = find_function_body(dec_code, find_last_func.end())
        dec_code = dec_code[:last_func_end]
        dec_code = dec_code.replace(defect_funcs_names[target_func_ordi-1], target_func_name)
        if len(defect_printf) != 0:
            dec_code = dec_code.replace(defect_printf[0], 'printf')
        return dec_code