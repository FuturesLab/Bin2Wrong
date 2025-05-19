import os
import sys
from shutil import copyfile
from post_utils import status

def add_headers(filepath, line):
    with open(filepath, 'r+') as f:
        content = f.read()
        f.seek(0, 0)
        data = line + '\n' + content
        f.write(data)
        f.close()


def handle_arrays(dims_list,var_name,var_type,prefix,is_struct,struct_type,struct_filepath,iterator_seed):
    added_hash_code = ""
    if (prefix == ""):
        arr_var_name = var_name
    else:
        arr_var_name = prefix + "." + var_name

    index = 0
    arr_dim = len(dims_list)
    for i in range(arr_dim):
        loop_var_name = iterator_seed+"_"+str(index)
        arr_var_name+="""["""+loop_var_name+"""]"""
        if dims_list[int(i)] != "":
            added_hash_code+="""\tfor (int """+f'{loop_var_name}'+""" = 0 ; """+ f'{loop_var_name}'+""" < """+dims_list[int(i)]+"""; """+f'{loop_var_name}'+"""++){\n\t"""
        else:
            added_hash_code+="""\tfor (int """+f'{loop_var_name}'+""" = 0 ; """+ f'{loop_var_name}'+""" < 1 ; """+f'{loop_var_name}'+"""++){\n\t"""
        if ("char" in var_type):
            added_hash_code+="""\tif ("""+arr_var_name+""" == \'\\0"""+"""\') break;\n\t"""

        index+=1
    if (is_struct):
        added_hash_code+=handle_structs(arr_var_name,struct_type,struct_filepath)
    else:
        added_hash_code+="""\ttransparent_crc("""+arr_var_name+""", """+f'"{arr_var_name}"'+""", i_print_hash_value);\n"""
    for i in range(arr_dim):
        added_hash_code+="""\t}\n"""
    return added_hash_code


def get_array_dims(array_decl):
    dims = []
    array_decl = array_decl.strip("\n")
    dims = [ s[:-1] for s in array_decl.split("[") if ']' in s]
    return dims

def read_struct_information(struct_filepath):
    filehandle = open(struct_filepath, 'rt')
    struct_field_info = {}
    for line in filehandle.readlines():
        split_line = line.split("\t")
        if ("New-Record" not in split_line):
            struct_field_info[current_struct].append(split_line)
        else:
            current_struct = split_line[1].strip("\n")
            struct_field_info[current_struct] = []
    return (struct_field_info)

def isRecord(field_type):
    #if (("struct" in field_type) or ("union" in field_type)) and ("anonymous" not in field_type):
    if (("struct" in field_type)): #or ("union" in field_type)):
        return True
    else:
        return False
def recordType(field_type):
    if ("struct" in field_type):
        return "struct"
    #elif ("union" in field_type):
    #    return "union"


def handle_structs(prefix, struct_type, struct_filepath):
    struct_info_dict = read_struct_information(struct_filepath)
    #print (struct_info_dict)
    #print (struct_type)
    struct_field_info = struct_info_dict[struct_type]
    added_text = ""
    index = 0
    for field_info in struct_field_info:
        field_name = field_info[0]
        field_type = field_info[1]
        is_a_Record = isRecord(field_type) # check if a struct or a union or anonymous
        #print (field_type)
        if ("[" in field_type and is_a_Record) :
            record_type = recordType(field_type)
            arr_dims = get_array_dims(field_type)
            splitted_field_type = field_type.split()
            struct_type_name = splitted_field_type[splitted_field_type.index(record_type)+1]
            if (struct_type != struct_type_name):
                added_text+=handle_arrays(arr_dims,field_name,field_type,prefix,True,struct_type_name,struct_filepath,"i_"+str(index))
            else:
                #print(" Processing File Failed : name recursion " + str(struct_type)+"."+str(field_name)+"."+str(struct_type_name) +"\n")
                pass
        elif ("[" in field_type and (not is_a_Record) and "*" not in field_type):
            arr_dims = get_array_dims(field_type)
            added_text+=handle_arrays(arr_dims,field_name,field_type,prefix,False,"","","i_"+str(index))
        elif ("[" not in field_type and is_a_Record):
            splitted_field_type = field_type.split()
            record_type = recordType(field_type)
            if ("anonymous" in field_type):
                continue # TODO: Fix this corner case

            if ("*" not in field_type):
                struct_type_name = splitted_field_type[splitted_field_type.index(record_type)+1]
                if not field_name:
                    #print(" Processing File Failed : empty field name " + str(prefix)+"."+str(field_name)+ "\n")
                    pass
                elif ("."+field_name+"." not in prefix):
                    added_text+=handle_structs(prefix+"."+field_name,struct_type_name, struct_filepath)
                else:
                    #print(" Processing File Failed : name recursion " + str(prefix)+"."+str(field_name)+ "\n")
                    pass
            else:
                #print(" Processing File Failed : struct with pointers " + str(prefix)+"."+str(field_name)+ "\n")
                pass

        elif not("anonymous" in field_type) and ("*" not in field_type):
            if not field_name:
                #print(" Processing File Failed : empty field name " + str(prefix)+"."+str(field_name)+ "\n")
                pass
            else:
                var_name = prefix+"."+field_name
                added_text+="""\ttransparent_crc("""+var_name+""", """+f'"{var_name}"'+""", i_print_hash_value);\n"""
        index = index + 1

    return (added_text)

def handle_regular_decl(var_name):
    added_hash_code = ""
    # if '*' not in var_name:
    added_hash_code+="""\ttransparent_crc("""+var_name+""", """+f'"{var_name}"'+""", i_print_hash_value);\n"""
    return (added_hash_code)

# Process any program that got no headers and no array and structs
def get_simple_globals(filepath,program):
    added_hash_code = ""
    added_var_init = ""
    filehandle = open(filepath, 'rt')
    index = 0
    for line in filehandle.readlines():
        if (line == ""):
            continue
        else:
            var_name = line.split("\t")[0]
            var_type = line.split("\t")[1]
            if (("table" in var_name) or ("va_list" in var_type) or ("fptr" in var_type) or ("FILE" in var_name) or ("FILE" in var_type) or ("ptrs" in var_name) or ("buffer" in var_name) or ("jmp_buf" in var_name) or ("buf" in var_name) or ("extfunc" in var_name) or ("crc32_tab" in var_name) or ("endianness_test" in var_name) or ("offset" in var_name) or ("addr" in var_name) or ("stdout" in var_name) or ("stdin" in var_name) or ("stderr" in var_name) or ("sys_errlist" in var_name) or ("sys_nerr" in var_name) or ("crc32_context" in var_name) or ("crc32_tab" in var_name) or ("signgam" in var_name)):
                continue
            if (("anonymous" not in var_type) and ("(" in var_type)):
                continue
            if ("void" in var_type):
                continue
            
        ## Pointers are not null
        if ("*" in var_type):
            added_hash_code+="""\tif ("""+var_name+""" != 0) { \n\t""" ## Don't print if it is null!
            pointer_depth = var_type.count("*")
            var_name = "(" + ("*")*pointer_depth+var_name + ")";
        
        if ("[" in var_type) and ("*" not in var_type):
            arr_dims = get_array_dims(var_type)
            added_hash_code+=handle_arrays(arr_dims,var_name,var_type,"",False,"","","i_"+str(index))
        elif not("anonymous" in var_type):
            added_hash_code+=handle_regular_decl(var_name)
            initn=""" """+var_name+""";"""
            if (("const" not in line) and ("va_list" not in line) and ("*" not in var_name) and (initn in program)):
                added_var_init +="""\t"""+var_name+""" = 0;\n"""
        
        ## Close the brackets
        if ("*" in var_type):
            added_hash_code+="""\n}"""

        index = index + 1

    return (added_hash_code,added_var_init)

def add_var_printf_code(var_name, var_type):
    #print(var_type)
    printf_code = ""
    if var_type == 'int\n':
        printf_code = """\tprintf(\""""+var_name+""": %d ", """+var_name+""");\n"""
    elif var_type == 'short\n':
        printf_code = """\tprintf(\""""+var_name+""": %d ", """+var_name+""");\n"""
    elif var_type == 'long\n':
        printf_code = """\tprintf(\""""+var_name+""": %ld ", """+var_name+""");\n"""
    elif var_type == 'float\n':
        printf_code = """\tprintf(\""""+var_name+""": %f ", """+var_name+""");\n"""
    elif var_type == 'double\n':
        printf_code = """\tprintf(\""""+var_name+""": %lf ", """+var_name+""");\n"""
    elif var_type == 'char *\n':
        printf_code = """\tprintf(\""""+var_name[2:-1]+""": %s ", """+var_name[2:-1]+""");\n"""
    elif var_type == 'int16_t\n':
        printf_code = """\tprintf(\""""+var_name+""": %d ", """+var_name+""");\n"""
    elif var_type == 'int32_t\n':
        printf_code = """\tprintf(\""""+var_name+""": %d ", """+var_name+""");\n"""
    elif var_type == 'int64_t\n':
        printf_code = """\tprintf(\""""+var_name+""": %ld ", """+var_name+""");\n"""
    return printf_code

# Process programs that got arrays/stracts or headers
def get_globals(filepath,record_info_file,program):
    added_hash_code = ""
    added_var_init = ""
    filehandle = open(filepath, 'rt')
    index = 0
    for line in filehandle.readlines():
        if (line == ""):
            continue
        else:
            var_name = line.split("\t")[0]
            var_type = line.split("\t")[1]
            if (("table" in var_name) or ("va_list" in var_type) or ("fptr" in var_type) or ("FILE" in var_name) or ("FILE" in var_type) or ("ptrs" in var_name) or ("buffer" in var_name) or ("jmp_buf" in var_name) or ("extfunc" in var_name) or ("buf" in var_name) or ("crc32_tab" in var_name) or ("endianness_test" in var_name) or ("offset" in var_name) or ("addr" in var_name) or ("stdout" in var_name) or ("stdin" in var_name) or ("stderr" in var_name) or ("sys_errlist" in var_name) or ("sys_nerr" in var_name) or ("crc32_context" in var_name) or ("crc32_tab" in var_name) or ("signgam" in var_name)):    
                continue
            if (("anonymous" not in var_type) and ("(" in var_type)):
                continue
            if ("void" in var_type):
                continue

        ## Pointers are not null
        if ("*" in var_type):
            added_hash_code+="""\tif ("""+var_name+""" != 0)\n{\t""" ## Don't print if it is null! TODO: add it in a loop for pointer of a pointer
            pointer_depth = var_type.count("*")
            var_name = "(" + ("*")*pointer_depth+var_name + ")"
        is_a_Record = isRecord(var_type)

        # if all OK, then continue to deal with this field
        if is_a_Record and ("[" not in var_type):
            record_type = recordType(var_type)
            splitted_field_type = var_type.split()
            rec_name = splitted_field_type[splitted_field_type.index(record_type)+1]
            if ("anonymous" in rec_name):
                struct_field_type = extract_anon_name(' '.join(splitted_field_type[splitted_field_type.index(record_type)+1:]))
            else:
                struct_field_type = rec_name
#            struct_field_type = splitted_field_type[splitted_field_type.index(record_type)+1]
            added_hash_code += handle_structs(var_name,struct_field_type,record_info_file)
        elif ("[" in var_type and is_a_Record):
            record_type = recordType(var_type)
            arr_dims = get_array_dims(var_type)
            if ("_record" in var_type):
                var_type = var_type.replace("_record",'')
                splitted_field_type = var_type.split()
                rec_name = splitted_field_type[0]
            else:
                splitted_field_type = var_type.split()
                rec_name = splitted_field_type[splitted_field_type.index(record_type)+1]
            if ("anonymous" in rec_name):
                struct_type_name = extract_anon_name(' '.join(splitted_field_type[splitted_field_type.index(record_type)+1:]))
            elif ("_record" in rec_name):
                struct_type_name = rec_name.replace("_record",'')
            else:
                struct_type_name = rec_name
            added_hash_code+=handle_arrays(arr_dims,var_name,"",True,struct_type_name,record_info_file,"i_"+str(index))
            
        elif not(is_a_Record) and ("[" in var_type) and ("*" not in var_type):
            arr_dims = get_array_dims(var_type)
            added_hash_code+=handle_arrays(arr_dims,var_name,var_type,"",False,"","","i_"+str(index))
        # elif not("anonymous" in var_type) and ("*" not in var_type):
        elif not("anonymous" in var_type):
            added_hash_code += handle_regular_decl(var_name)
            added_hash_code += add_var_printf_code(var_name, var_type)
            initn=""" """+var_name+""";"""
            if (("const" not in line) and ("va_list" not in line) and ("*" not in var_name) and (initn in program)):
                added_var_init +="""\t"""+var_name+""" = 0;\n"""

        ## Close the brackets
        if ("*" in var_type):
            added_hash_code+="""\n}"""

        index = index + 1
    #added_hash_code += """\tprintf("\\n");\n"""
    #print(added_hash_code)
    return (added_hash_code,added_var_init)

def create_copy(filename,copy_filename):
    copyfile(filename, copy_filename)

def extract_anon_name(full_name):
    first_colon_loc = full_name.find(':')
    second_colon_loc = full_name.find(':',first_colon_loc+1)
    #print(full_name)
    return (full_name[first_colon_loc+1:second_colon_loc])

def parse_CProgram(orig_filepath,copy_filepath,global_vars_file, main_info_file, record_info_file):
    """
    Parse text at given filepath

    Parameters
    ----------
    filepath : str
        Filepath for file_object to be parsed

    Returns
    -------
    data : new file


    """

    # Readint the original program
    filehandle = open(orig_filepath, 'rt')
    program=""
    try:
        program = filehandle.read()
    except ValueError:
        filehandle = open(orig_filepath, 'rt', encoding='latin-1') # in case the program contains strange chars
        try:
            program = filehandle.read()
        except ValueError:
            #print(" Processing File Reading Program as Unicode Failed : " + str(orig_filepath) + "\n")
            return None

    # Preparing the rest of the files needed
    filehandle_new = open(copy_filepath, 'wt')
    main_sign_filehandle = open(main_info_file,'rt')
    main_sign = main_sign_filehandle.read()


    # Avoid adding code around the definition of these functions - rename them back in the end
    program = program.replace("myprintf" ,"xxxmyp_rintf")
    program = program.replace("sprintf" ,"xxxp_rintf")
    program = program.replace("snprintf","xxxsnp_rintf")
    program = program.replace("int printf", "int ____dummy_p_rint_x")
    program = program.replace("int fprintf", "int ____dummy_fp_rintf_x")
    
    program = program.replace("extern void abort", "void ____dummy_ext_a_bort_x")
    program = program.replace("void abort", "void ____dummy_a_bort_x")
    program = program.replace("extern void exit", "void ____dummy_ext_e_xit_x")
    program = program.replace("void exit", "void ____dummy_e_xit_x")

    program = program.replace("vprintf", "____dummy_vp_rintf_x")
    #program = program.replace("__printf", "____dummy___p_rintf_x")
    program = program.replace("printf-", "____dummy_p_rintf-_x")
    program = program.replace("_printf_float", "____dummy_p_rintf_float-_x")
    program = program.replace("fprintf-chk", "____dummy_fp_rintf-chk_x")
    program = program.replace("__fprintf_chk", "____dummy___fp_rintf_chk_x")
    program = program.replace("vfprintf", "____dummy_vfp_rintf_x")

    # We are adding csmith.h which will add FILE from a proper C header
    if ("signbit" in program):
        program = program.replace("signbit(double", "signbittt(double")
        program = program.replace("signbit(float", "signbittt(float")
        program = program.replace("signbit(long", "signbittt(long")
        program = program.replace("signbit(int", "signbittt(int")
        program = program.replace("signbit(short", "signbittt(short")
        program = program.replace("signbit(char", "signbittt(char")
        program = program.replace("signbit(unsigned", "signbittt(unsigned")

    if ("typedef void *FILE;" in program):
        program = program.replace("FILE", "____FILEx")

    if ("cbrtl"  in program):
        program = program.replace("cbrtl", "____cbrtlx")

    # if base program can be coverted with abort or exit
    if (("20000819-1.c" not in program) and ("pr32500.c" not in program) and ("981130-1.c" not in program)):
        program = program.replace("exit (0)", "return 0")
        program = program.replace("exit(0)", "return 0")

    if ("void do_abort(void) { abort(); }" in program):
        program = program.replace("void do_abort(void) { abort(); }","void do_abort(void) { make_global_a_b_o_r_t(); return 0; abort(); }")
    if (("20020810-1.c" not in program) and ("20030313-1.c" not in program) and ("20080604-1.c" not in program) and ("= {abort};" not in program) and ("stdarg-1.c" not in program) and ("stdarg-2.c" not in program) and ("stdarg-4.c" not in program) and ("pr88714.c" not in program) and ("pr69691.c" not in program) and ("pr61673.c" not in program) and ("pr56205.c" not in program) and ("pr49161.c" not in program) and ("pr41919.c" not in program) and ("? abort()" not in program) and ("? abort ()" not in program) and ("if (!(x)) abort" not in program) and ("if(!(x)) abort" not in program) and ("if (!(X)) abort" not in program) and ("if (!(X)) { abort ()" not in program) and ("if(!(X)) { abort()" not in program) and ("if (!(x)) { abort ()" not in program) and ("if(!(x)) { abort()" not in program) and ("__builtin_abort()))" not in program)):
        # Abort - programs use either this or that notation 
        if ("__builtin_abort" in program):
            program = program.replace("__builtin_abort","make_global_a_b_o_r_t(); return 0; __builtin_abort")
        elif (("abort(" in program) and ("_abort" not in program)):
            program = program.replace("abort(","make_global_a_b_o_r_t(); return 0; abort(")
        elif (("abort (" in program) and ("_abort" not in program)):
            program = program.replace("abort (","make_global_a_b_o_r_t(); return 0; abort (")

    # Exit - to output + return
    if (("_exit" not in program) and ("-exit" not in program)):
        if ("exit (" in program):
            program = program.replace("exit (","make_global_e_x_i_t(); return 0; exit (")
        if ("exit(" in program):
            program = program.replace("exit(","make_global_e_x_i_t(); return 0; exit(")

    # printf functions into sprintf
    if (("if (printf (args)" not in program) and ("if(printf(args)" not in program) and ("if (fprintf" not in program) and ("if(fprintf" not in program) and ("strlen-6.c" not in program) and ("strlen-5.c" not in program) and (": (__builtin_printf" not in program) and (":(__builtin_printf" not in program) and (": printf" not in program) and (":printf" not in program)):
        # sprintf, fprintf and printf - we also replace sprint xxxprintf and back to avoid issues while replacing!
        if ("sprintf(" in program):
            program =  program.replace("sprintf","xxxp_rintf")        
        if ("__builtin_printf(" in program):
            program =  program.replace("__builtin_printf(","make_global(__wrapper_val); xxxp_rintf(__wrapper_val,")
        if ("__builtin_printf (" in program):
            program =  program.replace("__builtin_printf (","make_global(__wrapper_val); xxxp_rintf(__wrapper_val,")
        if ("__builtin_printf" in program):
            #print(" Processing File __builtin_printf Parsing Failed : " + str(orig_filepath) + "\n")
            pass
        if ("fprintf(" in program):
            program =  program.replace("fprintf(","make_global(__wrapper_val); xxxp_rintf(__wrapper_val,")
        if ("fprintf (" in program):
            program =  program.replace("fprintf (","make_global(__wrapper_val); xxxp_rintf(__wrapper_val,")
        if ("fprintf" in program):
            #print(" Processing File fprintf Parsing Failed : " + str(orig_filepath) + "\n")
            pass
        if ("printf(" in program):
            program =  program.replace("printf(","make_global(__wrapper_val); xxxp_rintf(__wrapper_val,")
        if ("__printf_chk(" in program):
            program =  program.replace("__printf_chk(1, ","make_global(__wrapper_val); xxxp_rintf(__wrapper_val,")
        if ("printf (" in program):
            program =  program.replace("printf (","make_global(__wrapper_val); xxxp_rintf(__wrapper_val,")
        if ("printf" in program):
            #print(" Processing File printf Parsing Failed : " + str(orig_filepath) + "\n")
            pass
    elif (("if (printf (args)" not in program) and ("if(printf(args)" not in program) and ("if (fprintf" not in program) and ("if(fprintf" not in program) and ("strlen-6.c" not in program) and ("strlen-5.c" not in program) and (": printf" not in program) and (": (__builtin_printf" not in program)):
        # Carefully try to take care of __builtin_printf
        if ("sprintf(" in program):
            program =  program.replace("sprintf","xxxp_rintf")
        if (" __builtin_printf(" in program):
            program =  program.replace(" __builtin_printf(","make_global(__wrapper_val); xxxp_rintf(__wrapper_val,")
        if (" printf(" in program):
            program =  program.replace(" printf(","make_global(__wrapper_val); xxxp_rintf(__wrapper_val,")
        if (" printf (" in program):
            program =  program.replace(" printf (","make_global(__wrapper_val); xxxp_rintf(__wrapper_val,")
        if ("printf" in program):
            #print(" Processing File printf Parsing Failed : " + str(orig_filepath) + "\n")
            pass

    if ("return make_global(__wrapper_val); xxxp_rintf(__wrapper_val," in program):
        program = program.replace("return make_global(__wrapper_val); xxxp_rintf(__wrapper_val,", "make_global(__wrapper_val); return xxxp_rintf(__wrapper_val,")

    # replace back xxxprintf to sprintf after finished it all
    program = program.replace("xxxmyp_rintf", "myprintf")
    program = program.replace("xxxp_rintf","sprintf")
    program = program.replace("xxxsnp_rintf","snprintf")
    program = program.replace("int ____dummy_p_rint_x", "int printf")
    program = program.replace("int ____dummy_fp_rintf_x", "int fprintf")
    
    program = program.replace("void ____dummy_ext_a_bort_x", "extern void abort")
    program = program.replace("void ____dummy_a_bort_x", "void abort")
    program = program.replace("void ____dummy_ext_e_xit_x", "extern void exit")
    program = program.replace("void ____dummy_e_xit_x", "void exit")

    program = program.replace("____dummy_vp_rintf_x", "vprintf")
    program = program.replace("____dummy___p_rintf_x", "__printf")
    program = program.replace("____dummy_p_rintf-_x", "printf-")
    program = program.replace("____dummy_p_rintf_float-_x", "_printf_float")
    program = program.replace("____dummy_fp_rintf-chk_x", "fprintf-chk")
    program = program.replace("____dummy___fp_rintf_chk_x", "__fprintf_chk")
    program = program.replace("____dummy_vfp_rintf_x", "vfprintf")

    ## Adding new main, transformation is done before this script, in script 0
    func0="func_0();"
    if ("main(int argc, char *argv[])" in program):
        program = program.replace("main(int argc, char *argv[])","func_0(int argc, char *argv[])")   
        func0="func_0(argc,argv);"
    elif ("int main(j)" in program):
        program = program.replace("int main(j)","int func_0(j)")
        func0="func_0(0);"
    elif ("int main(h)" in program):
        program = program.replace("int main(h)","int func_0(h)")
        func0="func_0(0);"
    elif ("main(int argc, char ** argv)" in program):
        program = program.replace("main(int argc, char ** argv)","func_0(int argc, char ** argv)")
        func0="func_0(argc, argv);"
    elif (main_sign in program):
        new_main_sign = main_sign
        new_main_sign = main_sign.replace("main","func_0")
        if ("(void)" in new_main_sign):
            new_main_sign = new_main_sign
        elif ("void" in new_main_sign):
            new_main_sign = new_main_sign.replace("void","int")
        program = program.replace(main_sign, new_main_sign)
    elif (("main()" in program)):
        program = program.replace("main()","func_0()")
    else:
        #print(" Processing File Main Failed : " + str(orig_filepath + "\n"))
        pass

    make_global_function_body = """
int i_csmith_transform = 0;
int i_print_hash_value = 0;
int make_global_a_b_o_r_t(){
\ttransparent_crc(i_csmith_transform, "abort call", i_print_hash_value);
\ti_csmith_transform=i_csmith_transform+1;
\treturn 0;
} \n
int make_global_e_x_i_t(){
\ttransparent_crc(i_csmith_transform, "abort exit", i_print_hash_value);
\ti_csmith_transform=i_csmith_transform+1;
\treturn 0;
} \n
int make_global(char *val){
\tif ((val == 0) || (strlen(val) == 0)) {
\t\ttransparent_crc(i_csmith_transform, "empty string", i_print_hash_value);
\t} else {
\t\tchar name[100]; sprintf(name, "gprnt%d", i_csmith_transform);
\t\ttransparent_crc_bytes(val, strlen(val), name , i_print_hash_value);
\t}
\ti_csmith_transform=i_csmith_transform+1;
\treturn 0;
} \n"""
    main_function_body = """int main(int argc, char* argv[]){
\tif (argc == 2 && strcmp(argv[1], "1") == 0) i_print_hash_value = 1;
\tplatform_main_begin();
\tcrc32_gentab();
"""
    func0_wrapper = """
\t"""+str(func0)+""" /* Original main of the program */
\tmake_global(__wrapper_val); /* Print the last use of the wrapper, or if never used it will print empty string */
"""
    if (os.path.exists(global_vars_file) and os.path.exists(record_info_file)):
        result=get_globals(global_vars_file,record_info_file,program)
        main_function_body+=func0_wrapper + result[0]
    elif (os.path.exists(global_vars_file)):
        result=get_simple_globals(global_vars_file,program)
        main_function_body+=func0_wrapper +  result[0]
    else:
        main_function_body+=func0_wrapper

    main_function_body+= """\tplatform_main_end(crc32_context ^ 0xFFFFFFFFUL, i_print_hash_value);
\tprintf("End of program\\n");
\treturn 0;
}
\t"""
    
    # Add new file with all the changes
    filehandle_new.write(program)

    filehandle_new.write(make_global_function_body)
    filehandle_new.write(main_function_body)
    filehandle.close()
    filehandle_new.close()
    add_headers(copy_filepath,"""#include \"csmith.h\"\nint make_global(char *);\nint make_global_a_b_o_r_t();\nint make_global_e_x_i_t();\nchar __wrapper_val[256]=\"I\";\n
""")

def clean(global_vars_file, main_info_file, record_info_file):
    if (os.path.exists(global_vars_file)):
        os.remove(global_vars_file)
    if (os.path.exists(main_info_file)):
        os.remove(main_info_file)
    if (os.path.exists(record_info_file)):
        os.remove(record_info_file)

def add_state_tracking(orig_f, state_f, add_libs):

    abs_path = os.path.abspath(orig_f)
    file_dir = os.path.dirname(abs_path)

    add_libs = add_libs + " -I/usr/local/lib/clang/18/include/"#" -I/usr/include/linux/"
    cwd = os.getcwd()
    create_copy(os.path.join(file_dir, orig_f), state_f)

    bin2wrong_path = str(os.environ.get('BIN2WRONGPATH'))

    global_vars_file = str(os.getenv("GLOBAL_INFO_TXT", os.path.join(bin2wrong_path, "Global-Info.txt")))
    main_info_file = str(os.environ.get('MAIN_SIGN_TXT', os.path.join(bin2wrong_path, "Main-Sign.txt")))
    record_info_file = str(os.environ.get('RECORD_INFO_TXT', os.path.join(bin2wrong_path, "Record-Info.txt")))

    if (os.path.exists(global_vars_file)):
        os.remove(global_vars_file)
    if (os.path.exists(main_info_file)):
        os.remove(main_info_file)
    if (os.path.exists(record_info_file)):
        os.remove(record_info_file)

    ctag_command = os.path.join(bin2wrong_path, 'post_decompilation/global_extractor/global-extractor')+' '+ os.path.join(file_dir, orig_f)  +' -- --no-warnings ' + add_libs + ' > /dev/null 2>&1'
    os.system (ctag_command)

    ret = status.OKAY
    if (os.path.exists(global_vars_file) and os.path.exists(main_info_file)): # ==> check later and os.path.exists(record_info_file)):
        data = parse_CProgram(os.path.join(file_dir, orig_f), state_f, global_vars_file, main_info_file, record_info_file)
    elif (os.path.exists(main_info_file)):
        data = parse_CProgram(os.path.join(file_dir, orig_f), state_f, global_vars_file, main_info_file, record_info_file)
    elif (os.path.exists(global_vars_file)):
        add_headers(state_f,"""/* Global but no valid main */""")
        ret = status.ERROR
    else:
        add_headers(state_f,"""/* No Global Variable and no valid main */""")
        ret = status.ERROR
    
    clean(global_vars_file, main_info_file, record_info_file)
    return ret

if __name__ == '__main__':

    input_args = sys.argv
    add_libs = ""
    if (len(input_args)>3):
        for i in range(2,len(input_args)):
            add_libs = add_libs + " -I" + input_args[i]

    add_state_tracking(sys.argv[1], sys.argv[2], add_libs)
