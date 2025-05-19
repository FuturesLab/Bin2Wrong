from pathlib import Path
import os, subprocess


def reko(input=str(os.environ.get('ORIGINAL_EXEC_PATH')), output=str(os.environ.get('DECOM_CODE_PATH'))):
    infile = Path(input)
    outputs = Path(str(infile).replace('.exe', '') + ".reko")

    seen = set()
    code = b''
    for source in outputs.glob('*text*.c'):
        with open(source, 'rb') as f:
            seen.add(source)
            code += f.read()
    for source in outputs.glob('*.c'):
        if source in seen:
            continue
        if "_data.c" in str(source):
            with open(source, 'rb') as f:
                global_vars = [line for line in f if not any(keyword in line for keyword in [b"#include", b"&"]) and line[0] != 47 and line[0] != 10]
                code += b"//GLOBAL\n"
                for l in global_vars:
                    code += l
                code += b"//GLOBAL\n"
        else:
                with open(source, 'rb') as f:
                    code += f.read()

    with open(output, 'wb') as file:
        file.write(code)

def revng(input, revng_artifact_path, output=str(os.environ.get('DECOM_CODE_PATH'))):
    revng_dir = str(Path(revng_artifact_path).parents[3])
    revng_wrapper_path = os.path.join(revng_dir, "revng")

    ptml_to_code = "{} ptml {} -o {}".format(revng_wrapper_path, input, output)
    os.system(ptml_to_code)