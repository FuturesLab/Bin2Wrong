## Post decompilation scripts:

`post_dec.py` is used as a script that runs each time after AFL++ executes the target decompiler.

It first fixes the decompiled C code (`fix_dec.replace_function`), trying to make it re-compilable.

If re-compilable, it will use `enhanCer.add_state_tracking` to inject state-tracking code into both the decompiled C file and the original one.

After compiling the two injected code files, it compares the execution results.

If different, it returns `1` to the AFL++, which has been modified (see [../AFLplusplus/README.md](../AFLplusplus/README.md).), and will save the test case into `crashes/` folder of AFL++'s fuzzing output directory.
