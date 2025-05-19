# American Fuzzy Lop plus plus (AFL++)

This is a modified version of [AFL++](https://github.com/AFLplusplus/AFLplusplus) 4.09c.

It retrieves the return value of `[Bin2Wrong]/post_decompilation/post_dec.py`. If the value is 1, it will save the test case as `Crash`.

A newer version may be used for Bin2Wrong, but the following changes need to be made:

## include/afl-fuzz.h:

1. **`void`**` (*afl_custom_post_run)` => **`u8`**` (*afl_custom_post_run)`

2. **`void`**` post_run_py(void *);` => **`u8`**` post_run_py(void *);`

## src/afl-fuzz-python.c:

1. **`void`**` post_run_py(void *py_mutator)` => **`u8`**` post_run_py(void *py_mutator)`

2. `Py_DECREF(py_value);` => 
```
long ret = PyLong_AsLong(py_value);
Py_DECREF(py_value);
return (u8)ret;
```
## src/afl-fuzz-run.c:
```
if (unlikely(el->afl_custom_post_run)) {

    el->afl_custom_post_run(el->data);

    }
```
=>
```
if (unlikely(el->afl_custom_post_run)) { 
    u8 post_run_ret = el->afl_custom_post_run(el->data); 
    if(post_run_ret == 1 && res == FSRV_RUN_OK){
      res = FSRV_RUN_CRASH;
    }
}
```

Then, build AFL++.