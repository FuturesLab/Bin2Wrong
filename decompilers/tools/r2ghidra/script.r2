# apply relocation
e bin.relocs.apply=true

# disable colored output
e scr.color=0

# automatically analyze all
aaa

# use Ghidra decompiler on all functions
pdg @@ * > PATH_TO_TMP/dec_default.c