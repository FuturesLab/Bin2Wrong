#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: ./run_fuzz.sh [decompiler_to_be_fuzzed]"
    exit 1
fi

CONFIGFILE=configs/config-$1.json

export AFL_DISABLE_TRIM=1
export AFL_CUSTOM_MUTATOR_ONLY=1 

export BIN2WRONGPATH=$(jq -r '.Bin2Wrong.path' $CONFIGFILE)
AFLINPUT=$BIN2WRONGPATH/$(jq -r '.Bin2Wrong.fuzzingDir' $CONFIGFILE)/input/
export AFLOUTPUT=$BIN2WRONGPATH/$(jq -r '.Bin2Wrong.fuzzingDir' $CONFIGFILE)/output/

export AFL_CUSTOM_MUTATOR_LIBRARY=$BIN2WRONGPATH/$(jq -r '.Bin2Wrong.mutator' $CONFIGFILE)
export PYTHONPATH=$BIN2WRONGPATH/$(jq -r '.Bin2Wrong.postdecDir' $CONFIGFILE)
export AFL_PYTHON_MODULE=$(jq -r '.Bin2Wrong.postdecName' $CONFIGFILE)

QEMU=$(jq -r '.Bin2Wrong.qemu' $CONFIGFILE)
if [ "$QEMU" == "true" ]; then
    QEMUCMD="-Q"
else
    QEMUCMD=""
fi

export COMPILER=$(jq -r '.compile.compiler' $CONFIGFILE)

export CLANG_FLAGS=$BIN2WRONGPATH/$(jq -r '.compile.clangflags' $CONFIGFILE)
export GCC_FLAGS=$BIN2WRONGPATH/$(jq -r '.compile.gccflags' $CONFIGFILE)
export TCC_FLAGS=$BIN2WRONGPATH/$(jq -r '.compile.tccflags' $CONFIGFILE)
export ICX_FLAGS=$BIN2WRONGPATH/$(jq -r '.compile.icxflags' $CONFIGFILE)
export MSVC_FLAGS=$BIN2WRONGPATH/$(jq -r '.compile.msvcflags' $CONFIGFILE)

export CSMITH_RUNTIME=$BIN2WRONGPATH/$(jq -r '.compile.csmith' $CONFIGFILE)
export GNU=$(jq -r '.compile.gnu' $CONFIGFILE)

export ICX=$(jq -r '.compile.icx' $CONFIGFILE)
export MSVC=$(jq -r '.compile.msvc' $CONFIGFILE)
export MSVCINC=$(jq -r '.compile.msvcinc' $CONFIGFILE)
export MSVCLIB=$(jq -r '.compile.msvclib' $CONFIGFILE)
export WIN2LIN=$(jq -r '.compile.win2lin' $CONFIGFILE)

export DECOMPILER=$(jq -r '.decompile.decompiler' $CONFIGFILE)
DECOMPILER_PATH=$(jq -r '.decompile.decompilerpath' $CONFIGFILE)
DECLIBCONFIG=$(jq -r '.decompile.declib' $CONFIGFILE)
if [ "$DECLIBCONFIG" == "" ]; then
    export DECLIB=$DECLIBCONFIG
else
    export DECLIB=$BIN2WRONGPATH/$DECLIBCONFIG
fi

export TMP_FOLDER=$BIN2WRONGPATH/$(jq -r '.Bin2Wrong.fuzzingDir' $CONFIGFILE)/tmp/
export TMPDIR=$BIN2WRONGPATH/$(jq -r '.Bin2Wrong.fuzzingDir' $CONFIGFILE)/tmp/

export MAIN_SIGN_TXT=$TMP_FOLDER/Main-Sign.txt
export GLOBAL_INFO_TXT=$TMP_FOLDER/Global-Info.txt
export RECORD_INFO_TXT=$TMP_FOLDER/Record-Info.txt

export ORIGINAL_CODE_PATH=$TMP_FOLDER/orig.c
export ORIGINAL_EXEC_PATH=$TMP_FOLDER/orig_exec
export USED_FLAGS_PATH=$TMP_FOLDER/used_flags.txt
export DECOM_CODE_PATH=$TMP_FOLDER/dec_default.c
export DECOM_CODE_FIXED_PATH=$TMP_FOLDER/dec.c
export FAULTY_FLAGS_PATH=$TMP_FOLDER/error_flags.txt

mkdir $TMP_FOLDER
cd AFLplusplus/

if [ "$DECOMPILER" == "retdec" ]; then
    (./afl-fuzz -i $AFLINPUT -o $AFLOUTPUT $QEMUCMD -t 90000 -- $DECOMPILER_PATH $ORIGINAL_EXEC_PATH --output $DECOM_CODE_PATH --cleanup --silent)
elif [ "$DECOMPILER" == "r2ghidra" ]; then
    sed "s|DECOUTPUT|${DECOM_CODE_PATH}|g" $TMP_FOLDER/../script_env.r2 > $TMP_FOLDER/../script.r2
    (AFL_INST_LIBS=1 ./afl-fuzz -i $AFLINPUT -o $AFLOUTPUT $QEMUCMD -t 90000 -- $DECOMPILER_PATH -q -i $TMP_FOLDER/../script.r2 $ORIGINAL_EXEC_PATH)
elif [ "$DECOMPILER" == "bn" ]; then
    (AFL_QEMU_INST_RANGES=libbinaryninjacore.so.1 ./afl-fuzz -i $AFLINPUT -o $AFLOUTPUT $QEMUCMD -t 90000 -- $DECOMPILER_PATH $ORIGINAL_EXEC_PATH $DECOM_CODE_PATH)
elif [ "$DECOMPILER" == "reko" ]; then
    (AFL_INST_LIBS=1 ./afl-fuzz -i $AFLINPUT -o $AFLOUTPUT $QEMUCMD -t 90000 -- $DECOMPILER_PATH $ORIGINAL_EXEC_PATH)
elif [ "$DECOMPILER" == "revng" ]; then
    export REVNG_ARTIFACT_PATH=$DECOMPILER_PATH
    (AFL_INST_LIBS=1 ./afl-fuzz -i $AFLINPUT -o $AFLOUTPUT $QEMUCMD -t 90000 -- $DECOMPILER_PATH -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngcPromoteStackPointer.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngcRestructureCFG.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngcSupport.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngcImportFromCAnalysis.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngFunctionIsolation.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngcBackend.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngTypeShrinking.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngBasicAnalyses.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngModelImporterBinary.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngcTypeNames.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngcDataLayoutAnalysis.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngYieldPipes.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngcModelToHeader.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngcInitModelTypes.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngcHelpersToHeader.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngABI.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngcMLIRPipes.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngABIAnalyses.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngcCanonicalize.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngModelImporter.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngcRemoveLiftingArtifacts.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngcRemoveExtractValues.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngEarlyFunctionAnalysis.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngRecompile.so -load DECOMPILERS_DIR/revng/root/lib64/revng/analyses/librevngModel.so -P DECOMPILERS_DIR/revng/root/share/revng/pipelines/revng-pipelines.yml -P DECOMPILERS_DIR/revng/root/share/revng/pipelines/revng-c-pipelines.yml --analyze decompile-to-single-file $ORIGINAL_EXEC_PATH -o $TMP_FOLDER/dec.ptml)
elif [ "$DECOMPILER" == "relyze" ]; then
    (AFL_SKIP_BIN_CHECK=1 ./afl-fuzz -i $AFLINPUT -o $AFLOUTPUT -t 90000 -m none -n -- $DECOMPILER_PATH $ORIGINAL_EXEC_PATH $DECOM_CODE_PATH)
elif [ "$DECOMPILER" == "angr" ]; then
    (AFL_SKIP_BIN_CHECK=1 ./afl-fuzz -i $AFLINPUT -o $AFLOUTPUT -t 90000 -m none -n -- $DECOMPILER_PATH $ORIGINAL_EXEC_PATH $DECOM_CODE_PATH)
else
    (echo 'decompiler not supported, add its config file and modify run_fuzz.sh')
fi