#include "afl-fuzz.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

typedef struct my_mutator {
    afl_state_t *afl;
    u8 *mutated_out;
} my_mutator_t;

// for storing bytes mapped to flags
typedef struct flags_bytes {
    size_t size;
    uint8_t *bytes;
    uint8_t *bytes_alt;
} flags_bytes;

// for storing C code
typedef struct src_code {
    size_t size;
    uint8_t *code;
    char *code_alt;
} src_code;

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  srand(seed);

  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));

  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  if ((data->mutated_out = (u8 *)malloc(MAX_FILE)) == NULL) {

    perror("afl_custom_init malloc");
    return NULL;

  }

  data->afl = afl;

  return data;

}

// Write mutated C code to SOURCE_FILE_PATH (config.compile.srcfile)
void write_mutated_src_to_file(const uint8_t *src, size_t size) {
    const char *mutatedSrcCode = getenv("ORIGINAL_CODE_PATH");

    FILE *src_f = fopen(mutatedSrcCode, "wb");
    if (src_f == NULL) {
      perror("Error opening file");
      return;
    }
    size_t elements_written = fwrite(src, 1, size, src_f);
    fclose(src_f);
}

size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size, u8 **out_buf, uint8_t *add_buf, size_t add_buf_size, size_t max_size) {
    flags_bytes *flagsBuf = calloc(1, sizeof(flags_bytes));
    src_code *codeBuf = calloc(1, sizeof(src_code));
  
    flagsBuf->bytes = (u8 *)malloc(MAX_FILE);
    flagsBuf->bytes_alt = (uint8_t *)malloc(MAX_FILE);
    codeBuf->code = (u8 *)malloc(MAX_FILE);
    codeBuf->code_alt = (char *)malloc(MAX_FILE);

    flagsBuf->size = 2048; // default number of bytes
    codeBuf->size = buf_size - flagsBuf->size;

    // copy bytes into flagsBuf
    memcpy(flagsBuf->bytes, buf, flagsBuf->size);
    // copy C code into codeBuf
    memcpy(codeBuf->code, buf + flagsBuf->size, codeBuf->size);

    // C code mutation, see srccode-mutators/CodeMutators.cpp
    src_code_mutation(codeBuf->code, codeBuf->size, codeBuf->code_alt);

    // get the length of mutated C code
    codeBuf->size = strlen(codeBuf->code_alt);
    // replace original C code with the mutated one
    memcpy(codeBuf->code, codeBuf->code_alt, codeBuf->size);

    // write mutated c code into disk for compilation
    write_mutated_src_to_file(codeBuf->code, codeBuf->size);
    // compilation optimization mutation, see compilation-mutators/CompilationMutators.cpp
    compilation_mutation(flagsBuf->bytes, flagsBuf->size, flagsBuf->bytes_alt);

    // concatenate mutated flag bytes and mutated c code
    memcpy(data->mutated_out, flagsBuf->bytes_alt, flagsBuf->size);
    memcpy(data->mutated_out+flagsBuf->size, codeBuf->code, codeBuf->size);

    // the output buffer size
    size_t out_size = flagsBuf->size + codeBuf->size;
    *out_buf = data->mutated_out;

    free(flagsBuf->bytes);
    free(flagsBuf->bytes_alt);
    flagsBuf->bytes = NULL;
    flagsBuf->bytes_alt = NULL;
    free(flagsBuf);

    free(codeBuf->code);
    free(codeBuf->code_alt);
    codeBuf->code = NULL;
    codeBuf->code_alt = NULL;
    free(codeBuf);
    
    return out_size;
}



void afl_custom_deinit(my_mutator_t *data) {

  free(data->mutated_out);
  free(data);

}
