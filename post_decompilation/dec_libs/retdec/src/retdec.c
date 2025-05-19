#include <stdint.h>
#include <stdlib.h>

typedef int64_t int128_t;

float __asm_movss(float a){

    return a;
}

float __asm_movaps(float a) {

    return a;
}

double __asm_movsd(double a) {

    return a;
}

int64_t __asm_movq(int64_t a) {

    return a;
}

double __asm_mulsd(double a, double b){
    return a * b;
}

int32_t __asm_cvttsd2si(double a){

    return a;
}

int64_t __asm_xorps(int64_t a, int64_t b){

    return a ^ b;
}

double __asm_cvtsi2sd(int64_t a){

    return a;
}

double __asm_cvtss2sd(float a){

    return a;
}

double __asm_addsd(double a, double b) {
    return a + b;
}

double __asm_subsd(double a, double b){
    return a - b;
}