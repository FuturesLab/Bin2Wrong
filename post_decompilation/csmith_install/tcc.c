#include <math.h>

float fabsf(float x) {
    return x < 0 ? -x : x;
}

double fabs(double x) {
    return x < 0 ? -x : x;
}