#include <stdint.h>
#include <string.h>

#include "address.h"
#include "utils.h"
#include "params.h"
#include "hashx8.h"
#include "sm3.h"
#include "sm3x8.h"
#include "sm3avx.h"

/*
 * 8-way parallel version of prf_addr; takes 8x as much input and output
 */
void prf_addrx8(unsigned char *out0,
                unsigned char *out1,
                unsigned char *out2,
                unsigned char *out3,
                unsigned char *out4,
                unsigned char *out5,
                unsigned char *out6,
                unsigned char *out7,
                const unsigned char *key,
                const uint32_t addrx8[8*8])
{
    unsigned char bufx8[8 * (SPX_N + SPX_SM3_ADDR_BYTES)];
    unsigned char outbufx8[8 * SPX_SM3_OUTPUT_BYTES];
    unsigned int j;

    for (j = 0; j < 8; j++) {
        memcpy(bufx8 + j*(SPX_N + SPX_SM3_ADDR_BYTES), key, SPX_N);
        memcpy(bufx8 + SPX_N + j*(SPX_N + SPX_SM3_ADDR_BYTES),
                         addrx8 + j*8, SPX_SM3_ADDR_BYTES);
    }

    sm3x8(
        /* out */
        outbufx8 + 0*SPX_SM3_OUTPUT_BYTES,
        outbufx8 + 1*SPX_SM3_OUTPUT_BYTES,
        outbufx8 + 2*SPX_SM3_OUTPUT_BYTES,
        outbufx8 + 3*SPX_SM3_OUTPUT_BYTES,
        outbufx8 + 4*SPX_SM3_OUTPUT_BYTES,
        outbufx8 + 5*SPX_SM3_OUTPUT_BYTES,
        outbufx8 + 6*SPX_SM3_OUTPUT_BYTES,
        outbufx8 + 7*SPX_SM3_OUTPUT_BYTES,
        bufx8 + 0*(SPX_SM3_ADDR_BYTES + SPX_N),
        bufx8 + 1*(SPX_SM3_ADDR_BYTES + SPX_N),
        bufx8 + 2*(SPX_SM3_ADDR_BYTES + SPX_N),
        bufx8 + 3*(SPX_SM3_ADDR_BYTES + SPX_N),
        bufx8 + 4*(SPX_SM3_ADDR_BYTES + SPX_N),
        bufx8 + 5*(SPX_SM3_ADDR_BYTES + SPX_N),
        bufx8 + 6*(SPX_SM3_ADDR_BYTES + SPX_N),
        bufx8 + 7*(SPX_SM3_ADDR_BYTES + SPX_N),
        SPX_SM3_ADDR_BYTES + SPX_N /* len */
    );

    memcpy(out0, outbufx8 + 0*SPX_SM3_OUTPUT_BYTES, SPX_N);
    memcpy(out1, outbufx8 + 1*SPX_SM3_OUTPUT_BYTES, SPX_N);
    memcpy(out2, outbufx8 + 2*SPX_SM3_OUTPUT_BYTES, SPX_N);
    memcpy(out3, outbufx8 + 3*SPX_SM3_OUTPUT_BYTES, SPX_N);
    memcpy(out4, outbufx8 + 4*SPX_SM3_OUTPUT_BYTES, SPX_N);
    memcpy(out5, outbufx8 + 5*SPX_SM3_OUTPUT_BYTES, SPX_N);
    memcpy(out6, outbufx8 + 6*SPX_SM3_OUTPUT_BYTES, SPX_N);
    memcpy(out7, outbufx8 + 7*SPX_SM3_OUTPUT_BYTES, SPX_N);
}
