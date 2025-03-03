#include <stdint.h>
#include <string.h>

#include "thash.h"
#include "address.h"
#include "params.h"
#include "utils.h"
#include "sm3.h"

/**
 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
 */
void thash(unsigned char *out, const unsigned char *in, unsigned int inblocks,  
           const unsigned char *pub_seed, uint32_t addr[8])  
{  
    unsigned char buf[SPX_SM3_ADDR_BYTES + inblocks * SPX_N];  
    unsigned char outbuf[SPX_SM3_OUTPUT_BYTES];  
    uint8_t sm3_state[40];
    (void)pub_seed; /* Suppress an 'unused parameter' warning. */  
  
    /* Concatenate address and input data */  
    memcpy(sm3_state, state_seeded, 40 * sizeof(uint8_t));
    memcpy(buf, addr, SPX_SM3_ADDR_BYTES);  
    memcpy(buf + SPX_SM3_ADDR_BYTES, in, inblocks * SPX_N);  
  
    /* Compute SM3 hash */  
    //sm3(outbuf, buf, SPX_SM3_ADDR_BYTES + inblocks * SPX_N);  
    sm3_inc_finalize(outbuf, sm3_state, buf, SPX_SM3_ADDR_BYTES + inblocks*SPX_N);
  
    /* Copy the hash output to the result */  
    memcpy(out, outbuf, SPX_N);  
}

