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
    unsigned char buf[SPX_N + SPX_SM3_ADDR_BYTES + inblocks * SPX_N];  
    unsigned char outbuf[SPX_SM3_OUTPUT_BYTES];  
    unsigned char bitmask[inblocks * SPX_N]; 
    uint8_t sm3_state[40]; 
    unsigned int i;  
  
    // Concatenate pub_seed, addr, and input data  
    memcpy(buf, pub_seed, SPX_N);  
    memcpy(buf + SPX_N, addr, SPX_SM3_ADDR_BYTES); 
    mgf1_256(bitmask, inblocks * SPX_N, buf, SPX_N + SPX_SM3_ADDR_BYTES); 
    // for (i = 0; i < inblocks * SPX_N; i++) {  
    //     buf[SPX_N + SPX_SM3_ADDR_BYTES + i] = in[i];  
    // }  
  
    // Generate bitmask using SM3  
    // sm3(bitmask, buf, SPX_N + SPX_SM3_ADDR_BYTES + inblocks * SPX_N);  
    memcpy(sm3_state, state_seeded, 40 * sizeof(uint8_t));
    // XOR input data with bitmask  
    for (i = 0; i < inblocks * SPX_N; i++) {  
        buf[SPX_N + SPX_SM3_ADDR_BYTES + i] = in[i] ^ bitmask[i];  
    }  
  
    // Hash the XORed data using SM3  
    // sm3(outbuf, buf + SPX_N, SPX_SM3_ADDR_BYTES + inblocks * SPX_N);  
    sm3_inc_finalize(outbuf, sm3_state, buf + SPX_N,
                        SPX_SM3_ADDR_BYTES + inblocks*SPX_N);
    // Copy the hash output to the result  
    memcpy(out, outbuf, SPX_N);
}

