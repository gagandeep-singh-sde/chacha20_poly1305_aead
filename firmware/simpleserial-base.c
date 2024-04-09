/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2012-2017 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "hal.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "simpleserial.h"

#define BLOCK_SIZE 64

/*
-----------------
ChaCha20_Poly1305
-----------------
*/
uint8_t key[32];
uint8_t nonce[12];

void chacha20_poly1305_init(uint32_t state[16], const uint8_t key[32], const uint8_t nonce[12], uint32_t counter)
{
    // Initialize constants
    const uint32_t constants[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

    // Initialize state with constants
    memcpy(state, constants, sizeof(constants));

    // Set key
    memcpy(&state[4], key, 32);

    // Set counter
    state[12] = counter;

    // Set nonce
    memcpy(&state[13], nonce, 12);
}

void copy_state(uint32_t dest[16], const uint32_t src[16])
{
    for (int i = 0; i < 16; i++)
    {
        dest[i] = src[i];
    }
}

void quarter_round(uint32_t state[16], int a, int b, int c, int d)
{
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF;
    state[d] ^= state[a];
    state[d] = (state[d] << 16 | state[d] >> 16) & 0xFFFFFFFF;
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF;
    state[b] ^= state[c];
    state[b] = (state[b] << 12 | state[b] >> 20) & 0xFFFFFFFF;
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF;
    state[d] ^= state[a];
    state[d] = (state[d] << 8 | state[d] >> 24) & 0xFFFFFFFF;
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF;
    state[b] ^= state[c];
    state[b] = (state[b] << 7 | state[b] >> 25) & 0xFFFFFFFF;
}

void inner_block(uint32_t state[16])
{
    for (int i = 0; i < 10; i++)
    {
        quarter_round(state, 0, 4, 8, 12);
        quarter_round(state, 1, 5, 9, 13);
        quarter_round(state, 2, 6, 10, 14);
        quarter_round(state, 3, 7, 11, 15);
        quarter_round(state, 0, 5, 10, 15);
        quarter_round(state, 1, 6, 11, 12);
        quarter_round(state, 2, 7, 8, 13);
        quarter_round(state, 3, 4, 9, 14);
    }
}

void add_states(uint32_t final_state[16], const uint32_t original_state[16])
{
    for (int i = 0; i < 16; i++)
    {
        final_state[i] += original_state[i];
    }
}

void serialized_block(uint32_t *array, uint8_t *key_stream)
{
    for (int i = 0; i < 16; i++)
    {
        key_stream[i * 4 + 0] = (array[i] >> 0) & 0xFF;
        key_stream[i * 4 + 1] = (array[i] >> 8) & 0xFF;
        key_stream[i * 4 + 2] = (array[i] >> 16) & 0xFF;
        key_stream[i * 4 + 3] = (array[i] >> 24) & 0xFF;
    }
}

void chacha20_block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t *key_stream)
{
    uint32_t state[16];
    chacha20_poly1305_init(state, key, nonce, counter);
    uint32_t original_state[16];
    copy_state(original_state, state);
    inner_block(state);
    add_states(state, original_state);
    serialized_block(state, key_stream);
}

void xor_blocks(const uint8_t block1[64], const uint8_t block2[64], uint8_t result[64])
{
    for (int i = 0; i < BLOCK_SIZE; i++)
    {
        result[i] = block1[i] ^ block2[i];
    }
}

void chacha20_encrypt(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, const uint8_t *plaintext, size_t len, uint8_t *encrypted_message)
{
    // Initialize variables
    size_t blocks = len / BLOCK_SIZE;
    size_t remainder = len % BLOCK_SIZE;
    uint8_t key_stream[BLOCK_SIZE];

    // Encrypt full blocks
    for (size_t j = 0; j < blocks; j++)
    {
        chacha20_block(key, nonce, counter + j, key_stream);
        xor_blocks(&plaintext[j * BLOCK_SIZE], key_stream, &encrypted_message[j * BLOCK_SIZE]);
    }

    // Encrypt remaining bytes
    if (remainder != 0)
    {
        chacha20_block(key, nonce, counter + blocks, key_stream);
        xor_blocks(&plaintext[blocks * BLOCK_SIZE], key_stream, &encrypted_message[blocks * BLOCK_SIZE]);
    }
}

/*
-----------------
ChaCha20_Poly1305
-----------------
*/

uint8_t get_key(uint8_t *k, uint8_t len)
{
    for (uint8_t i = 0; i < len; i++)
    {
        key[i] = k[i];
    }
    return 0x00;
}

uint8_t get_nonce(uint8_t *n, uint8_t len)
{
    for (uint8_t i = 0; i < len; i++)
    {
        nonce[i] = n[i];
    }
    return 0x00;
}

uint8_t get_pt(uint8_t *pt, uint8_t len)
{
    /**********************************
     * Start user-specific code here. */
    uint8_t *plaintext = pt;
    uint32_t counter = 0;
    uint8_t encrypted_message[len];

    trigger_high();

    chacha20_encrypt(key, nonce, counter, plaintext, len, encrypted_message);

    trigger_low();
    /* End user-specific code here. *
    ********************************/
    simpleserial_put('r', 64, encrypted_message);
    return 0x00;
}

uint8_t reset(uint8_t *x, uint8_t len)
{
    // Reset key here if needed
    return 0x00;
}

#if SS_VER == SS_VER_2_1
uint8_t aes(uint8_t cmd, uint8_t scmd, uint8_t len, uint8_t *buf)
{
    uint8_t req_len = 0;
    uint8_t err = 0;

    if (scmd & 0x02)
    {
        req_len += 16;
        if (req_len > len)
        {
            return SS_ERR_LEN;
        }
        err = get_key(buf + req_len - 16, 16);
        if (err)
            return err;
    }
    if (scmd & 0x01)
    {
        req_len += 16;
        if (req_len > len)
        {
            return SS_ERR_LEN;
        }
        err = get_pt(buf + req_len - 16, 16);
        if (err)
            return err;
    }

    if (len != req_len)
    {
        return SS_ERR_LEN;
    }

    return 0x00;
}
#endif

int main(void)
{
    platform_init();
    init_uart();
    trigger_setup();

    /* Uncomment this to get a HELLO message for debug */
    /*
    putch('h');
    putch('e');
    putch('l');
    putch('l');
    putch('o');
    putch('\n');
    */

    simpleserial_init();
#if SS_VER != SS_VER_2_1
    simpleserial_addcmd('p', 64, get_pt);
    simpleserial_addcmd('k', 32, get_key);
    simpleserial_addcmd('n', 12, get_nonce);
    simpleserial_addcmd('x', 0, reset);
#else
    simpleserial_addcmd(0x01, 16, aes);

#endif
    while (1)
        simpleserial_get();
}
