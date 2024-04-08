#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <gmp.h>

// Constants
#define BLOCK_SIZE 64
mpz_t P;
void initialize_constants()
{
  // Initialize P
  mpz_init_set_str(P, "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB", 16); // 16 for hexadecimal
}

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
  // for (int i = 0; i < 16; i++)
  // {
  //   printf("%02x ", state[i]);
  //   if ((i + 1) % 4 == 0)
  //   {
  //     printf("\n");
  //   }
  // }
  // printf("\n");
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

void poly1305_key_gen(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t poly1305_key[32])
{
  uint8_t block[64];
  chacha20_block(key, nonce, counter, block);
  memcpy(poly1305_key, block, 32);
}

void num_to_8_le_bytes(uint64_t num, uint8_t *bytes)
{
  for (int i = 0; i < 8; i++)
  {
    bytes[i] = (num >> (i * 8)) & 0xFF;
  }
}

void poly1305_key_clamp(uint8_t r[16])
{
  r[3] &= 15;
  r[7] &= 15;
  r[11] &= 15;
  r[15] &= 15;
  r[4] &= 252;
  r[8] &= 252;
  r[12] &= 252;
}

uint64_t little_endian_bytes_to_number(const uint8_t *bytes)
{
  uint64_t number = 0;
  for (int i = 0; i < 8; i++)
  {
    number |= ((uint64_t)bytes[i]) << (i * 8);
  }
  return number;
}

void num_to_16_le_bytes(uint64_t num, uint8_t *bytes)
{
  for (int i = 0; i < 16; i++)
  {
    bytes[i] = (num >> (i * 8)) & 0xFF;
  }
}

void poly1305_mac(const uint8_t *msg, const uint8_t *key, size_t msg_len, uint8_t *mac)
{
  mpz_t r, temp;
  mpz_init(r);
  mpz_init(temp);

  mpz_import(r, 16, -1, sizeof(uint8_t), 0, 0, key);
  uint8_t r_exported[16];
  mpz_export(r_exported, NULL, -1, sizeof(uint8_t), 0, 0, r);
  poly1305_key_clamp(r_exported);
  mpz_import(r, 16, -1, sizeof(uint8_t), 0, 0, r_exported);
  uint64_t s = little_endian_bytes_to_number(key + 16);
  printf("s: %llu\n", s);
  uint64_t a_accumulator = 0;

  for (size_t i = 0; i < msg_len; i += 16)
  {
    uint64_t n = little_endian_bytes_to_number(msg + i);
    a_accumulator += n;

    mpz_set_ui(temp, a_accumulator);
    mpz_mul(temp, r, temp);
    mpz_mod(temp, temp, P);

    a_accumulator = mpz_get_ui(temp);
  }
  a_accumulator += s;
  num_to_16_le_bytes(a_accumulator, mac);

  mpz_clear(r);
  mpz_clear(temp);
}

int main()
{
  initialize_constants();
  uint8_t key[32] = {0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
                     0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f};
  uint8_t nonce[12] = {0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47};
  uint32_t counter = 0;
  uint8_t plaintext[] = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
  uint8_t poly1305_key[32];
  uint8_t aad[] = {0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7};

  // Authentication
  poly1305_key_gen(key, nonce, counter, poly1305_key);
  printf("Poly1305 key: ");
  for (int i = 0; i < 32; i++)
  {
    printf("%02x ", poly1305_key[i]);
  }
  printf("\n");

  // Encryption
  size_t msg_len = strlen((char *)plaintext);
  uint8_t encrypted_message[msg_len];
  memset(encrypted_message, 0, msg_len);
  chacha20_encrypt(key, nonce, counter + 1, plaintext, msg_len, encrypted_message);
  printf("Encrypted message");
  printf("\n");
  for (int i = 0; i < msg_len; i++)
  {
    printf("%02x ", encrypted_message[i]);
    if ((i + 1) % 16 == 0)
    {
      printf("\n");
    }
  }

  // Preparing Message Authentication Data
  size_t aad_len = sizeof(aad);
  size_t aad_padded_len = aad_len + (16 - (aad_len % 16));
  uint8_t padded_aad[aad_padded_len];
  memset(padded_aad, 0, aad_padded_len);
  memcpy(padded_aad, aad, aad_len);

  size_t ctx_padded_len = msg_len + (16 - (msg_len % 16));
  uint8_t padded_ctx[ctx_padded_len];
  memset(padded_ctx, 0, ctx_padded_len);
  memcpy(padded_ctx, encrypted_message, msg_len);

  uint8_t aad_len_le[8];
  uint8_t ctx_len_le[8];
  num_to_8_le_bytes(aad_len, aad_len_le);
  num_to_8_le_bytes(msg_len, ctx_len_le);

  size_t mac_data_len = aad_padded_len + ctx_padded_len + sizeof(aad_len_le) + sizeof(ctx_len_le);
  // size_t mac_data_len = aad_padded_len + ctx_padded_len + sizeof(ctx_len_le);
  uint8_t mac_data[mac_data_len];

  // Copy padded_aad into mac_data
  memcpy(mac_data, padded_aad, aad_padded_len);

  // Copy padded_ctx into mac_data, starting after padded_aad
  memcpy(mac_data + aad_padded_len, padded_ctx, ctx_padded_len);

  // Copy aad_len_le into mac_data, starting after padded_aad and padded_ctx
  memcpy(mac_data + aad_padded_len + ctx_padded_len, aad_len_le, sizeof(aad_len_le));

  // Copy ctx_len_le into mac_data, starting after padded_aad, padded_ctx, and aad_len_le
  memcpy(mac_data + aad_padded_len + ctx_padded_len + sizeof(aad_len_le), ctx_len_le, sizeof(ctx_len_le));
  // memcpy(mac_data + aad_padded_len + ctx_padded_len, ctx_len_le, sizeof(ctx_len_le));

  // Print mac_data as a hexadecimal string
  printf("\n MAC Data: \n");
  for (size_t i = 0; i < mac_data_len; i++)
  {
    printf("%02x ", mac_data[i]);
    if ((i + 1) % 16 == 0)
    {
      printf("\n");
    }
  }
  printf("\n");

  uint8_t mac[16];
  poly1305_mac(mac_data, poly1305_key, mac_data_len, mac);

  printf("\nMAC: ");
  for (int i = 0; i < 16; i++)
  {
    printf("%02x ", mac[i]);
  }
  printf("\n");

  return 0;
}