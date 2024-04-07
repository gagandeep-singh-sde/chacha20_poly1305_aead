#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Constants
#define BLOCK_SIZE 64

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
  printf("\n");
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
  for (int i = 0; i < 16; i++)
  {
    printf("%02x ", state[i]);
    if ((i + 1) % 4 == 0)
    {
      printf("\n");
    }
  }
  printf("\n");
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

int main()
{
  uint8_t key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  uint8_t nonce[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};
  uint32_t counter = 1;
  uint8_t plaintext[] = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

  // Encryption
  size_t msg_len = strlen((char *)plaintext);
  uint8_t encrypted_message[msg_len];
  memset(encrypted_message, 0, msg_len);
  chacha20_encrypt(key, nonce, counter, plaintext, msg_len, encrypted_message);
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
  return 0;
}