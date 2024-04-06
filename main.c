#include <stdio.h>
#include <stdint.h>c

void chacha20_poly1305_init(uint32_t state[16], const uint8_t key[32], const uint8_t nonce[12], uint32_t counter);

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

int main()
{
  uint8_t key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
  uint8_t nonce[12] = {0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};
  uint32_t counter = 1;
  uint32_t state[16];

  chacha20_poly1305_init(state, key, nonce, counter);

  printf("Initialized state:\n");
  for (int i = 0; i < 16; i++)
  {
    printf("%08x ", state[i]);
    if ((i + 1) % 4 == 0)
    {
      printf("\n");
    }
  }

  return 0;
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