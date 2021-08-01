/*
 * test-fast-rang.c
 * testing fast-rang.c
 * fastest random number generator
 * compile with:
 * gcc -Wall -O2 -o test-fast-rng test-fast-rng.c fast-rng.s
 * time ./test-fast-rng
 * see the magic
 */
typedef unsigned long long u64b;

u64b rng_hash_128(u64b *s);

static u64b seed[2];

int main(void)
{
  u64b result;
  int i;

  /* Initialize seed */
  seed[0] = 9837546364323845343ULL;
  seed[1] = 3573842394563042942ULL;

  for (i = 0; i < 1000000000; ++i) {
    result = rng_hash_128(seed);
  }
  return 0;
}
