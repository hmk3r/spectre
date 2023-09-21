<h1 align="center"> CS-470 Advanced computer architecture Homework 4<br>Spectre</h1>
<h3 align="center"> Lyubomir Kyorovski <h3>
<h4 align="center">336277 - lyubomir.kyorovski@epfl.ch<h4>

## Testing environment

- CPU: Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz
  - Base speed: 2.21 GHz
  - Cores: 6
  - Logical processors: 12
  - Virtualization: Enabled
  - L1 cache: 384 KB
  - L2 cache: 1.5 MB
  - L3 cache: 9.0 MB

- RAM: DDR4 32GB @ 2666 MHz, 19-19-19-43
- OS: Ubuntu 20.04 (5.8.0-55)
- Hypervisor: VirtualBox 6.1.22 on Windows 10 Enterprise Build 18363
- gcc: 9.3.0

Compiled with `gcc spectre.c -o spectre -g -O0`

## Training the branch predictors

On each run of the training-attack procedure, we train the global branch predictor with a long loop(10<sup>5</sup>) iterations.

For Intel's local branch predictor, information on the internet is rather scarce. The latest ***official*** information I could find is from 1999, and states [1]:

> The branch target buffer prediction algorithm includes pattern matching and can track up to the last four branch directions per branch address.

We can therefore train the branch predictor for 5 iterations, we will be guaranteed that the branch history dictates that the branch should be taken on the sixth iteration. We train the local branch predictor by simply invoking the victim function with a value of `x` which we know is valid and will therefore resolve the branch positively.

## Extending the side channel

To increase the time between branch prediction and branch resolution, we can evict the variables used in the comparison from cache. On each iteration in the training-attack phase, we evict `array1_size` from cache.

Evicting the value we call the victim function with(`x`) seems to degrade the attack's accuracy. I tried to combat this by evicting `x` only when we are on an attack run with something in the lines of:

```c
// mask is all 1 on attack run, all 0 on training run
register uintptr_t mask = ...;

...

_mm_clflush((void *)(
    ((uintptr_t)&x & mask) |
    ((uintptr_t)&array1[legal_x] & ~mask)
  )
);
```

The strategy above unfortunately worsened the result, so it was omitted.

Another tactic I tried was to force `x` to be retrieved from memory through a few "jumps" using pointer operations:

```c
// _mm_clflush these on every iteration in the training-attack
size_t *branch_delay_1 = &x;
size_t **branch_delay_2 = &branch_delay_2;
size_t ***branch_delay_3 = &branch_delay_3;

...

victim_function(
  *(*(*branch_delay_3))
);
```

This technique also didn't work, in fact it crippled the attack.

The last thing I could think of is to evicting all the values associated with the x we're training with which are used in the victim function(i.e. `&array2[array1[legal_x] * 512]` and `&array1[legal_x]`) from the cache on each iteration of the training-attack phase, in hopes that the memory becomes busy between the last training run and the attack run, so that retrieving `array1_size` takes longer and delays the branch resolution. This seemed to work, as the average delta between the best scores increased by approximately 70-100 points.

## Improving the attack accuracy

Similar to what we did in the Flush+Reload lab, we make multiple runs of the attack the improve its accuracy. We keep track of what's most oftenly cached, and we get the results with the highest cache hit score.

We also combine the local branch training loop with the attack loop, as this removes the chance that between the two loops the global branch predictor loses the training we did on it.

We also periodically change the value of x `legal_x` with which we train the local branch predictor.

An attempt was made to prevent data prefetching, by complicating the access pattern, when doing the time measurement. First I tried what was suggested in the Cache Attack Lab, but this didn't seem to work very well(at least on my machine). I resorted to using prime number multiplication + addition to get some unpredictability in the access order.

## Additional problems

The exploit was developed under Ubuntu 20.04, kernel 5.8.0-55, which features mitigations against spectre. To make the machine vulnerable again, some flags had to be put in the boot configuration(taken from [2]).

```bash
noibrs noibpb nopti nospectre_v2 nospectre_v1 l1tf=off
nospec_store_bypass_disable no_stf_barrier mds=off tsx=on 
tsx_async_abort=off mitigations=off 
```

During branch training/attack phase, we need to alternate between a malicious value of x and a legitimate one. As we do not want any additional if-statements to pollute our branch predictor, bit predication was used. Unfortunately, there were some challenges, but a work-around has been established. These are presented in the code and comments below:

```c
      // if i % 6 == 0, set x to be all 1s, otherwise all 0s
      // x = !(i % 6 == 0) - 1 doesn't seem to work, i'm guessing "==" affects the branch predictor
      // To emulate it, we can again perform the modulo operation and directly subtract 1
      // this will result in either 0xFF..FF(when i % 6 == 0) or an integer 0-4(when i % 6 != 0)
      // we then omit the least significant nibble, since it can contain a non-0-or-F value
      x = ((i % 6) - 1) & ~0xF;
      // to correct the ommited nibble, copy the value from the 2nd least significant nibble to the first one
      // by or-ing the 4-time(nibble-sized) bitshifted value of x with itself 
      x |= x >> 4;
      // set x to either malicious_x or legal_x, or is mutually exclusive since one of
      // ~x & legal_x or x & malicious_x is guaranteed to be all 0
      x = (x & malicious_x) | (~x & legal_x);
```

## References

\[1\] Intel® Architecture Optimization Reference Manual, 1999, p. 30 - [https://courses.cs.washington.edu/courses/csep501/05au/x86/24512701.pdf](https://courses.cs.washington.edu/courses/csep501/05au/x86/24512701.pdf)

\[2\] Make linux fast again - [https://make-linux-fast-again.com/](https://make-linux-fast-again.com/)
