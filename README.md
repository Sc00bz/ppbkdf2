# Parallel PBKDF2 (PPBKDF2)
A computationally hard password KDF

## Pseudocode
```
iterations = 1024
while 384 * cost > 0xffffffff
  iterations = 2 * iterations
  cost = floor(cost / 2)
work = xorBlocks(pbkdf2(password, salt, iterations, length:384*hashLen*cost))
key = pbkdf2(password, work, iterations:1, length)
```

`xorBlocks()` xors every `hashLen` block of PBKDF2 output together. With PBKDF2 each block of output is calculated independently of each other. Which means this can use SIMD and threads to compute the output faster.
