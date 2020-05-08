/*
 * Fibonacci calculator prototype
 */

/* Calculate Fibonacci numbers by Fast Doubling */
long long fib_sequence_fdouble(int n)
{
    unsigned int i;
    long long f[2];
    f[0] = 0; /* F(k) */
    f[1] = 1; /* F(k+1) */

    if (n < 2) { /* F(0) = 0, F(1) = 1 */
        return n;
    }

    for (i = 1U << 31; i; i >>= 1) {
        long long k1 =
            f[0] * (f[1] * 2 - f[0]); /* F(2k) = F(k) * [ 2 * F(k+1) – F(k) ] */
        long long k2 =
            f[0] * f[0] + f[1] * f[1]; /* F(2k+1) = F(k)^2 + F(k+1)^2 */
        if (n & i) {                   /* current binary digit == 1 */
            f[0] = k2;                 /* F(n) = F(2k+1) */
            f[1] = k1 + k2; /* F(n+1) = F(2k+2) =  F(2k) +  F(2k+1) */
        } else {
            f[0] = k1; /* F(n) = F(2k) */
            f[1] = k2; /* F(n+1) = F(2k+1) */
        }
    }
    return f[0];
}