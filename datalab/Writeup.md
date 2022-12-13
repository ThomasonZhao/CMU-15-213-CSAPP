# Datalab

This is the writeup for CSAPP datalab

## bitXor

`XOR` gate can be composed by couple `NAND` gate. Use legal ops `~ &` to construct `NAND` gate to get `XOR`.

```c
int bitXor(int x, int y) {
    /* Use ~ and & constuct NAND gate to calculate XOR */
    int temp = ~(x & y);
    int a = ~(x & temp);
    int b = ~(y & temp);
    int result = ~(a & b);
    return result;
}
```

  ## tmin

$T_{min}$ is `0x80000000 = 0b1000...0`. Do bit shift on 1 will get the correct result

```c
int tmin(void) {
    /* Tmin is 0b1000...0, so doing bit shift on 1 */
    return 1 << 31;
}
```

## isTmax

$T_{max}$ is `0x700000000 = 0b0111...1`, which is $T_{min} = T_{max} + 1$. Also, we know that $T_{min} + T_{max} = 0$. So we may use this advantage to solve the puzzle. 

```c
int isTmax(int x) {
    /* Tmax is 0b0111...1, it is Tmin - 1. Tmin + Tmax = 1 */
    return !(~((x + 1) + x) | !(x + 1));
}
```

## allOddBits

To satisfy the requirement of having all odd bits to be 1, the simplest number is `0xAAAAAAAA = 0b1010...1010`.  

```c
int allOddBits(int x) {
    /* The simplest number satisfied the requirement is 0xAAA..A, so make it and do comparision */
    int temp = 0xAA;
    int oddBits = temp << 24;
    oddBits += temp << 16;
    oddBits += temp << 8;
    oddBits += temp;
    return !((x & oddBits) ^ oddBits);
}
```

## negate

Doing two's complement negation. Use negate operator then add 1. 

```c
int negate(int x) {
    /* Doing two's complement negation */
    int result = ~x;
    result += 1;
    return result;
}
```

## isAsciiDigit

Make sure it range from `0x30 ~ 0x39 (inclusive)` which means that `(x - 0x30) >= 0 && (0x39 - x) >= 0`. So implement this into code. 

```c
int isAsciiDigit(int x) {
  /* (x - 0x30 >= 0) && (0x39 - x) >=0 */
  int NEG = 1 << 31;
  return !((x + ~0x30 + 1) & NEG) & !((0x39 + ~x + 1) & NEG);
}
```

## conditional

We may use `!!` to identify if `x` is not 0. When `x` is not 0, we should have `y` side identifier to be `0xfff...f` and `z` side to be `0x0`, and when `x` is 0 vise versa. Therefore, it only satisfy one side of `|` operator, other side will be 0. 

```c
int conditional(int x, int y, int z) {
    /* Use ~(!!x) + 1 as identifier to make sure it only satisfy one side, other side is 0*/
    int temp = ~(!!x) + 1;
    return (temp & y) | (~temp & z);
}
```

## isLessOrEqual

Solve the problem case by case

```c
int isLessOrEqual(int x, int y) {
    /* Solve it case by case. Check the sign of x and y */
    int signX = x >> 31;
    int signY = y >> 31;
    return (signX & !signY) | (!(signX ^ signY) & !((y + ~x + 1) >> 31));
}
```

## logicalNeg

There are two number that is same as itself after the negation, $T_{min}$ and 0. But 0 always "positive" (most significant bit is 0).

```c
int logicalNeg(int x) {
    /* 0 is the only number that is "positive" after its negation */
    int negX = ~x + 1;
    int result = ((x >> 31) | (negX >> 31)) + 1;
    return result;
}
```

## *howManyBits

I have no idea how to implement this except for stupid enumeration. I find a solution instead. 

The solution first flip the sign of the input if it is negative. Then, it doing a binary search on the processed input. **Key here on the binary search is that he shift the input based on what it get.** 

```c
int howManyBits(int x) {
  int sign, b1, b2, b4, b8, b16;
  sign = (x >> 31);
  x = (sign & ~x) | (~sign & x);
  b16 = !!(x >> 16) << 4;
  x = x >> b16;
  b8 = !!(x >> 8) << 3;
  x = x >> b8;
  b4 = !!(x >> 4) << 2;
  x = x >> b4;
  b2 = !!(x >> 2) << 1;
  x = x >> b2;
  b1 = !!(x >> 1);
  x = x >> b1;
  return b16 + b8 + b4 + b2 + b1 + x + 1;
}
```

## floatScale2

In floating point part, we are allowed to use `if, while` those branch and loop, which is much easier than stuffs above. 

```c
unsigned floatScale2(unsigned uf) {
    unsigned frac = (uf << 9) >> 9;
    unsigned exp = (uf << 1) >> 24;
    unsigned sign = uf >> 31;

    // Check if NaN or infinity
    if (exp == 0xff){
        return uf;
    }

    if (exp != 0){
        exp += 1;
    } else {
        frac <<= 1;
    }

    return (sign << 31) + (exp << 23) + frac;
}
```

## float Float2Int

```c
int floatFloat2Int(unsigned uf) {
    unsigned frac = (uf << 9) >> 9;
    int exp = (uf << 1) >> 24;
    int sign = uf >> 31;
    int result;

    // 0 representation
    if (exp == 0 && frac == 0){
        return 0;
    }

    exp -= 127;
    result = 1 << exp;
    // overflow
    if (exp > 31){
        return 1 << 31;
    }
    // 0.???...
    if (exp < 0){
        return 0;
    }

    if (exp > 23){
        result += frac << (exp - 23);
    } else {
        result += frac >> (23 - exp);
    }

    if (sign){
        result = ~result + 1;
    }

    return result;
}
```

## floatPower2

```c
unsigned floatPower2(int x) {
    unsigned INF = 0xff << 23;
    int exp = x + 127;
    // overflow
    if (exp >= 255){
        return INF;
    }
    // 0.00000??...
    if (exp <= 0){
        return 0;
    }
    return exp << 23;
}
```









