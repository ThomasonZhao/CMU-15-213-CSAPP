# Lecture 10 Program Optimization

## Optimizing Compilers

Number 1 compiler rule: **When in doubt, the compiler must be conservative**

This constrain a lot for compilers to do some "proper" optimizations on a set of code. 

## Generally Useful Optimization

Optimizations that you or the compiler should do regardless of processor/compiler

![image-20220628153409287](assets/image-20220628153409287.png)

**Reduction in Strength**

-   Replace costly operation with simpler one

-   Shift, add instead of multiply or divide

-   Recognize sequence of products
-   Share common subexpressions
    -   Reuse portions of expressions

![image-20220628154058636](assets/image-20220628154058636.png)

## Optimization Blocker #1: Procedure Calls

Take a look at this piece of code:

![image-20220628154354516](assets/image-20220628154354516.png)

Quadratic performance of this code

![image-20220628154500624](assets/image-20220628154500624.png)

The reason why it have this poor performance is because `strlen` executed every iteration. `strlen` it self takes linear time of the input. 

Therefore the overall performance result to be $O(n^2)$. The way to improve it is to extract it out of the loop since its output is constant

![image-20220628154821791](assets/image-20220628154821791.png)

**Why couldn't compiler move `strlen` out of inner loop?**

-   Procedure may have side effect
    -   Alters global state each time called
-   Function may not return same value for given arguments
    -   Depends on other parts of global state
    -   Procedure `lower` could interact with `strlen`

**Warning:**

-   Compiler treats procedure calls as a black box
-   Weak optimizations near them

## Optimization Blocker #2: Memory Aliasing

**Aliasing**

-   Two different memory references specify single location
-   Easy to have happen in C
    -   Since allowed to d address arthmetic
    -   Direct access to storage structures
-   Get in habit of introducing local variables
    -   Accumulating within loops
    -   **Your way of telling compiler not to check for aliasing**

## Exploiting Instruction-Level Parallelism

Need general understanding of modern processor design

-   Hardware can execute multiple instructions in parallel

Performance limited by data dependencies

Simple transformations can yield dramatic performance improvement

-   Compilers often cannot make these transformations
-   Lack of associativity and distributivity in floating-point arithmetic

E.g.

![image-20220628161111053](assets/image-20220628161111053.png)

![image-20220628161139223](assets/image-20220628161139223.png)

## Cycles Per Element (CPE)

Convenient way to express performance of program that operates on vectors or lists
$$
T = \text{CPE} \cdot n + \text{Overhead}
$$
Some basic optimizations

![image-20220628161719097](assets/image-20220628161719097.png)

## Modern CPU Design

![image-20220628161902092](assets/image-20220628161902092.png)

## Superscalar Processor

![image-20220628162549794](assets/image-20220628162549794.png)

## Pipelined Functional Unites

![image-20220628162759127](assets/image-20220628162759127.png)

![image-20220628163113469](assets/image-20220628163113469.png)

## Loop Unrolling (2x1)

![image-20220628163525217](assets/image-20220628163525217.png)

![image-20220628163541585](assets/image-20220628163541585.png)

![image-20220628163639098](assets/image-20220628163639098.png)

![image-20220628164152798](assets/image-20220628164152798.png)

![image-20220628164604326](assets/image-20220628164604326.png)

![image-20220628164612676](assets/image-20220628164612676.png)

![image-20220628164630918](assets/image-20220628164630918.png)

## Unrolling & Accumulating: Double \*

![image-20220628164731770](assets/image-20220628164731770.png)

![image-20220628165130381](assets/image-20220628165130381.png)

## Branches

![image-20220628165316252](assets/image-20220628165316252.png)

Modern computer predict where the branch will go and continue working on the prediction route. But this action won't modify register or memory data. So if the guess failed, it can fix easily fix it but waste the clock cycles that doing on the wrong route.

![image-20220628165835801](assets/image-20220628165835801.png)

If the prediction invalid:

![image-20220628165854335](assets/image-20220628165854335.png)

Misprediction Recovery

![image-20220628170131876](assets/image-20220628170131876.png)

## Getting High Performance

![image-20220628170203575](assets/image-20220628170203575.png)







