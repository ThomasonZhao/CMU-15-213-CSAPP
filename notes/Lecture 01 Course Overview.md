# Lecture 01 Course Overview

## Course Theme: Abstraction Is Good But Don't Forget Reality

Limits of abstraction:

-   The presence of bugs
-   Need to understand details of underlying implementations

## Great Reality #1 Ints are not Integers, Floats are not Reals

Ex 1: Is $x^2\geq0$ ?

Float's may say Yes!

Int's may not

```gdb
(gdb) print 40000 * 40000
$1 = 1600000000
(gdb) print 50000 * 50000
$2 = -1794967296
```

It's actually negative! That's because it expects a 32 bit integer for output. 

Ex 2: Is $(x+y)+z=x+(y+z)$ ?

Unsigned & Signed Int's may say Yes!

Float's may not

```gdb
(gdb) print (1e20 + -1e20) + 3.14
$3 = 3.1400000000000001
(gdb) print 1e20 + (-1e20 + 3.14)
$4 = 0
```

## Computer Arithmetic

Usual mathematical properties may fail due to the finiteness of representations. 

## Great Reality #2 You Got to know Assembly

Understanding assembly is key to machine-level execution. 

## Great Reality #3: Memory Matters

Programs continue accessing memories (itself is in the memory). Getting know about memory help dealing with bugs and other security issues. 

Some low level programming language such as C and C++ don't provide any memory protection. 

## Great Reality #4: There's more to performance than asymptotic complexity

The performance of a program highly related to the memory access patterns and memory organization

## Great Reality #5: Computers do more than execute programs

Managing date IO

Communicate with each other over network.

## Course Perspective

-   Computer Architecture
-   Operating System
-   Compilers
-   Networking

## Labs**

### Programs and Data

Bits operations, arithmetic, assembly language programs

Representation of C control and data structures

Includes aspects of architecture and compilers

-   L1 datalab: Manipulating bits
-   L2 bomblab: Defusing a binary bomb
-   L3 attacklab: The basic of code injection attacks

### The Memory Hierarchy

Memory technology, memory hierarchy, caches, disks, locality

Includes aspects of architecture and OS

-   L4 cachelab: Building a cache simulator and optimizing for locality. 

### Exceptional Control Flow

Hardware exceptions, processes, process control, Unix signals, nonlocal jumps

Includes aspects of compilers, OS, and architecture

-   L5 tshlab: Writing your own Unix shell.

### Virtual Memory

Virtual memory, address translation, dynamic storage allocation

includes aspects of architecture and OS

-   L6 malloclab: Writing your own malloc package

### Networking, and Concurrency

High level and low level I/O, network programming

Internet services, Web servers

concurrency, concurrent server design, threads

I/O multiplexing with select

Includes aspects of networking, OS, and architecture

-   L7 proxylab: Writing your own Web proxy



