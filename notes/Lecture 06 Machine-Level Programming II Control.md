# Lecture 06 Machine-Level Programming II Control

## Condition Codes (Implicit Setting)

Condition codes represent the state of most recent arithmetic instruction.  

Single bit registers

-   `CF` Carry Flag (for unsigned)
-   `SF` Sign Flag (for signed)
-   `ZF` Zero Flag
-   `OF` Overflow Flag (for signed)

![image-20220525114920402](assets/image-20220525114920402.png)

## Condition Codes (Explicit Setting: Compare)

Explicit Setting by Compare Instruction

```assembly
cmpq SRC2, SRC1
```

`cmpq b, a` a like computing `a - b` without setting destination

![image-20220525114824406](assets/image-20220525114824406.png)

## Condition Codes (Explicit Setting: Test)

Explicit Setting by Test Instruction

```assembly
testq SRC2, SRC1
```

`testq b, a` a like computing `a & b` without setting destination

![image-20220525115139447](assets/image-20220525115139447.png)

## Reading Condition Codes

SetX Instructions

-   Set low-order byte of destination to 0 or 1 based on combinations of condition codes
-   Does not alter remaining 7 bytes

![image-20220525115311381](assets/image-20220525115311381.png)

## Jumping

jX Instructions

-   Jump to different part of code depending on condition codes

![image-20220525120622231](assets/image-20220525120622231.png)

## Expressing with Goto Code

C allows `goto` statement

Jump to position designated by label (more like an assembly code structure)

![image-20220525121321103](assets/image-20220525121321103.png)

## Using Conditional Moves

Conditional Move Instructions

-   Instruction supports:

```
if (Test) Dest <- Src
```

-   Supported in post-1995 x86 processors
-   GCC tries to use them 
    -   But, only when known to be safe

Why?

-   Branches are very disruptive to instruction flow through pipelines
-   Conditional moves do no require control transfer

E.g.

![image-20220525122133049](assets/image-20220525122133049.png)

## Bad Cases for Conditional Move

![image-20220525122338589](assets/image-20220525122338589.png)

## "Do-While" Loop Example

![image-20220525122509130](assets/image-20220525122509130.png)

## General "Do-While" Translation

![image-20220525122811971](assets/image-20220525122811971.png)

## General "While" Translation \#1

"Jump-to-middle" translation

Used with `-Og`

![image-20220525123018849](assets/image-20220525123018849.png)

E.g.

![image-20220525123128035](assets/image-20220525123128035.png)

## General "While" Translation \#2

"Do-while" conversion

Used with `-O1`

![image-20220525123242897](assets/image-20220525123242897.png)

## "For" Loop Form

Usually, we translate a "For" loop to a while loop. They have exactly the same behavior.

![image-20220525123458835](assets/image-20220525123458835.png)

## Switch Statement

C uses jump table structure to implement switch statement. 

![image-20220525124317087](assets/image-20220525124317087.png)

At the beginning of the switch statement, it first check the argument jump to the default behavior (too small or too large). 

![image-20220525124613197](assets/image-20220525124613197.png)

Then, it will implement an unconditional jump to the jump table with the index of the argument. 

![image-20220525124728255](assets/image-20220525124728255.png)

The jump table:

![image-20220525124818491](assets/image-20220525124818491.png)



















