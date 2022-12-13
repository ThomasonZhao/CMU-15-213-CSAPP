# Bomblab

This is the writeup for CSAPP bomblab

Tool: IDA/Ghidra, pwndbg

## Phase 1

Phase 1 compare input with a string originally inside the program. 

```
Border relations with Canada have never been better.
```

So input the same string can defuse the bomb

## Phase 2

Phase 2 read in 6 numbers in sequence. There is a while loop checking that the number in the back should be twice the one in the front. 

```
1 2 4 8 16 32
```

## Phase 3

Phase 3 read in 2 numbers. The first number used as a variable in a switch statement of total 8 choices. From the disassembler, we can know different value that will be compared with our second number. So find the right case you want to choose and input them as pairs

```
0 207
```

## Phase 4

Phase 4 also read in 2 numbers. The first number should be less than or equal to `0xE = 14`. There is a function called `func4` that is a recursive function, the input number should make its return value equal to 0. After some test, input `0` can return `0`, so just simply solved it. 

// TODO

In details, `fun4` balabala

Then the program just simply compare the second value with 0. If it is, you will pass the test, otherwise the bomb will explode. 

```
0 0
```

## Phase 5

Phase 6 read in string with length 6, encrypt/decrypt it in some way and compare the result of the encryption/decryption with `flyers`. 

It take an `AND` operation to the input string byte, which result only the half of the byte. Ex. `f = 0x66; 0x66 AND 0x0f = 0x06`. The program use the last half byte as the index to get the characters in the array. If the output of those character become `flyers`, you defuse the bomb.

The encryption/decryption array:

```
unsigned char array_3449[] =
{
  0x6D, 0x61, 0x64, 0x75, 0x69, 0x65, 0x72, 0x73, 0x6E, 0x66, 
  0x6F, 0x74, 0x76, 0x62, 0x79, 0x6C
};
```

```
ionefg
```

## Phase 6

Phase 6 read in 6 numbers. First, there are two nested loop to make sure every input number is less or equal to 6, and there are no number that next to each other are equal. Ex:

```
1 3 4 6 9 2		(X) because 9 > 6
1 3 6 6 2 4		(X) because 6 = 6 and they are next to each other
```

Then there is a second loop use 7 minus each input number and store the value in the same position as the original input. 

The third loop initialize the "node" for the next loop. There are 6 nodes in total (also 6 input).  

The fourth loop set up the pointer for each "node" by the sequence of the input. Similar to an object, the "node" here have 8 byte to store their own value and another 8 byte point to another node. 

The last loop examine the "node chain" to make sure it is in decreasing or same order.  

After debugging, the pointing direction should be:

```
node3 -> node4 -> node5 -> node6 -> node1 -> node2
```

The solution should be (remember, the second loop reverse the inputs if we choose not to have repeated number):

```
4 3 2 1 6 5
```

## Secret Phase

If we take a specific look at the `phase_defused` function, we can see that if the `num_input_strings`, which counting the number of inputs, equal to 6, another branch will open up. 

After dynamic analysis, the new branch in the `phase_defused` function redo the `sscanf` function on the input of phase 4:

```c
sscanf(PHASE_4_str, "%d %d %s", rdx, rcx, r8);
```

Then compare the contents of the last string with `DrEvil`. If equal, the checks passed, successfully into the secrete phase. But as it said: `But finding it and solving it are quite different...`

The secret phase read in string and convert it to long int. The value after convert should less than 1000. Then call the `fun7`, another recursive function, with the parameter of `char *a1, input_val`. `a1` is an array in the program `.data` section, which we are able to access by disassembler. The return value of `fun7` should equal to 2, then we defuse the secret phase. 

There are two recursive branches for `fun7`. The whole `fun7` looks like this:

```c
// error case
if (!a1)
    return -1;

// base case
if (*a1 = a2)
	return 0;

// recursive branches
if (*a1 > a2)
	return 2 * fun7(*(a1 + 0x8), input_val);
if (*a1 < a2)
    return 2 * fun7(*(a1 + 0x10), input_val) + 1;
```

 So in order to make the the return value to be 2, we may go in the first branch for first call, go in the second branch for second call, and terminate the recursion for third call. 

After examine the array, we can easily find the solution for the secret phase follow the procedure above. 

```
2
```



