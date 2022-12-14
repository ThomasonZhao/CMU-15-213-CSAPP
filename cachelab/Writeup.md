# Cachelab

This is the write up for CSAPP cachelab

## Part A

### General Solution

In part A, we will need to write a cache simulator to interprete the trace output file generated by `valgrind`. At run time, the parameters for the cache will be given through command line options.

Luckily, professor provide us with a reference binary as a template to "guide through", ~~or show the answer in front of you~~.

First thing first is to define a useful structure which can be used for simulate the cache. From the course video and the recitation, we are able to know that cache is composed by three parts: cache set, cache line, cache block. Since it's just a simulation, so we don't need the cache block to actually store the data, we just need to determine if the address that program access is a hit/miss/eviction. 

Generally, a cache line need a `valid bit`, `tag`, and `cache block`. But here we can remove `cache block` with the reason above and add a `lru` variable act as a time stemp to determine which line should be evicted. 

Cache line -> cache set -> cache. So here in the code blow, `Cache = ***cacheLine`.

```c
typedef struct {
    int valid_bit;
    int lru;
    long unsigned int tag;
} cacheLine;

typedef cacheLine* cacheSet;
typedef cacheSet* Cache;

/* initialize cache, allocate enough space for the cache */
Cache init_cache(int s, int E, int b)
{
    int S = 1 << s;
    Cache cache = (Cache)malloc(sizeof(cacheSet) * S);
    if (cache == NULL) return NULL;
    for (int i = 0; i < S; i++)
    {
        cache[i] = (cacheSet)calloc(E, sizeof(cacheLine));
        if (cache[i] == NULL) return NULL;
    }
    return cache;
}

/* free cache one by one */
void free_cache(Cache cache, int s)
{
    int S = 1 << s;
    for (int i = 0; i < S; i++)
    {
        free(cache[i]);
    }
    free(cache);
}
```

Then, another big thing is to understand how to use `getopt` by reading the man page and search for demo code online. In `optstring`, an option followed by a colon `:` means it requires an argument, followed by two colon `:` means the argument is optional. If the `optstring` start with a add sign `+`, means it will stop when it meets first unrecognizable option. 

```c
    /* filter out useful opts */
    while((opt = getopt(argc, argv, "+hvs:E:b:t:")) != -1)
    {
        switch(opt)
        {
            case 'v':
                v_flag = 1;
                break;
            case 's':
                s = atoi(optarg);
                break;
            case 'E':
                E = atoi(optarg);
                break;
            case 'b':
                b = atoi(optarg);
                break;
            case 't':
                target = optarg;
                break;
            case 'h':
            default: /* '?' */
                print_help_msg();
                exit(0);
        }
    }

    /* check arguments */
    if (s <= 0 || E <=0 || b <= 0 || target == NULL)
    {
        fprintf(stderr, "%s: Missing required command line argument\n", argv[0]);
        print_help_msg();
        exit(0);
    }
```

Then, we have to analyze how the trace file access the cache and what should we do to determine it is a hit/miss/eviction. 

To index the cache, we should first know the cache set index from the provided `s, E, b, addr`. Second, we will check the `tag` in all valid cache lines to see if it match. If it does match, we will get a hit, otherwise fail to hit (still need to determine whether it is a miss or eviction). 

If the cache is not full, then it will be a miss and cache will put the data into the empty cache line. If it is full, then we will have to change the content of last used cache line to the new input one, which is an eviction. 

```c
/* access cache with the address to check whether is hit 1/miss 2/eviction 0 */
int access_cache(Cache cache, long unsigned int addr, int s, int E, int b)
{
    long unsigned int tag = addr >> (s + b);
    unsigned int set_idx = (addr >> b) & ((1 << s) - 1);
    int empty = -1;
    int evict = 0;

    cacheSet cacheset = cache[set_idx];

    for (int i = 0; i < E; i++)
    {
        if (cacheset[i].valid_bit)
        {
            if (cacheset[i].tag == tag)
            {
                // hit
                cacheset[i].lru = 0;
                return 1;
            }

            cacheset[i].lru++;

            if (cacheset[evict].lru <= cacheset[i].lru)
            {
                evict = i;
            }
        }
        else
        {
            empty = i;
        }
    }

    if (empty == -1)
    {
        // eviction is as well as a miss
        cacheset[evict].tag = tag;
        cacheset[evict].lru = 0;
        return 0;
    }
    else
    {
        // miss
        cacheset[empty].valid_bit = 1;
        cacheset[empty].tag = tag;
        cacheset[empty].lru = 0;
        return 2;
    }
}
```

So now, the whole program is basically accomplish all goals we would like to achieve, combine them up and add some helper function like `print_help_msg` and scan through the trace file. 

```c
#include "cachelab.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

typedef struct {
    int valid_bit;
    int lru;
    long unsigned int tag;
} cacheLine;

typedef cacheLine* cacheSet;
typedef cacheSet* Cache;

void print_help_msg()
{
    fprintf(stderr, "Usage: ./csim [-hv] -s <num> -E <num> -b <num> -t <file> \n\
Options:\n\
  -h         Print this help message.\n\
  -v         Optional verbose flag. \n\
  -s <num>   Number of set index bits. \n\
  -E <num>   Number of lines per set. \n\
  -b <num>   Number of block offset bits. \n\
  -t <file>  Trace file. \n\
\n\
Examples: \n\
  linux>  ./csim -s 4 -E 1 -b 4 -t traces/yi.trace \n\
  linux>  ./csim -v -s 8 -E 2 -b 4 -t traces/yi.trace \n");
}

/* initialize cache, allocate enough space for the cache */
Cache init_cache(int s, int E, int b)
{
    int S = 1 << s;
    Cache cache = (Cache)malloc(sizeof(cacheSet) * S);
    if (cache == NULL) return NULL;
    for (int i = 0; i < S; i++)
    {
        cache[i] = (cacheSet)calloc(E, sizeof(cacheLine));
        if (cache[i] == NULL) return NULL;
    }
    return cache;
}

/* free cache one by one */
void free_cache(Cache cache, int s)
{
    int S = 1 << s;
    for (int i = 0; i < S; i++)
    {
        free(cache[i]);
    }
    free(cache);
}

/* access cache with the address to check whether is hit 1/miss 2/eviction 0 */
int access_cache(Cache cache, long unsigned int addr, int s, int E, int b)
{
    long unsigned int tag = addr >> (s + b);
    unsigned int set_idx = (addr >> b) & ((1 << s) - 1);
    int empty = -1;
    int evict = 0;

    cacheSet cacheset = cache[set_idx];

    for (int i = 0; i < E; i++)
    {
        if (cacheset[i].valid_bit)
        {
            if (cacheset[i].tag == tag)
            {
                // hit
                cacheset[i].lru = 0;
                return 1;
            }

            cacheset[i].lru++;

            if (cacheset[evict].lru <= cacheset[i].lru)
            {
                evict = i;
            }
        }
        else
        {
            empty = i;
        }
    }

    if (empty == -1)
    {
        // eviction is as well as a miss
        cacheset[evict].tag = tag;
        cacheset[evict].lru = 0;
        return 0;
    }
    else
    {
        // miss
        cacheset[empty].valid_bit = 1;
        cacheset[empty].tag = tag;
        cacheset[empty].lru = 0;
        return 2;
    }
}

int main(int argc, char *argv[])
{
    int opt;
    int v_flag = 0;
    int s = 0;
    int E = 0;
    int b = 0;
    char *target;

    /* filter out useful opts */
    while((opt = getopt(argc, argv, "+hvs:E:b:t:")) != -1)
    {
        switch(opt)
        {
            case 'v':
                v_flag = 1;
                break;
            case 's':
                s = atoi(optarg);
                break;
            case 'E':
                E = atoi(optarg);
                break;
            case 'b':
                b = atoi(optarg);
                break;
            case 't':
                target = optarg;
                break;
            case 'h':
            default: /* '?' */
                print_help_msg();
                exit(0);
        }
    }

    /* check arguments */
    if (s <= 0 || E <=0 || b <= 0 || target == NULL)
    {
        fprintf(stderr, "%s: Missing required command line argument\n", argv[0]);
        print_help_msg();
        exit(0);
    }

    /* initilize cache */
    Cache cache = init_cache(s, E, b);
    if ( cache == NULL)
    {
        fprintf(stderr, "Fail to initilize caches!");
        exit(0);
    }

    FILE *target_file;
    target_file = fopen(target, "r");
    if (target_file == NULL)
    {
        fprintf(stderr, "Fail to open the trace file!");
        exit(0);
    }

    /* scan through file*/
    char operation;
    long unsigned int addr;
    int size;

    int hit_count = 0;
    int miss_count = 0;
    int eviction_count = 0;

    int condition;
    char* template[] = {"eviction", "hit", "miss"};

    while (fscanf(target_file, " %c %lx, %d\n", &operation, &addr, &size) != -1)
    {
        switch(operation)
        {
            case 'I':
                continue;
            case 'L':
            case 'S':
                condition = access_cache(cache, addr, s, E, b);
                break;
            case 'M':
                condition = access_cache(cache, addr, s, E, b);
                hit_count++;
                break;
            default:
                fprintf(stderr, "Wrong operation in trace file!");
                exit(0);
        }

        switch(condition)
        {
            // eviction is also miss
            case 0:
                eviction_count++;
                miss_count++;
                break;
            // hit
            case 1:
                hit_count++;
                break;
            // miss
            case 2:
                miss_count++;
                break;
        }

        if (v_flag)
        {
            switch(operation)
            {
                case 'L':
                case 'S':
                    printf("%c %lx, %d %s\n", operation, addr, size, template[condition]);
                    break;
                case 'M':
                    printf("%c %lx, %d %s hit\n", operation, addr, size, template[condition]);
                    break;
            }

        }
    }

    printSummary(hit_count, miss_count, eviction_count);
    free_cache(cache, s);
    fclose(target_file);

    return 0;
}
```

Result:

```
Part A: Testing cache simulator
Running ./test-csim
                        Your simulator     Reference simulator
Points (s,E,b)    Hits  Misses  Evicts    Hits  Misses  Evicts
     3 (1,1,1)       9       8       6       9       8       6  traces/yi2.trace
     3 (4,2,4)       4       5       2       4       5       2  traces/yi.trace
     3 (2,1,4)       2       3       1       2       3       1  traces/dave.trace
     3 (2,1,3)     167      71      67     167      71      67  traces/trans.trace
     3 (2,2,3)     201      37      29     201      37      29  traces/trans.trace
     3 (2,4,3)     212      26      10     212      26      10  traces/trans.trace
     3 (5,1,5)     231       7       0     231       7       0  traces/trans.trace
     6 (5,1,5)  265189   21775   21743  265189   21775   21743  traces/long.trace
    27
```

### Reverse Engineering

This is a trickier version of solve. Since professor provide with the reference file, we can reverse engineer it to get the content and logic in the `csim-ref` binary file. Luckily, it comiles with all symbol preserved, it looks exactly the same as the source code in some professional reverse engineering tools. Here is just an example:

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char c; // [rsp+2Fh] [rbp-1h]

  while ( 1 )
  {
    c = getopt(argc, (char *const *)argv, "s:E:b:t:vh");
    if ( c == -1 )
      break;
    switch ( c )
    {
      case 'E':
        E = atoi(optarg);
        break;
      case 'b':
        b = atoi(optarg);
        break;
      case 'h':
        printUsage((char **)argv);
      case 's':
        s = atoi(optarg);
        break;
      case 't':
        trace_file = optarg;
        break;
      case 'v':
        verbosity = 1;
        break;
      default:
        printUsage((char **)argv);
    }
  }
  if ( !s || !E || !b || !trace_file )
  {
    printf("%s: Missing required command line argument\n", *argv);
    printUsage((char **)argv);
  }
  S = (int)pow(2.0, (double)s);
  B = (int)pow(2.0, (double)b);
  initCache();
  replayTrace(trace_file);
  freeCache();
  printSummary(hit_count, miss_count, eviction_count);
  return 0;
}
```

Through reverse the logic, we can also know what we need to do in our program XD. 

## Part B

In part B, we are going to write a function to transpose matrix with different sizes 32 x 32, 64 x 64, 61 x 67, under the cache condition of `s = 5, E = 1, b = 5`, which has 32 set/line, each line have 32 bytes.

### 32 x 32

For 32 x 32 matrix is easy. Since each line of cache can store at most 8 `int`. Split the block into 8 x 8 submatrix, read out each line in matrix A and copy to each column in matrix B will solve the problem. 

```c
if (M == 32)
{
    int i, j, k;
    int t0, t1, t2, t3, t4, t5, t6, t7;
    for (i = 0; i < N; i += 8)
    {
        for (j = 0; j < M; j += 8)
        {
            for (k = i; k < i + 8; k++)
            {
                t0 = A[k][j];
                t1 = A[k][j + 1];
                t2 = A[k][j + 2];
                t3 = A[k][j + 3];
                t4 = A[k][j + 4];
                t5 = A[k][j + 5];
                t6 = A[k][j + 6];
                t7 = A[k][j + 7];

                B[j][k] = t0;
                B[j + 1][k] = t1;
                B[j + 2][k] = t2;
                B[j + 3][k] = t3;
                B[j + 4][k] = t4;
                B[j + 5][k] = t5;
                B[j + 6][k] = t6;
                B[j + 7][k] = t7;
            }
        }
    }
}
```

Result:

```
Function 0 (2 total)
Step 1: Validating and generating memory traces
Step 2: Evaluating performance (s=5, E=1, b=5)
func 0 (Transpose submission): hits:1766, misses:287, evictions:255

Function 1 (2 total)
Step 1: Validating and generating memory traces
Step 2: Evaluating performance (s=5, E=1, b=5)
func 1 (Simple row-wise scan transpose): hits:870, misses:1183, evictions:1151

Summary for official submission (func 0): correctness=1 misses=287

TEST_TRANS_RESULTS=1:287
```

### 64 x 64

This is the hardest part in the assignment, I didn't finish this myself, so I take reference from [here](https://zhuanlan.zhihu.com/p/42754565). 

So basically, the idea is to split 8 x 8  matrix into smaller 4 x 4 matrix. However, if we directly apply the idea to the 8 x 8 matrix, the result will be the same as spliting the original matrix into 4 x 4 matrix, which is about 1644 misses, fail the test.

That's because these two method have the same idea, which is to read 4 row in A and write 4 column in B. So they have the same result, no matter what size you original matrix are.   

The trick is that: When reading first four lines of the 8 x 8 submatrix, it also reads in the content in the block `2` and store somewhere in matrix B (the content in B doesn't matter because not finish yet). We use same cache to read out more data. 

Then, we reuse the cache to recover the lost block `2` in matrix B and copy the rest content to B.   

```
1   2

3   4
```

So in the code, it reverse the read sequence to "preheat" the cache prepare for the following read/write in block `3` and `4` to decrease the miss further.  

```c
if (M == 64)
{
    int i, j, k, l;
    int t0, t1, t2, t3, t4, t5, t6, t7;
    for (i = 0; i < N; i += 8)
    {
        for (j = 0; j < M; j += 8)
        {
            for (k = i; k < i + 4; ++k)
            {
                /* read upper left, upper right*/
                t0 = A[k][j];
                t1 = A[k][j+1];
                t2 = A[k][j+2];
                t3 = A[k][j+3];
                t4 = A[k][j+4];
                t5 = A[k][j+5];
                t6 = A[k][j+6];
                t7 = A[k][j+7];

                B[j][k] = t0;
                B[j+1][k] = t1;
                B[j+2][k] = t2;
                B[j+3][k] = t3;
                /* reverse the sequence */
                B[j][k+4] = t7;
                B[j+1][k+4] = t6;
                B[j+2][k+4] = t5;
                B[j+3][k+4] = t4;
            }
            for (l = 0; l < 4; ++l)
            {
               /* read by column */
                t0 = A[i+4][j+3-l];
                t1 = A[i+5][j+3-l];
                t2 = A[i+6][j+3-l];
                t3 = A[i+7][j+3-l];
                t4 = A[i+4][j+4+l];
                t5 = A[i+5][j+4+l];
                t6 = A[i+6][j+4+l];
                t7 = A[i+7][j+4+l];

               /* transfer upper right to lower left */
                B[j+4+l][i] = B[j+3-l][i+4];
                B[j+4+l][i+1] = B[j+3-l][i+5];
                B[j+4+l][i+2] = B[j+3-l][i+6];
                B[j+4+l][i+3] = B[j+3-l][i+7];
               /* place the lower blocks to right */
                B[j+3-l][i+4] = t0;
                B[j+3-l][i+5] = t1;
                B[j+3-l][i+6] = t2;
                B[j+3-l][i+7] = t3;
                B[j+4+l][i+4] = t4;
                B[j+4+l][i+5] = t5;
                B[j+4+l][i+6] = t6;
                B[j+4+l][i+7] = t7;
            }
        }
    }
}
```

Result:

```
Function 1 (2 total)
Step 1: Validating and generating memory traces
Step 2: Evaluating performance (s=5, E=1, b=5)
func 1 (Simple row-wise scan transpose): hits:3474, misses:4723, evictions:4691

Summary for official submission (func 0): correctness=1 misses=1243

TEST_TRANS_RESULTS=1:1243
```

### 61 x 67

This is also very simple to deal with. Since it is not a square matrix, the improvement to split the matrix into smaller part is little. We can just split it into 16 x 16 matrix and it will be fine. 

```c
if (M == 61)
{
    int i, j, k, l;
    for (i = 0; i < N; i += 16)
    {
        for (j = 0; j < M; j += 16)
        {
            for (k = i; k < i + 16 && k < N; k++)
            {
                for (l = j; l < j + 16 && l < M; l++)
                {
                    B[l][k] = A[k][l];
                }
            }
        }
    }
}
```

Result:

```
Function 0 (2 total)
Step 1: Validating and generating memory traces
Step 2: Evaluating performance (s=5, E=1, b=5)
func 0 (Transpose submission): hits:6187, misses:1992, evictions:1960

Function 1 (2 total)
Step 1: Validating and generating memory traces
Step 2: Evaluating performance (s=5, E=1, b=5)
func 1 (Simple row-wise scan transpose): hits:3756, misses:4423, evictions:4391

Summary for official submission (func 0): correctness=1 misses=1992

TEST_TRANS_RESULTS=1:1992
```