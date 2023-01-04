# Malloclab

This is the writeup for CSAPP Malloclab

I am writing this blog after spending two days working on the malloclab. Finally came out with a piece of shit. I got 85/100 in this lab, which almost "totally references" others' implementations. I should do more work on C programming. I still have a long way to go. :(

## Goals

In this lab, we are going to write our own dynamic memory allocator, including the functionalities of what we usually use: `malloc`, `free`, and `realloc`. We will have to finish four functions in the provided lab handout: `mm_init`, `mm_malloc`, `mm_free`, and `mm_realloc`. Similar to the original malloc (ptmalloc), our dynamic allocator is an immediate general-purpose allocator, which (1) we may not make any assumption on the data structure we are going to store. (2) have to make allocation immediately after calling the allocation function. (3) data should align with the 8-byte alignment. 

We will have a check program `mdriver.c`, after we do `make` in the handout directory, we are able to run the driver and test our code on different functionalities. (Caution: the trace file does not provide us with the handout, you may search on the web or use what I found in my [CSAPP github repo](https://github.com/ThomasonZhao/CMU-15-213-CSAPP))

Similar to the syscall that manages the virtual memory: `brk`, `sbrk`, and `mmap` (which we are not going to use), the handout provides us some syscall-like functions in `memlib.c`: `mem_sbrk`, `mem_heap_lo`, `mem_heap_hi`, `mem_heapsize`, and `mem_pagesize`.

## Implementations

### Implicit Free List

Implicit free list implementation is actually provided by the code in the book. The data structure used in this implementation is as follows:

```c
typedef struct block
{
    word_t header;
    void *data;
    word_t footer;
}
```

```
| header | data block & padding | footer | another header | ... |
```

> By the way, this project doesn't allow us to define any explicitly stated structure like above, so we may first find out a good way to do the pointer arithmetic.

We are suggested to use the macro to solve this issue. The reason not to use different helper functions to implement pointer arithmetic is that function calls are expensive. Each pointer arithmetic is really simple, but to make a function call needs to allocate a stack, jump to the function body, and jump back. This lab will be going to measure both the memory utilization of the implementation and the throughput. Macros, on the other hand, will do the pointer arithmetic in the compile time. The compiler will transform different macros to the corresponding assembly instructions and replace them everywhere in the binary ELF file. 

The book provides us with the macro below. With those macros, we can easily manipulate the heap block data structure. 

```c
/* Basic constants and macros */
#define WSIZE 4             /* Word and header/footer size (bytes) */
#define DSIZE 8             /* Double word size (bytes) */
#define CHUNKSIZE (1 << 12) /* Extend heap by this amount (bytes) */

#define MAX(x, y) ((x) > (y) ? (x) : (y))

/* Pack a size and allocated bit into a word */
#define PACK(size, alloc) ((size) | (alloc))

/* Read and write a word at address p */
#define GET(p) (*(unsigned int *)(p))
#define PUT(p, val) (*(unsigned int *)(p) = (val))

/* Read the size and allocated fields from address p */
#define GET_SIZE(p) (GET(p) & ~0x7)
#define GET_ALLOC(p) (GET(p) & 0x1)

/* Given block ptr bp, compute address of its header and footer */
#define HDRP(bp) ((char *)(bp) - WSIZE)
#define FTRP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)

/* Given block ptr bp, compute address of next and previous blocks */
#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE(((char *)(bp) - WSIZE)))
#define PREV_BLKP(bp) ((char *)(bp) - GET_SIZE(((char *)(bp) - DSIZE)))
```

The implementation details will be discussed through the sequence of the calling routine. 

`mm_init` function is straightforward. First open part of the memory region for a default heap data structure: prologue and epilogue. These two data blocks are used to constrain the search will not go ahead of the heap start (prologue) and will not go beyond the heap end (epilogue). Then we extend a `CHUNKSIZE` of the heap to store values.

```c
/*
 * mm_init - Initialize the malloc package.
 */
int mm_init(void)
{
    size_t init_brk_size = 4 * WSIZE;

    /* Create the initial empty heap */
    if ((heap_listp = mem_sbrk(init_brk_size)) == (void *)-1)
        return -1;

    PUT(heap_listp, 0);                            /* Alignment padding */
    PUT(heap_listp + (1 * WSIZE), PACK(DSIZE, 1)); /* Prologue header */
    PUT(heap_listp + (2 * WSIZE), PACK(DSIZE, 1)); /* Prologue footer */
    PUT(heap_listp + (3 * WSIZE), PACK(0, 1));     /* Epilogue header */
    heap_listp += (2 * WSIZE);

    /* Extend the empty heap with a free block of CHUNKSIZE bytes */
    if (extend_heap(CHUNKSIZE / WSIZE) == NULL)
        return -1;
    return 0;
}
```

```
| padding | prologue header | prologue footer | heap start from here | ... | epilogue header |
```

`extend_heap` function mainly does two things: (1) use sbrk to open new space for heap. (2) make sure the newly opened space will be consistent with the original blocks, which we will use `coalesce` function for the newly inserted free block.

```c
/*
 * extend_heap - Extend heap with free block and return its block pointer
 */
static void *extend_heap(size_t words)
{
    char *bp;
    size_t size;

    /* Allocate an even number of words to maintain alignment */
    size = (words % 2) ? (words + 1) * WSIZE : words * WSIZE;
    if ((long)(bp = mem_sbrk(size)) == -1)
        return NULL;

    /* Initialize free block header/footer and the epilogue header */
    PUT(HDRP(bp), PACK(size, 0));         /* Free block header */
    PUT(FTRP(bp), PACK(size, 0));         /* Free block footer */
    PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1)); /* New epilogue header */

    SET_PREV(bp, 0);
    SET_NEXT(bp, 0);

    /* Coalesce if the previous block was free */
    return coalesce(bp);
}
```

`coalesce` function will coalesce the previous and next free block to make a continuous big free block. Discuss the condition case by case based on the allocation bit that is stored in the header and footer of the previous and next blocks will be very easy to implement.

```c
/*
 * coalesce - Boundary tag coalescing. Return ptr to coalesced block
 */
static void *coalesce(void *bp)
{
    size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp)));
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
    size_t size = GET_SIZE(HDRP(bp));

    if (prev_alloc && next_alloc)
    { /* Case 1 */
    }

    else if (prev_alloc && !next_alloc)
    { /* Case 2 */
        size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
        PUT(HDRP(bp), PACK(size, 0));
        PUT(FTRP(bp), PACK(size, 0));
    }

    else if (!prev_alloc && next_alloc)
    { /* Case 3 */
        size += GET_SIZE(HDRP(PREV_BLKP(bp)));
        PUT(FTRP(bp), PACK(size, 0));
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
        bp = PREV_BLKP(bp);
    }

    else
    { /* Case 4 */
        size += GET_SIZE(HDRP(PREV_BLKP(bp))) +
                GET_SIZE(FTRP(NEXT_BLKP(bp)));
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
        PUT(FTRP(NEXT_BLKP(bp)), PACK(size, 0));
        bp = PREV_BLKP(bp);
    }

    return bp;
}
```

`mm_malloc` function will deal with first aligning the size (including header, footer, and data block size) provided by the user, trying to find a fit block of this size. There are two different search algorithms that will be discussed later: [First Fit Search](#first-fit-search) and [Best Fit Search](#best-fit-search). If it fails, try to extend the heap by at least a `CHUNKSIZE` and return the new ptr as the allocated block. 

```c
/*
 * mm_malloc - Allocate a block with at least size bytes of payload
 */
void *mm_malloc(size_t size)
{
    size_t asize;      /* Adjusted block size */
    size_t extendsize; /* Amount to extend heap if no fit */
    char *bp;

    if (heap_listp == 0)
        mm_init();

    /* Ignore spurious requests */
    if (size == 0)
        return NULL;

    /* Adjust block size to include overhead and alignment reqs. */
    asize = ALIGN(size + DSIZE);

    /* Search the free list for a fit */
    if ((bp = find_fit(asize)) != NULL)
    {
        place(bp, asize);
        return bp;
    }

    /* No fit found. Get more memory and place the block */
    extendsize = MAX(asize, CHUNKSIZE);
    if ((bp = extend_heap(extendsize / WSIZE)) == NULL)
        return NULL;

    place(bp, asize);
    return bp;
}
```

`place` function just to place the newly allocated block, mark it as allocated and do the split if the block is too large to fit. 

```c
/*
 * place - Place block of asize bytes at start of free block bp
 *         and split if remainder would be at least minimum block size
 */
static void place(void *bp, size_t asize)
{
    size_t csize = GET_SIZE(HDRP(bp));

    if ((csize - asize) >= (2 * DSIZE))
    { /* Split large free block */
        PUT(HDRP(bp), PACK(asize, 1));
        PUT(FTRP(bp), PACK(asize, 1));
        bp = NEXT_BLKP(bp);
        PUT(HDRP(bp), PACK(csize - asize, 0));
        PUT(FTRP(bp), PACK(csize - asize, 0));

        SET_PREV(bp, 0);
        SET_NEXT(bp, 0);
        coalesce(bp);
    }
    else
    { /* Do not split */
        PUT(HDRP(bp), PACK(csize, 1));
        PUT(FTRP(bp), PACK(csize, 1));
    }
}
```

`mm_free` and `mm_realloc` will be easy to implement, so just place the code here.

```c
/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
    void *bp = ptr;

    if (bp == NULL)
        return;

    size_t size = GET_SIZE(HDRP(bp));

    PUT(HDRP(bp), PACK(size, 0));
    PUT(FTRP(bp), PACK(size, 0));
    SET_PREV(bp, NULL);
    SET_NEXT(bp, NULL);
    coalesce(bp);
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    size_t oldsize;
    void *newptr;

    /* If size == 0 then this is just free, and we return NULL. */
    if (size == 0)
    {
        mm_free(ptr);
        return NULL;
    }

    /* If oldptr is NULL, then this is just malloc. */
    if (ptr == NULL)
    {
        return mm_malloc(size);
    }

    /* Copy the old data. */
    oldsize = GET_SIZE(HDRP(ptr));
    if (ALIGN(size + DSIZE) > oldsize)
    {
        newptr = mm_malloc(size);
        /* If realloc() fails the original block is left untouched  */
        if (!newptr)
        {
            return NULL;
        }

        memcpy(newptr, ptr, oldsize - WSIZE);
        oldsize = size;

        /* Free the old block. */
        mm_free(ptr);

        return newptr;
    }

    return ptr;
}
```

#### First Fit Search

First fit search version of `find_fit` helper function:

```c
/*
 * find_fit - Find a fit for a block with asize bytes
 */
static void *find_fit(size_t asize)
{
    /* First-fit search */
    void *bp;

    for (bp = heap_listp; GET_SIZE(HDRP(bp)) > 0; bp = NEXT_BLKP(bp))
    {
        if (!GET_ALLOC(HDRP(bp)) && (asize <= GET_SIZE(HDRP(bp))))
        {
            return bp;
        }
    }
    return NULL; /* No fit */
}
```

Only implement the first fit search is not good enough, the utilization is fine, but throuput is too low.

```
Results for mm malloc:
trace  valid  util     ops      secs  Kops
 0       yes   99%    5694  0.009120   624
 1       yes   99%    5848  0.008181   715
 2       yes   99%    6648  0.013710   485
 3       yes  100%    5380  0.010180   528
 4       yes   66%   14400  0.000756 19050
 5       yes   91%    4800  0.009039   531
 6       yes   92%    4800  0.007961   603
 7       yes   55%   12000  0.242923    49
 8       yes   51%   24000  0.386055    62
 9       yes   27%   14401  0.119937   120
10       yes   34%   14401  0.004224  3409
Total          74%  112372  0.812084   138

Perf index = 44 (util) + 9 (thru) = 54/100
```

#### Next Fit Search

The next fit search version of `find_fit` helper function is shown below. We will need an additional global `rover` to store what is the last allocated block. We search from that block to the end, then search from the beginning until around back to `rover` block. 

```c
/*
 * find_fit - Find a fit for a block with asize bytes
 */
static void *find_fit(size_t asize)
{
    /* Next fit search */
    char *oldrover = rover;

    /* Search from the rover to the end of list */
    for (; GET_SIZE(HDRP(rover)) > 0; rover = NEXT_BLKP(rover))
        if (!GET_ALLOC(HDRP(rover)) && (asize <= GET_SIZE(HDRP(rover))))
            return rover;

    /* search from start of list to old rover */
    for (rover = heap_listp; rover < oldrover; rover = NEXT_BLKP(rover))
        if (!GET_ALLOC(HDRP(rover)) && (asize <= GET_SIZE(HDRP(rover))))
            return rover;

    return NULL; /* no fit found */
}
```

The result of the test shows that next fit is a lot better than the first fit search (probably because most of the test trace are written in malloc a lot of block at the beginning)

```
Results for mm malloc:
trace  valid  util     ops      secs  Kops
 0       yes   91%    5694  0.002856  1994
 1       yes   92%    5848  0.001983  2949
 2       yes   95%    6648  0.005219  1274
 3       yes   97%    5380  0.005443   988
 4       yes   66%   14400  0.000714 20182
 5       yes   90%    4800  0.005957   806
 6       yes   89%    4800  0.006055   793
 7       yes   55%   12000  0.027610   435
 8       yes   51%   24000  0.014347  1673
 9       yes   27%   14401  0.118755   121
10       yes   45%   14401  0.004188  3438
Total          73%  112372  0.193127   582

Perf index = 44 (util) + 39 (thru) = 82/100
```

#### Best Fit Search

I didn't implement the best fit search, but I did implement it on my wisc easier version of malloc lab. So the logic is easy and can add on to both the first fit and next fit search. Have an additional variable to store the best size fit and the best fit block pointer. If we find another block fits better than the current one, we replace it with the new one. Once we find a perfect fit (same size), then we terminate the search and return that block.  

### Segregate Free List

Rather than using the implicit free list, we could make the free list visible to our program so that we can search through the free list instead of the. Though there are still many different implementations on the free list. I choose a relatively more sufficient implementation: segregate free list.

Segregate free list, by definition, is to put multiple free blocks within a range of size into a separate free list. We could have multiple ranges of sizes, here for malloclab, I choose the range cutoff: `16 32 64 128 256 512 1024 2048 4096`. Each free block will have a new data structure as follow:

```c
typedef struct free_block
{
    word_t header;
    void *prev;
    void *next;
    void *leftover_data;
    word_t footer;
}
```

Since new data structure is introduced, we will need new macrod to deal with the free list.

```c
/* Given free block ptr fbp, read and write prev and next ptr */
#define GET_PREV(fbp) (GET(fbp))
#define SET_PREV(fbp, prev) (PUT((fbp), (prev)))
#define GET_NEXT(fbp) (GET((char *)(fbp) + WSIZE))
#define SET_NEXT(fbp, next) (PUT((char *)(fbp) + WSIZE, (next)))
```

In order to store the free list, we will need additional space in the heap block to store it, so we will first make more room in the heap block to store the list.

`sgrgt_list_init` function is used to initialize the segregate list before we initialize any prologue and epilogue block in the `mm_init` function. 

```c
/*
 * sgrgt_list_init - Initialize the segregate list at the beginning of the heap.
 */
static void sgrgt_list_init(void)
{
    sgrgt_listp = (unsigned int *)heap_listp;
    PUT(heap_listp + (0 * WSIZE), 0); /* size <= 16 */
    PUT(heap_listp + (1 * WSIZE), 0); /* size <= 32 */
    PUT(heap_listp + (2 * WSIZE), 0); /* size <= 64 */
    PUT(heap_listp + (3 * WSIZE), 0); /* size <= 128 */
    PUT(heap_listp + (4 * WSIZE), 0); /* size <= 256 */
    PUT(heap_listp + (5 * WSIZE), 0); /* size <= 512 */
    PUT(heap_listp + (6 * WSIZE), 0); /* size <= 1024 */
    PUT(heap_listp + (7 * WSIZE), 0); /* size <= 2048 */
    PUT(heap_listp + (8 * WSIZE), 0); /* size <= 4096 */
    PUT(heap_listp + (9 * WSIZE), 0); /* size >  4096 */

    /* Shift the start of the heap */
    heap_listp += 10 * WSIZE;
}
```

`sgrgt_list_insrt` and `sgrgt_list_remov` functions are used to insert and remove a block to/from the segregate list. The implementation is easy, just a double-linked list insert and remove.  A block should be inserted if it was coalesced in `coalesce` function and removed if it was to place as an allocated block in `place` function or coalesced in `coalesce` function to make a bigger free block.

```c
/*
 * insrt_sgrgt_list - Insert a block to segregate list
 */
static void sgrgt_list_insrt(void *bp)
{
    if (bp == NULL)
        return;
    void *root = sgrgt_listp + sgrgt_list_idx(GET_SIZE(HDRP(bp)));
    void *curr = root;
    void *next = GET(root);

    while (next)
    {
        if (GET_SIZE(HDRP(next)) >= GET_SIZE(HDRP(bp)))
            break;

        curr = next;
        next = GET_NEXT(next);
    }

    if (curr == root)
    { /* Insert into root */
        PUT(root, bp);
        SET_PREV(bp, NULL);
        SET_NEXT(bp, next);
        if (next != NULL)
            SET_PREV(next, bp);
    }
    else
    { /* Insert between curr and next */
        SET_PREV(bp, curr);
        SET_NEXT(bp, next);
        SET_NEXT(curr, bp);
        if (next != NULL)
            SET_PREV(next, bp);
    }
}

/*
 * remov_sgrgt_list - Remove a block from segregate list
 */
static void sgrgt_list_remov(void *bp)
{
    if (bp == NULL || GET_ALLOC(HDRP(bp)))
        return;
    void *root = sgrgt_listp + sgrgt_list_idx(GET_SIZE(HDRP(bp)));
    void *prev = GET_PREV(bp);
    void *next = GET_NEXT(bp);

    /* Clear pointers */
    SET_PREV(bp, NULL);
    SET_NEXT(bp, NULL);

    if (prev == NULL)
    {
        if (next != NULL)
            SET_PREV(next, NULL);
        PUT(root, next);
    }
    else
    {
        if (next != NULL)
            SET_PREV(next, prev);
        SET_NEXT(prev, next);
    }
}
```

With all those helper functions above (and some small logic like setting the prev and next pointer when a free a block, remove the redundant pointer after alloc the block. Check out the [CSAPP github repo](https://github.com/ThomasonZhao/CMU-15-213-CSAPP)), we could successfully implement the segregate list version of malloc. The improvement is huge compared to the first version.

```
Results for mm malloc:
trace  valid  util     ops      secs  Kops
 0       yes   99%    5694  0.000922  6173
 1       yes   99%    5848  0.000932  6274
 2       yes   99%    6648  0.001061  6268
 3       yes  100%    5380  0.000919  5855
 4       yes   66%   14400  0.002008  7170
 5       yes   94%    4800  0.001548  3101
 6       yes   95%    4800  0.001583  3032
 7       yes   55%   12000  0.001968  6099
 8       yes   51%   24000  0.004786  5015
 9       yes   31%   14401  0.122253   118
10       yes   30%   14401  0.005329  2702
Total          75%  112372  0.143308   784

Perf index = 45 (util) + 40 (thru) = 85/100
```

## Debugging Tips

Modify the `Makefile` to compile the program with debugging symbols and also turns on the `gprof` profile check.

```makefile
# Modified parts

CFLAGS = -Wall -Og -m32 -pg -g
# -Og optimization will not interrupt the debugging
# -pg gprof profile check
# -g  compile with debugging symbol

test: mdriver
	./mdriver -V
	gprof ./mdriver > gprof.out
	cat gprof.out
```

`gprof` is a great tool to find out where we could do to improve the program. It will give a detailed call graph of the program and also some analysis on it. Here is what I have on the segregate free list version

```
Flat profile:

Each sample counts as 0.01 seconds.
  %   cumulative   self              self     total           
 time   seconds   seconds    calls  ms/call  ms/call  name    
 72.66      0.93     0.93       11    84.55   110.38  eval_mm_valid
 13.28      1.10     0.17    60985     0.00     0.00  add_range
  8.59      1.21     0.11    60985     0.00     0.00  remove_range
  1.56      1.23     0.02  1426824     0.00     0.00  sgrgt_list_insrt
  0.78      1.24     0.01  3563688     0.00     0.00  sgrgt_list_idx
  0.78      1.25     0.01   710172     0.00     0.00  find_fit
  0.78      1.26     0.01   710172     0.00     0.00  mm_free
  0.78      1.27     0.01      110     0.09     0.47  eval_mm_speed
  0.78      1.28     0.01       11     0.91     1.29  eval_mm_util
  0.00      1.28     0.00  1426824     0.00     0.00  coalesce
  0.00      1.28     0.00  1426692     0.00     0.00  sgrgt_list_remov
  0.00      1.28     0.00   710172     0.00     0.00  mm_malloc
  0.00      1.28     0.00   710172     0.00     0.00  place
  0.00      1.28     0.00   121970     0.00     0.00  mem_heap_hi
  0.00      1.28     0.00   121970     0.00     0.00  mem_heap_lo
  0.00      1.28     0.00   115176     0.00     0.00  mm_realloc
  0.00      1.28     0.00    56388     0.00     0.00  mem_sbrk
  0.00      1.28     0.00    56256     0.00     0.00  extend_heap
  0.00      1.28     0.00      132     0.00     0.00  mem_reset_brk
  0.00      1.28     0.00      132     0.00     0.00  mm_init
  0.00      1.28     0.00      132     0.00     0.00  sgrgt_list_init
  0.00      1.28     0.00       11     0.00     0.00  clear_ranges
  0.00      1.28     0.00       11     0.00     0.00  free_trace
  0.00      1.28     0.00       11     0.00     4.70  fsecs
  0.00      1.28     0.00       11     0.00     4.70  ftimer_gettod
  0.00      1.28     0.00       11     0.00     0.00  mem_heapsize
  0.00      1.28     0.00       11     0.00     0.00  read_trace
  0.00      1.28     0.00        1     0.00     0.00  init_fsecs
  0.00      1.28     0.00        1     0.00     0.00  mem_init
  0.00      1.28     0.00        1     0.00     0.00  printresults

 %         the percentage of the total running time of the
time       program used by this function.

cumulative a running sum of the number of seconds accounted
 seconds   for by this function and those listed above it.

 self      the number of seconds accounted for by this
seconds    function alone.  This is the major sort for this
           listing.

calls      the number of times this function was invoked, if
           this function is profiled, else blank.

 self      the average number of milliseconds spent in this
ms/call    function per call, if this function is profiled,
	   else blank.

 total     the average number of milliseconds spent in this
ms/call    function and its descendents per call, if this
	   function is profiled, else blank.

name       the name of the function.  This is the minor sort
           for this listing. The index shows the location of
	   the function in the gprof listing. If the index is
	   in parenthesis it shows where it would appear in
	   the gprof listing if it were to be printed.

Copyright (C) 2012-2020 Free Software Foundation, Inc.

Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved.

		     Call graph (explanation follows)


granularity: each sample hit covers 4 byte(s) for 0.78% of 1.28 seconds

index % time    self  children    called     name
                                                 <spontaneous>
[1]    100.0    0.00    1.28                 main [1]
                0.93    0.28      11/11          eval_mm_valid [2]
                0.00    0.05      11/11          fsecs [6]
                0.01    0.00      11/11          eval_mm_util [12]
                0.00    0.00      11/11          free_trace [26]
                0.00    0.00      11/11          read_trace [28]
                0.00    0.00       1/1           init_fsecs [29]
                0.00    0.00       1/1           mem_init [30]
                0.00    0.00       1/1           printresults [31]
-----------------------------------------------
                0.93    0.28      11/11          main [1]
[2]     94.9    0.93    0.28      11         eval_mm_valid [2]
                0.17    0.00   60985/60985       add_range [3]
                0.11    0.00   60985/60985       remove_range [4]
                0.00    0.00   51387/710172      mm_malloc [8]
                0.00    0.00   51387/710172      mm_free [11]
                0.00    0.00    9598/115176      mm_realloc [16]
                0.00    0.00      11/132         mm_init [19]
                0.00    0.00      11/132         mem_reset_brk [23]
                0.00    0.00      11/11          clear_ranges [25]
-----------------------------------------------
                0.17    0.00   60985/60985       eval_mm_valid [2]
[3]     13.3    0.17    0.00   60985         add_range [3]
                0.00    0.00  121970/121970      mem_heap_lo [21]
                0.00    0.00  121970/121970      mem_heap_hi [20]
-----------------------------------------------
                0.11    0.00   60985/60985       eval_mm_valid [2]
[4]      8.6    0.11    0.00   60985         remove_range [4]
-----------------------------------------------
                0.01    0.04     110/110         ftimer_gettod [7]
[5]      4.0    0.01    0.04     110         eval_mm_speed [5]
                0.00    0.02  513870/710172      mm_malloc [8]
                0.01    0.01  513870/710172      mm_free [11]
                0.00    0.01   95980/115176      mm_realloc [16]
                0.00    0.00     110/132         mm_init [19]
                0.00    0.00     110/132         mem_reset_brk [23]
-----------------------------------------------
                0.00    0.05      11/11          main [1]
[6]      4.0    0.00    0.05      11         fsecs [6]
                0.00    0.05      11/11          ftimer_gettod [7]
-----------------------------------------------
                0.00    0.05      11/11          fsecs [6]
[7]      4.0    0.00    0.05      11         ftimer_gettod [7]
                0.01    0.04     110/110         eval_mm_speed [5]
-----------------------------------------------
                0.00    0.00   51387/710172      eval_mm_util [12]
                0.00    0.00   51387/710172      eval_mm_valid [2]
                0.00    0.00   93528/710172      mm_realloc [16]
                0.00    0.02  513870/710172      eval_mm_speed [5]
[8]      2.1    0.00    0.03  710172         mm_malloc [8]
                0.00    0.01  710172/710172      place [13]
                0.01    0.00  710172/710172      find_fit [14]
                0.00    0.00   56124/56256       extend_heap [18]
-----------------------------------------------
                0.00    0.00   56256/1426824     extend_heap [18]
                0.00    0.01  660396/1426824     place [13]
                0.00    0.01  710172/1426824     mm_free [11]
[9]      2.0    0.00    0.03 1426824         coalesce [9]
                0.02    0.00 1426824/1426824     sgrgt_list_insrt [10]
                0.00    0.00  716520/1426692     sgrgt_list_remov [17]
-----------------------------------------------
                0.02    0.00 1426824/1426824     coalesce [9]
[10]     1.9    0.02    0.00 1426824         sgrgt_list_insrt [10]
                0.00    0.00 1426824/3563688     sgrgt_list_idx [15]
-----------------------------------------------
                0.00    0.00   51387/710172      eval_mm_util [12]
                0.00    0.00   51387/710172      eval_mm_valid [2]
                0.00    0.00   93528/710172      mm_realloc [16]
                0.01    0.01  513870/710172      eval_mm_speed [5]
[11]     1.8    0.01    0.01  710172         mm_free [11]
                0.00    0.01  710172/1426824     coalesce [9]
-----------------------------------------------
                0.01    0.00      11/11          main [1]
[12]     1.1    0.01    0.00      11         eval_mm_util [12]
                0.00    0.00   51387/710172      mm_malloc [8]
                0.00    0.00   51387/710172      mm_free [11]
                0.00    0.00    9598/115176      mm_realloc [16]
                0.00    0.00      11/132         mm_init [19]
                0.00    0.00      11/132         mem_reset_brk [23]
                0.00    0.00      11/11          mem_heapsize [27]
-----------------------------------------------
                0.00    0.01  710172/710172      mm_malloc [8]
[13]     1.1    0.00    0.01  710172         place [13]
                0.00    0.01  660396/1426824     coalesce [9]
                0.00    0.00  710172/1426692     sgrgt_list_remov [17]
-----------------------------------------------
                0.01    0.00  710172/710172      mm_malloc [8]
[14]     0.9    0.01    0.00  710172         find_fit [14]
                0.00    0.00  710172/3563688     sgrgt_list_idx [15]
-----------------------------------------------
                0.00    0.00  710172/3563688     find_fit [14]
                0.00    0.00 1426692/3563688     sgrgt_list_remov [17]
                0.00    0.00 1426824/3563688     sgrgt_list_insrt [10]
[15]     0.8    0.01    0.00 3563688         sgrgt_list_idx [15]
-----------------------------------------------
                0.00    0.00    9598/115176      eval_mm_util [12]
                0.00    0.00    9598/115176      eval_mm_valid [2]
                0.00    0.01   95980/115176      eval_mm_speed [5]
[16]     0.5    0.00    0.01  115176         mm_realloc [16]
                0.00    0.00   93528/710172      mm_malloc [8]
                0.00    0.00   93528/710172      mm_free [11]
-----------------------------------------------
                0.00    0.00  710172/1426692     place [13]
                0.00    0.00  716520/1426692     coalesce [9]
[17]     0.3    0.00    0.00 1426692         sgrgt_list_remov [17]
                0.00    0.00 1426692/3563688     sgrgt_list_idx [15]
-----------------------------------------------
                0.00    0.00     132/56256       mm_init [19]
                0.00    0.00   56124/56256       mm_malloc [8]
[18]     0.1    0.00    0.00   56256         extend_heap [18]
                0.00    0.00   56256/1426824     coalesce [9]
                0.00    0.00   56256/56388       mem_sbrk [22]
-----------------------------------------------
                0.00    0.00      11/132         eval_mm_util [12]
                0.00    0.00      11/132         eval_mm_valid [2]
                0.00    0.00     110/132         eval_mm_speed [5]
[19]     0.0    0.00    0.00     132         mm_init [19]
                0.00    0.00     132/56256       extend_heap [18]
                0.00    0.00     132/56388       mem_sbrk [22]
                0.00    0.00     132/132         sgrgt_list_init [24]
-----------------------------------------------
                0.00    0.00  121970/121970      add_range [3]
[20]     0.0    0.00    0.00  121970         mem_heap_hi [20]
-----------------------------------------------
                0.00    0.00  121970/121970      add_range [3]
[21]     0.0    0.00    0.00  121970         mem_heap_lo [21]
-----------------------------------------------
                0.00    0.00     132/56388       mm_init [19]
                0.00    0.00   56256/56388       extend_heap [18]
[22]     0.0    0.00    0.00   56388         mem_sbrk [22]
-----------------------------------------------
                0.00    0.00      11/132         eval_mm_util [12]
                0.00    0.00      11/132         eval_mm_valid [2]
                0.00    0.00     110/132         eval_mm_speed [5]
[23]     0.0    0.00    0.00     132         mem_reset_brk [23]
-----------------------------------------------
                0.00    0.00     132/132         mm_init [19]
[24]     0.0    0.00    0.00     132         sgrgt_list_init [24]
-----------------------------------------------
                0.00    0.00      11/11          eval_mm_valid [2]
[25]     0.0    0.00    0.00      11         clear_ranges [25]
-----------------------------------------------
                0.00    0.00      11/11          main [1]
[26]     0.0    0.00    0.00      11         free_trace [26]
-----------------------------------------------
                0.00    0.00      11/11          eval_mm_util [12]
[27]     0.0    0.00    0.00      11         mem_heapsize [27]
-----------------------------------------------
                0.00    0.00      11/11          main [1]
[28]     0.0    0.00    0.00      11         read_trace [28]
-----------------------------------------------
                0.00    0.00       1/1           main [1]
[29]     0.0    0.00    0.00       1         init_fsecs [29]
-----------------------------------------------
                0.00    0.00       1/1           main [1]
[30]     0.0    0.00    0.00       1         mem_init [30]
-----------------------------------------------
                0.00    0.00       1/1           main [1]
[31]     0.0    0.00    0.00       1         printresults [31]
-----------------------------------------------

 This table describes the call tree of the program, and was sorted by
 the total amount of time spent in each function and its children.

 Each entry in this table consists of several lines.  The line with the
 index number at the left hand margin lists the current function.
 The lines above it list the functions that called this function,
 and the lines below it list the functions this one called.
 This line lists:
     index	A unique number given to each element of the table.
		Index numbers are sorted numerically.
		The index number is printed next to every function name so
		it is easier to look up where the function is in the table.

     % time	This is the percentage of the `total' time that was spent
		in this function and its children.  Note that due to
		different viewpoints, functions excluded by options, etc,
		these numbers will NOT add up to 100%.

     self	This is the total amount of time spent in this function.

     children	This is the total amount of time propagated into this
		function by its children.

     called	This is the number of times the function was called.
		If the function called itself recursively, the number
		only includes non-recursive calls, and is followed by
		a `+' and the number of recursive calls.

     name	The name of the current function.  The index number is
		printed after it.  If the function is a member of a
		cycle, the cycle number is printed between the
		function's name and the index number.


 For the function's parents, the fields have the following meanings:

     self	This is the amount of time that was propagated directly
		from the function into this parent.

     children	This is the amount of time that was propagated from
		the function's children into this parent.

     called	This is the number of times this parent called the
		function `/' the total number of times the function
		was called.  Recursive calls to the function are not
		included in the number after the `/'.

     name	This is the name of the parent.  The parent's index
		number is printed after it.  If the parent is a
		member of a cycle, the cycle number is printed between
		the name and the index number.

 If the parents of the function cannot be determined, the word
 `<spontaneous>' is printed in the `name' field, and all the other
 fields are blank.

 For the function's children, the fields have the following meanings:

     self	This is the amount of time that was propagated directly
		from the child into the function.

     children	This is the amount of time that was propagated from the
		child's children to the function.

     called	This is the number of times the function called
		this child `/' the total number of times the child
		was called.  Recursive calls by the child are not
		listed in the number after the `/'.

     name	This is the name of the child.  The child's index
		number is printed after it.  If the child is a
		member of a cycle, the cycle number is printed
		between the name and the index number.

 If there are any cycles (circles) in the call graph, there is an
 entry for the cycle-as-a-whole.  This entry shows who called the
 cycle (as parents) and the members of the cycle (as children.)
 The `+' recursive calls entry shows the number of function calls that
 were internal to the cycle, and the calls entry for each member shows,
 for that member, how many times it was called from other members of
 the cycle.

Copyright (C) 2012-2020 Free Software Foundation, Inc.

Copying and distribution of this file, with or without modification,
are permitted in any medium without royalty provided the copyright
notice and this notice are preserved.

Index by function name

   [3] add_range (mdriver.c)   [7] ftimer_gettod           [8] mm_malloc
  [25] clear_ranges (mdriver.c) [29] init_fsecs           [16] mm_realloc
   [9] coalesce (mm.c)        [20] mem_heap_hi            [13] place (mm.c)
   [5] eval_mm_speed (mdriver.c) [21] mem_heap_lo         [31] printresults (mdriver.c)
  [12] eval_mm_util (mdriver.c) [27] mem_heapsize         [28] read_trace (mdriver.c)
   [2] eval_mm_valid (mdriver.c) [30] mem_init             [4] remove_range (mdriver.c)
  [18] extend_heap (mm.c)     [23] mem_reset_brk          [15] sgrgt_list_idx (mm.c)
  [14] find_fit (mm.c)        [22] mem_sbrk               [24] sgrgt_list_init (mm.c)
  [26] free_trace (mdriver.c) [11] mm_free                [10] sgrgt_list_insrt (mm.c)
   [6] fsecs                  [19] mm_init                [17] sgrgt_list_remov (mm.c)
```

## Summary

Malloclab is inevitably the hardest lab among all labs in CSAPP. But I learned a lot from it (though my code is still a piece of shit). The next step will be to take look at what real libc ptmalloc is doing by studying its source code. Then we could head to the last lab - proxylab. 

## References

Source code from the book

https://zhuanlan.zhihu.com/p/150100073

https://littlecsd.net/2019/02/14/csapp-Malloclab/