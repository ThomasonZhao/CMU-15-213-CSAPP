/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 *
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "CSAPP",
    /* First member's full name */
    "Thomason Zhao",
    /* First member's email address */
    "thomasonzhao@outlook.com",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""};

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~0x7)

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

/*
 * If NEXT_FIT defined use next fit search, else use first-fit search
 */
#define NEXT_FITx

/*
 * If SGRGT_LIST defined use segregate free list implementation, else use
 * implicit free list implementation
 */
#define SGRGT_LIST

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
#define HDRP(bp) ((char *)(bp)-WSIZE)
#define FTRP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)

/* Given block ptr bp, compute address of next and previous blocks */
#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE(((char *)(bp)-WSIZE)))
#define PREV_BLKP(bp) ((char *)(bp)-GET_SIZE(((char *)(bp)-DSIZE)))

#ifdef SGRGT_LIST

/* Given free block ptr fbp, read and write prev and next ptr */
#define GET_PREV(fbp) (GET(fbp))
#define SET_PREV(fbp, prev) (PUT((fbp), (prev)))
#define GET_NEXT(fbp) (GET((char *)(fbp) + WSIZE))
#define SET_NEXT(fbp, next) (PUT((char *)(fbp) + WSIZE, (next)))
// #define GET_PREV(p) (*(unsigned int *)(p))
// #define SET_PREV(p, prev) (*(unsigned int *)(p) = (prev))
// #define GET_NEXT(p) (*((unsigned int *)(p)+1))
// #define SET_NEXT(p, val) (*((unsigned int *)(p)+1) = (val))
#endif

/* Global variables */
static char *heap_listp; /* Pointer to first block */

#ifdef NEXT_FIT
static char *rover; /* Next fit rover */
#endif

#ifdef SGRGT_LIST
static unsigned int *sgrgt_listp; /* Pointer to free list*/
#endif

/* Function prototypes for internal helper routines */
static void *extend_heap(size_t words);
static void place(void *bp, size_t asize);
static void *find_fit(size_t asize);
static void *coalesce(void *bp);
static void checkheap(int verbose);
static void printblock(void *bp);
static void checkblock(void *bp);

#ifdef SGRGT_LIST
static void sgrgt_list_init(void);
static size_t sgrgt_list_idx(size_t size);
static void sgrgt_list_insrt(void *bp);
static void sgrgt_list_remov(void *bp);
#endif

/*
 * mm_init - Initialize the malloc package.
 */
int mm_init(void)
{
    size_t init_brk_size = 4 * WSIZE;

#ifdef SGRGT_LIST
    init_brk_size = 14 * WSIZE;
#endif

    /* Create the initial empty heap */
    if ((heap_listp = mem_sbrk(init_brk_size)) == (void *)-1)
        return -1;

#ifdef SGRGT_LIST
    sgrgt_list_init();
#endif

    PUT(heap_listp, 0);                            /* Alignment padding */
    PUT(heap_listp + (1 * WSIZE), PACK(DSIZE, 1)); /* Prologue header */
    PUT(heap_listp + (2 * WSIZE), PACK(DSIZE, 1)); /* Prologue footer */
    PUT(heap_listp + (3 * WSIZE), PACK(0, 1));     /* Epilogue header */
    heap_listp += (2 * WSIZE);

#ifdef NEXT_FIT
    rover = heap_listp;
#endif

    /* Extend the empty heap with a free block of CHUNKSIZE bytes */
    if (extend_heap(CHUNKSIZE / WSIZE) == NULL)
        return -1;
    return 0;
}

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

#ifdef SGRGT_LIST
    SET_PREV(bp, NULL);
    SET_NEXT(bp, NULL);
#endif

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

/*
 * The remaining routines are internal helper routines
 */

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

#ifdef SGRGT_LIST
    SET_PREV(bp, 0);
    SET_NEXT(bp, 0);
#endif

    /* Coalesce if the previous block was free */
    return coalesce(bp);
}

/*
 * place - Place block of asize bytes at start of free block bp
 *         and split if remainder would be at least minimum block size
 */
static void place(void *bp, size_t asize)
{
    size_t csize = GET_SIZE(HDRP(bp));

#ifdef SGRGT_LIST
    sgrgt_list_remov(bp);
#endif

    if ((csize - asize) >= (2 * DSIZE))
    { /* Split large free block */
        PUT(HDRP(bp), PACK(asize, 1));
        PUT(FTRP(bp), PACK(asize, 1));
        bp = NEXT_BLKP(bp);
        PUT(HDRP(bp), PACK(csize - asize, 0));
        PUT(FTRP(bp), PACK(csize - asize, 0));

#ifdef SGRGT_LIST
        SET_PREV(bp, 0);
        SET_NEXT(bp, 0);
#endif

        coalesce(bp);
    }
    else
    { /* Do not split */
        PUT(HDRP(bp), PACK(csize, 1));
        PUT(FTRP(bp), PACK(csize, 1));
    }
}

/*
 * find_fit - Find a fit for a block with asize bytes
 */
static void *find_fit(size_t asize)
{
#ifdef SGRGT_LIST
    /* Segregate list implementation */
    void *root;

    for (root = sgrgt_listp + sgrgt_list_idx(asize); root != (heap_listp - WSIZE); root += WSIZE)
    {
        void *bp = GET(root);
        while (bp)
        {
            if (GET_SIZE(HDRP(bp)) >= asize)
                return bp;
            bp = GET_NEXT(bp);
        }
    }

    return NULL;
#endif

#ifdef NEXT_FIT
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
#else
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
#endif
}

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

#ifdef SGRGT_LIST
        sgrgt_list_remov(NEXT_BLKP(bp));
#endif

        size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
        PUT(HDRP(bp), PACK(size, 0));
        PUT(FTRP(bp), PACK(size, 0));
    }

    else if (!prev_alloc && next_alloc)
    { /* Case 3 */

#ifdef SGRGT_LIST
        sgrgt_list_remov(PREV_BLKP(bp));
#endif

        size += GET_SIZE(HDRP(PREV_BLKP(bp)));
        PUT(FTRP(bp), PACK(size, 0));
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
        bp = PREV_BLKP(bp);
    }

    else
    { /* Case 4 */

#ifdef SGRGT_LIST
        sgrgt_list_remov(PREV_BLKP(bp));
        sgrgt_list_remov(NEXT_BLKP(bp));
#endif

        size += GET_SIZE(HDRP(PREV_BLKP(bp))) +
                GET_SIZE(FTRP(NEXT_BLKP(bp)));
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
        PUT(FTRP(NEXT_BLKP(bp)), PACK(size, 0));
        bp = PREV_BLKP(bp);
    }

#ifdef NEXT_FIT
    /* Make sure the rover isn't pointing into the free block */
    /* that we just coalesced */
    if ((rover > (char *)bp) && (rover < NEXT_BLKP(bp)))
        rover = bp;
#endif

#ifdef SGRGT_LIST
    sgrgt_list_insrt(bp);
#endif

    return bp;
}

/*
 * checkheap - Minimal check of the heap for consistency
 */
void checkheap(int verbose)
{
    char *bp = heap_listp;

    if (verbose)
        printf("Heap (%p):\n", heap_listp);

    if ((GET_SIZE(HDRP(heap_listp)) != DSIZE) || !GET_ALLOC(HDRP(heap_listp)))
        printf("Bad prologue header\n");
    checkblock(heap_listp);

    for (bp = heap_listp; GET_SIZE(HDRP(bp)) > 0; bp = NEXT_BLKP(bp))
    {
        if (verbose)
            printblock(bp);
        checkblock(bp);
    }

    if (verbose)
        printblock(bp);
    if ((GET_SIZE(HDRP(bp)) != 0) || !(GET_ALLOC(HDRP(bp))))
        printf("Bad epilogue header\n");
}

static void printblock(void *bp)
{
    size_t hsize, halloc, fsize, falloc;

    checkheap(0);
    hsize = GET_SIZE(HDRP(bp));
    halloc = GET_ALLOC(HDRP(bp));
    fsize = GET_SIZE(FTRP(bp));
    falloc = GET_ALLOC(FTRP(bp));

    if (hsize == 0)
    {
        printf("%p: EOL\n", bp);
        return;
    }

    printf("%p: header: [%d:%c] footer: [%d:%c]\n", bp,
           hsize, (halloc ? 'a' : 'f'),
           fsize, (falloc ? 'a' : 'f'));
}

static void checkblock(void *bp)
{
    if ((size_t)bp % 8)
        printf("Error: %p is not doubleword aligned\n", bp);
    if (GET(HDRP(bp)) != GET(FTRP(bp)))
        printf("Error: header does not match footer\n");
}

#ifdef SGRGT_LIST
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

static size_t sgrgt_list_idx(size_t size)
{
    int i;

    if (size <= 16)
        i = 0;
    else if (size <= 32)
        i = 1;
    else if (size <= 64)
        i = 2;
    else if (size <= 128)
        i = 3;
    else if (size <= 256)
        i = 4;
    else if (size <= 512)
        i = 5;
    else if (size <= 1024)
        i = 6;
    else if (size <= 2048)
        i = 7;
    else if (size <= 4096)
        i = 8;
    else
        i = 9;

    return i;
}

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
#endif
