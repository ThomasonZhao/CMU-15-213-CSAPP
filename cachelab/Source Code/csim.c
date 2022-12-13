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
