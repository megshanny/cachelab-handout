#include "cachelab.h"
#include <stdbool.h> //bool
#include <unistd.h>
#include <getopt.h> //getopt, optarg
#include <stdlib.h> //atoi
#include <stdio.h>  //FILE
#include <math.h> //pow
#include <errno.h> // __errno_location
#include <string.h> //strerror 
static int s = 0, E = 0, b = 0;
static bool verbosity = 0;
static int S, B;
static int set_index_mask;

int miss_count = 0;
int hit_count = 0;
int eviction_count = 0;
unsigned int lru_counter = 0;
typedef struct cache_set_t
{
    long long valid;
    long long tag;
    long long lru;
} cache_set_t;

typedef struct cache_t
{
    cache_set_t *data;
} cache_t;

cache_t *cache;

void initCache()
{
    cache = (cache_t *)malloc(8LL * S);
    for (int i = 0; i < S; i++)
    {
        cache[i].data = (cache_set_t *)malloc(24LL * E);
        for (int j = 0; j < E; j++)
        {
            cache[i].data[j].valid = 0;
            cache[i].data[j].tag = 0LL;
            cache[i].data[j].lru = 0LL;
        }
    }
    double v1 = pow(2.0, (double)s) - 1.0;
    set_index_mask = (unsigned int)v1;
}

void accessData(long long addr)
{
    long long tag;
    
    // int lru_counter = 0;
    // miss_count = 0;
    // hit_count = 0;
    // eviction_count = 0;
    unsigned int eviction_line = 0;
    unsigned int eviction_lru = -1LL;

    tag = addr >> ((unsigned)s + (unsigned)b);
    cache_set_t *cache_set = cache[(addr >> b) & set_index_mask].data;
    int i;
    for (i = 0;; i++)
    {
        if (i >= E)
        {
            ++miss_count;
            if (verbosity)
            {
                printf("miss ");
            }
            for (int j = 0; j < E; j++)
            {
                if (cache_set[j].lru < eviction_lru)
                {
                    eviction_line = j;
                    eviction_lru = cache_set[j].lru;
                }
            }
            if (cache_set[eviction_line].valid)
            {
                ++eviction_count;
                if (verbosity)
                {
                    printf("eviction ");
                }
            }
            cache_set[eviction_line].valid = 1;
            cache_set[eviction_line].tag = tag;
            unsigned int v2 = lru_counter++;
            cache_set[eviction_line].lru = v2;

            return;
        }
        if (cache_set[i].tag == tag && cache_set[i].valid)
        {
            break;
        }
    }
    ++hit_count;
    if (verbosity)
    {
        printf("hit ");
    }
    unsigned int v1 = lru_counter++;
    cache_set[i].lru = v1;
}

void replayTrace(char *trace_fn)
{
    int *v1;
    char *v2;
    char buf[1000];
    unsigned int len;
    long long addr; //?
    FILE *trace_fp = fopen(trace_fn, "r");
    if (!trace_fp)
    {
        v1 = __errno_location();
        v2 = strerror(*v1);
        fprintf(stderr, "%s: %s\n", trace_fn, v2);
        exit(1);
    }
    // ??
    while (fgets(buf, 1000, trace_fp))
    {
        if (buf[1] == 'S' || buf[1] == 'L' || buf[1] == 'M')
        {
            sscanf(&buf[3], "%llx,%u", &addr, &len);
            if (verbosity)
            {
                printf("%c %llx,%u ", (unsigned int)buf[1], addr, len);
            }
            accessData(addr);
            if (buf[1] == 'M') // M访问两次
            {
                accessData(addr);
            }
            if (verbosity)
            {
                putchar('\n');
            }
            
        }
    }
    fclose(trace_fp);
}
void printUsage(char **argv)
{
    printf("Usage: %s [-hv] -s <num> -E <num> -b <num> -t <file>\n", *argv);
    puts("Options:");
    puts("  -h         Print this help message.");
    puts("  -v         Optional verbose flag.");
    puts("  -s <num>   Number of set index bits.");
    puts("  -E <num>   Number of lines per set.");
    puts("  -b <num>   Number of block offset bits.");
    puts("  -t <file>  Trace file.");
    puts("\nExamples:");
    printf("  linux>  %s -s 4 -E 1 -b 4 -t traces/yi.trace\n", *argv);
    printf("  linux>  %s -v -s 8 -E 2 -b 4 -t traces/yi.trace\n", *argv);
    exit(0);
}
void freeCache()
{
    for (int i = 0; i < S; i++)
    {
        free(cache[i].data);
    }
    free(cache);
}
int main(int argc, const char **argv)
{
    // printf("--------(-1)-------");
    char c;
    char *trace_file;
    
    while (1)
    {
        c = getopt(argc, (char *const *)argv, "s:E:b:t:vh");
        // printf("--------c-------");
        if (c == -1)
        {
            break;
        }
        switch (c)
        {
        case 'E':
            E = atoi(optarg);
            //  printf("E = %d",E);
            break;
        case 'b':
            b = atoi(optarg);
            //  printf("b = %d",b);
            break;
        case 's':
            s = atoi(optarg);
            // printf("s = %d",s);
            break;
        case 'h':
            printUsage((char **)argv);
            break;
        case 't':
            trace_file = optarg;
            break;
        case 'v':
            verbosity = 1;
            break;
        default:
            printUsage((char **)argv);
            break;
        }
    }
    // printf("---------0----------");
    if (!s || !E || !b || !trace_file)
    {
        printf("%s: Missing required command line argument\n", *argv);
        printUsage((char **)argv);
    }
    S = (int)pow(2.0, (double)s);
    B = (int)pow(2.0, (double)b);
    // printf("-----------1--------------");
    
    initCache();
    // printf("-----------2--------------");
    
    replayTrace(trace_file);
    // printf("-----------3--------------");
    freeCache();
    printSummary(hit_count, miss_count, eviction_count);
    return 0;
}
