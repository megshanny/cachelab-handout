#include "cachelab.h"
#include <stdbool.h> //bool
#include <unistd.h>
#include <getopt.h> //getopt, optarg
#include <stdlib.h> //atoi
#include <stdio.h>  //FILE
#include <math.h>   //pow
#include <errno.h>  // __errno_location
#include <string.h> //strerror

static int s = 0, E = 0, b = 0;
static bool verbosity = 0;
static int S;

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
}

void accessData(long long addr)
{
    long long tag;
    int set_index_mask = S - 1;

    unsigned int eviction_line = 0;
    unsigned int eviction_lru = -1U;

    tag = addr >> ((unsigned)s + (unsigned)b);
    cache_set_t *cache_set = cache[(addr >> b) & set_index_mask].data;

    int i;
    for (i = 0; i < E; ++i)
    {
        if (cache_set[i].tag == tag && cache_set[i].valid)
        {
            break;
        }
    }

    if (i >= E)
    {
        ++miss_count;
        if (verbosity)
        {
            printf("miss ");
        }

        for (int j = 0; j < E; ++j)
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
        cache_set[eviction_line].lru = lru_counter++;

        return;
    }

    ++hit_count;
    if (verbosity)
    {
        printf("hit ");
    }

    cache_set[i].lru = lru_counter++;
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
    char c;
    char *trace_file;

    while (1)
    {
        c = getopt(argc, (char *const *)argv, "s:E:b:t:vh");
        if (c == -1)
        {
            break;
        }
        switch (c)
        {
        case 'E':
            E = atoi(optarg);
            break;
        case 'b':
            b = atoi(optarg);
            break;
        case 's':
            s = atoi(optarg);
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
    if (!s || !E || !b || !trace_file)
    {
        printf("%s: Missing required command line argument\n", *argv);
        printUsage((char **)argv);
    }
    S = (int)pow(2.0, (double)s);

    initCache();
    replayTrace(trace_file);
    freeCache();
    printSummary(hit_count, miss_count, eviction_count);
    return 0;
}
