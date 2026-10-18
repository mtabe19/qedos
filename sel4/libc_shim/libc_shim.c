/*
 * Freestanding libc + entropy + deterministic coalescing heap shim
 * for OpenSSL 3.6.1 in an x86_64 seL4/Microkit Protection Domain.
 */
#include "libc_shim.h"

#define WEAK __attribute__((weak))

/* =========================================================================
 * 1. Deterministic Coalescing Heap Allocator (16 MiB BSS Pool)
 * =========================================================================
 * Doubly-linked physical block list with immediate forward & backward
 * free-block coalescing and block splitting so repeated SSL_new/SSL_free
 * cycles never fragment or leak the static pool.
 */
#define HEAP_POOL_SIZE (16u * 1024u * 1024u)
#define ALIGN16(x)     (((x) + 15ULL) & ~15ULL)

typedef struct heap_block {
    size_t size;              /* Payload size in bytes (multiple of 16) */
    struct heap_block *prev;  /* Physically adjacent previous block */
    struct heap_block *next;  /* Physically adjacent next block */
    uint32_t is_free;
    uint32_t magic;
} __attribute__((aligned(16))) heap_block_t;

#define HEAP_MAGIC_USED 0xA110CA7Eu
#define HEAP_MAGIC_FREE 0xF4EEB10Cu
#define MIN_SPLIT_SIZE  32u

static uint8_t heap_pool[HEAP_POOL_SIZE] __attribute__((aligned(64)));
static heap_block_t *heap_head = NULL;
static size_t heap_bytes_used = 0;

static void heap_ensure_init(void)
{
    if (heap_head == NULL) {
        heap_head = (heap_block_t *)heap_pool;
        heap_head->size = HEAP_POOL_SIZE - sizeof(heap_block_t);
        heap_head->prev = NULL;
        heap_head->next = NULL;
        heap_head->is_free = 1;
        heap_head->magic = HEAP_MAGIC_FREE;
        heap_bytes_used = 0;
    }
}

void libc_shim_heap_reset(void)
{
    heap_head = NULL;
    heap_ensure_init();
}

size_t libc_shim_heap_bytes_in_use(void)
{
    heap_ensure_init();
    return heap_bytes_used;
}

size_t libc_shim_heap_capacity(void)
{
    return HEAP_POOL_SIZE - sizeof(heap_block_t);
}

static void heap_split_block(heap_block_t *blk, size_t req_size)
{
    if (blk->size >= req_size + sizeof(heap_block_t) + MIN_SPLIT_SIZE) {
        uint8_t *split_addr = (uint8_t *)(blk + 1) + req_size;
        heap_block_t *rem = (heap_block_t *)split_addr;
        rem->size = blk->size - req_size - sizeof(heap_block_t);
        rem->prev = blk;
        rem->next = blk->next;
        rem->is_free = 1;
        rem->magic = HEAP_MAGIC_FREE;
        if (blk->next != NULL) {
            blk->next->prev = rem;
        }
        blk->next = rem;
        blk->size = req_size;
    }
}

static heap_block_t *heap_coalesce(heap_block_t *blk)
{
    /* Coalesce with next physical block if free */
    if (blk->next != NULL && blk->next->is_free) {
        heap_block_t *nxt = blk->next;
        blk->size += sizeof(heap_block_t) + nxt->size;
        blk->next = nxt->next;
        if (blk->next != NULL) {
            blk->next->prev = blk;
        }
    }
    /* Coalesce with previous physical block if free */
    if (blk->prev != NULL && blk->prev->is_free) {
        heap_block_t *prv = blk->prev;
        prv->size += sizeof(heap_block_t) + blk->size;
        prv->next = blk->next;
        if (prv->next != NULL) {
            prv->next->prev = prv;
        }
        blk = prv;
    }
    return blk;
}

WEAK void *malloc(size_t size)
{
    heap_ensure_init();
    if (size == 0) {
        size = 16;
    }
    size_t req = ALIGN16(size);
    if (req < size) {
        return NULL; /* overflow */
    }

    for (heap_block_t *cur = heap_head; cur != NULL; cur = cur->next) {
        if (cur->is_free && cur->size >= req) {
            heap_split_block(cur, req);
            cur->is_free = 0;
            cur->magic = HEAP_MAGIC_USED;
            heap_bytes_used += cur->size;
            return (void *)(cur + 1);
        }
    }
    return NULL;
}

WEAK void free(void *ptr)
{
    if (ptr == NULL) {
        return;
    }
    uintptr_t addr = (uintptr_t)ptr;
    uintptr_t pool_start = (uintptr_t)heap_pool + sizeof(heap_block_t);
    uintptr_t pool_end = (uintptr_t)heap_pool + HEAP_POOL_SIZE;
    if (addr < pool_start || addr >= pool_end) {
        return;
    }
    heap_block_t *blk = ((heap_block_t *)ptr) - 1;
    if (blk->magic != HEAP_MAGIC_USED || blk->is_free) {
        return;
    }
    if (heap_bytes_used >= blk->size) {
        heap_bytes_used -= blk->size;
    } else {
        heap_bytes_used = 0;
    }
    blk->is_free = 1;
    blk->magic = HEAP_MAGIC_FREE;
    (void)heap_coalesce(blk);
}

WEAK void *memset(void *s, int c, size_t n);
WEAK void *memcpy(void *dest, const void *src, size_t n);

WEAK void *calloc(size_t nmemb, size_t size)
{
    if (nmemb != 0 && size > ((size_t)-1) / nmemb) {
        return NULL;
    }
    size_t total = nmemb * size;
    if (total == 0) {
        total = 16;
    }
    void *p = malloc(total);
    if (p != NULL) {
        memset(p, 0, total);
    }
    return p;
}

WEAK void *realloc(void *ptr, size_t size)
{
    if (ptr == NULL) {
        return malloc(size);
    }
    if (size == 0) {
        free(ptr);
        return NULL;
    }
    heap_block_t *blk = ((heap_block_t *)ptr) - 1;
    if (blk->magic != HEAP_MAGIC_USED) {
        return NULL;
    }
    size_t req = ALIGN16(size);
    if (req <= blk->size) {
        return ptr;
    }
    /* Try in-place expansion with next free block */
    if (blk->next != NULL && blk->next->is_free &&
        (blk->size + sizeof(heap_block_t) + blk->next->size) >= req) {
        size_t old_size = blk->size;
        heap_block_t *nxt = blk->next;
        blk->size += sizeof(heap_block_t) + nxt->size;
        blk->next = nxt->next;
        if (blk->next != NULL) {
            blk->next->prev = blk;
        }
        heap_split_block(blk, req);
        heap_bytes_used += (blk->size - old_size);
        return ptr;
    }

    void *new_ptr = malloc(req);
    if (new_ptr == NULL) {
        return NULL;
    }
    memcpy(new_ptr, ptr, blk->size);
    free(ptr);
    return new_ptr;
}

WEAK int posix_memalign(void **memptr, size_t alignment, size_t size)
{
    if (memptr == NULL || alignment == 0 || (alignment & (alignment - 1)) != 0 ||
        (alignment % sizeof(void *)) != 0) {
        return 22; /* EINVAL */
    }
    if (alignment <= 16) {
        void *p = malloc(size);
        if (p == NULL) {
            return 12; /* ENOMEM */
        }
        *memptr = p;
        return 0;
    }
    heap_ensure_init();
    size_t req = ALIGN16(size == 0 ? 16 : size);
    for (heap_block_t *cur = heap_head; cur != NULL; cur = cur->next) {
        if (!cur->is_free || cur->size < req) {
            continue;
        }
        uintptr_t payload_addr = (uintptr_t)(cur + 1);
        uintptr_t aligned_addr = (payload_addr + (alignment - 1)) & ~(uintptr_t)(alignment - 1);
        size_t prefix = (size_t)(aligned_addr - payload_addr);
        if (prefix != 0 && prefix < sizeof(heap_block_t) + MIN_SPLIT_SIZE) {
            /* Advance aligned_addr by multiples of alignment until prefix fits a free block */
            size_t min_prefix = sizeof(heap_block_t) + MIN_SPLIT_SIZE;
            size_t extra = ((min_prefix - prefix + alignment - 1) / alignment) * alignment;
            aligned_addr += extra;
            prefix = (size_t)(aligned_addr - payload_addr);
        }
        if (cur->size < prefix + req) {
            continue;
        }
        if (prefix > 0) {
            size_t front_payload = prefix - sizeof(heap_block_t);
            heap_split_block(cur, front_payload);
            cur = cur->next;
        }
        heap_split_block(cur, req);
        cur->is_free = 0;
        cur->magic = HEAP_MAGIC_USED;
        heap_bytes_used += cur->size;
        *memptr = (void *)(cur + 1);
        return 0;
    }
    return 12; /* ENOMEM */
}

/* =========================================================================
 * 2. Memory & String Primitives (WEAK to coexist with libsddf_util.a)
 * ========================================================================= */
WEAK void *memcpy(void *dest, const void *src, size_t n)
{
    uint8_t *d = (uint8_t *)dest;
    const uint8_t *s = (const uint8_t *)src;
    for (size_t i = 0; i < n; i++) {
        d[i] = s[i];
    }
    return dest;
}

WEAK void *memmove(void *dest, const void *src, size_t n)
{
    uint8_t *d = (uint8_t *)dest;
    const uint8_t *s = (const uint8_t *)src;
    if (d < s || d >= s + n) {
        for (size_t i = 0; i < n; i++) {
            d[i] = s[i];
        }
    } else if (d > s) {
        for (size_t i = n; i > 0; i--) {
            d[i - 1] = s[i - 1];
        }
    }
    return dest;
}

WEAK void *memset(void *s, int c, size_t n)
{
    uint8_t *p = (uint8_t *)s;
    uint8_t v = (uint8_t)c;
    for (size_t i = 0; i < n; i++) {
        p[i] = v;
    }
    return s;
}

WEAK int memcmp(const void *s1, const void *s2, size_t n)
{
    const uint8_t *a = (const uint8_t *)s1;
    const uint8_t *b = (const uint8_t *)s2;
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            return (int)a[i] - (int)b[i];
        }
    }
    return 0;
}

WEAK void *memchr(const void *s, int c, size_t n)
{
    const uint8_t *p = (const uint8_t *)s;
    uint8_t target = (uint8_t)c;
    for (size_t i = 0; i < n; i++) {
        if (p[i] == target) {
            return (void *)(p + i);
        }
    }
    return NULL;
}

WEAK size_t strlen(const char *s)
{
    size_t len = 0;
    while (s[len] != '\0') {
        len++;
    }
    return len;
}

WEAK int strcmp(const char *s1, const char *s2)
{
    while (*s1 != '\0' && *s1 == *s2) {
        s1++;
        s2++;
    }
    return (int)(unsigned char)*s1 - (int)(unsigned char)*s2;
}

WEAK int strncmp(const char *s1, const char *s2, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned char c1 = (unsigned char)s1[i];
        unsigned char c2 = (unsigned char)s2[i];
        if (c1 != c2 || c1 == '\0') {
            return (int)c1 - (int)c2;
        }
    }
    return 0;
}

WEAK char *strcpy(char *dest, const char *src)
{
    char *d = dest;
    while ((*d++ = *src++) != '\0') {
    }
    return dest;
}

WEAK char *strncpy(char *dest, const char *src, size_t n)
{
    size_t i = 0;
    for (; i < n && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }
    for (; i < n; i++) {
        dest[i] = '\0';
    }
    return dest;
}

WEAK char *strcat(char *dest, const char *src)
{
    char *d = dest + strlen(dest);
    while ((*d++ = *src++) != '\0') {
    }
    return dest;
}

WEAK char *strchr(const char *s, int c)
{
    char ch = (char)c;
    while (*s != '\0') {
        if (*s == ch) {
            return (char *)s;
        }
        s++;
    }
    return (ch == '\0') ? (char *)s : NULL;
}

WEAK char *strrchr(const char *s, int c)
{
    const char *last = NULL;
    char ch = (char)c;
    while (*s != '\0') {
        if (*s == ch) {
            last = s;
        }
        s++;
    }
    return (ch == '\0') ? (char *)s : (char *)last;
}

WEAK char *strstr(const char *haystack, const char *needle)
{
    if (*needle == '\0') {
        return (char *)haystack;
    }
    size_t nlen = strlen(needle);
    for (; *haystack != '\0'; haystack++) {
        if (*haystack == *needle && strncmp(haystack, needle, nlen) == 0) {
            return (char *)haystack;
        }
    }
    return NULL;
}

WEAK size_t strspn(const char *s, const char *accept)
{
    size_t count = 0;
    for (; *s != '\0'; s++) {
        if (strchr(accept, *s) == NULL) {
            break;
        }
        count++;
    }
    return count;
}

WEAK size_t strcspn(const char *s, const char *reject)
{
    size_t count = 0;
    for (; *s != '\0'; s++) {
        if (strchr(reject, *s) != NULL) {
            break;
        }
        count++;
    }
    return count;
}

WEAK char *strpbrk(const char *s, const char *accept)
{
    for (; *s != '\0'; s++) {
        if (strchr(accept, *s) != NULL) {
            return (char *)s;
        }
    }
    return NULL;
}

WEAK char *strdup(const char *s)
{
    if (s == NULL) {
        return NULL;
    }
    size_t len = strlen(s) + 1;
    char *copy = (char *)malloc(len);
    if (copy != NULL) {
        memcpy(copy, s, len);
    }
    return copy;
}

/* =========================================================================
 * 3. Ctype & Number Parsing & Sorting Stubs
 * ========================================================================= */
/* glibc <ctype.h> table bits (little-endian host) */
#define C_UPPER  0x0100
#define C_LOWER  0x0200
#define C_ALPHA  0x0400
#define C_DIGIT  0x0800
#define C_XDIGIT 0x1000
#define C_SPACE  0x2000
#define C_PRINT  0x4000
#define C_GRAPH  0x8000
#define C_BLANK  0x0001
#define C_CNTRL  0x0002
#define C_PUNCT  0x0004
#define C_ALNUM  0x0008

static uint16_t ctype_b_table[384];
static int32_t ctype_tolower_table[384];
static int32_t ctype_toupper_table[384];
static const uint16_t *ctype_b_ptr = NULL;
static const int32_t *ctype_tolower_ptr = NULL;
static const int32_t *ctype_toupper_ptr = NULL;

static void ctype_ensure_init(void)
{
    if (ctype_b_ptr != NULL) {
        return;
    }
    for (int i = -128; i < 256; i++) {
        int idx = i + 128;
        uint16_t mask = 0;
        int32_t lo = i;
        int32_t up = i;
        if (i >= 0 && i <= 127) {
            if (i < 32 || i == 127) {
                mask |= C_CNTRL;
            }
            if (i == ' ' || i == '\t') {
                mask |= C_BLANK;
            }
            if (i == ' ' || (i >= '\t' && i <= '\r')) {
                mask |= C_SPACE;
            }
            if (i >= 32 && i < 127) {
                mask |= C_PRINT;
                if (i != ' ') {
                    mask |= C_GRAPH;
                }
            }
            if (i >= 'A' && i <= 'Z') {
                mask |= C_UPPER | C_ALPHA | C_ALNUM;
                lo = i + ('a' - 'A');
            } else if (i >= 'a' && i <= 'z') {
                mask |= C_LOWER | C_ALPHA | C_ALNUM;
                up = i - ('a' - 'A');
            } else if (i >= '0' && i <= '9') {
                mask |= C_DIGIT | C_ALNUM | C_XDIGIT;
            }
            if ((i >= 'A' && i <= 'F') || (i >= 'a' && i <= 'f')) {
                mask |= C_XDIGIT;
            }
            if ((mask & C_GRAPH) && !(mask & C_ALNUM)) {
                mask |= C_PUNCT;
            }
        }
        ctype_b_table[idx] = mask;
        ctype_tolower_table[idx] = lo;
        ctype_toupper_table[idx] = up;
    }
    ctype_b_ptr = &ctype_b_table[128];
    ctype_tolower_ptr = &ctype_tolower_table[128];
    ctype_toupper_ptr = &ctype_toupper_table[128];
}

WEAK const uint16_t **__ctype_b_loc(void)
{
    ctype_ensure_init();
    return &ctype_b_ptr;
}

WEAK const int32_t **__ctype_tolower_loc(void)
{
    ctype_ensure_init();
    return &ctype_tolower_ptr;
}

WEAK const int32_t **__ctype_toupper_loc(void)
{
    ctype_ensure_init();
    return &ctype_toupper_ptr;
}

WEAK int atoi(const char *nptr)
{
    while (*nptr == ' ' || (*nptr >= '\t' && *nptr <= '\r')) {
        nptr++;
    }
    int sign = 1;
    if (*nptr == '-') {
        sign = -1;
        nptr++;
    } else if (*nptr == '+') {
        nptr++;
    }
    int val = 0;
    while (*nptr >= '0' && *nptr <= '9') {
        val = val * 10 + (*nptr - '0');
        nptr++;
    }
    return sign * val;
}

WEAK unsigned long strtoul(const char *nptr, char **endptr, int base)
{
    const char *s = nptr;
    while (*s == ' ' || (*s >= '\t' && *s <= '\r')) {
        s++;
    }
    int neg = 0;
    if (*s == '-') {
        neg = 1;
        s++;
    } else if (*s == '+') {
        s++;
    }
    if ((base == 0 || base == 16) && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
        base = 16;
    } else if (base == 0) {
        base = (s[0] == '0') ? 8 : 10;
    }
    unsigned long acc = 0;
    int any = 0;
    for (; *s != '\0'; s++) {
        int digit;
        if (*s >= '0' && *s <= '9') {
            digit = *s - '0';
        } else if (*s >= 'a' && *s <= 'z') {
            digit = *s - 'a' + 10;
        } else if (*s >= 'A' && *s <= 'Z') {
            digit = *s - 'A' + 10;
        } else {
            break;
        }
        if (digit >= base) {
            break;
        }
        any = 1;
        acc = acc * (unsigned long)base + (unsigned long)digit;
    }
    if (endptr != NULL) {
        *endptr = (char *)(any ? s : nptr);
    }
    return neg ? (0UL - acc) : acc;
}

WEAK long strtol(const char *nptr, char **endptr, int base)
{
    return (long)strtoul(nptr, endptr, base);
}

WEAK long __isoc23_strtol(const char *nptr, char **endptr, int base)
{
    return strtol(nptr, endptr, base);
}

WEAK unsigned long __isoc23_strtoul(const char *nptr, char **endptr, int base)
{
    return strtoul(nptr, endptr, base);
}

WEAK void qsort(void *base, size_t nmemb, size_t size,
                int (*compar)(const void *, const void *))
{
    if (base == NULL || nmemb < 2 || size == 0 || compar == NULL) {
        return;
    }
    uint8_t *arr = (uint8_t *)base;
    /* Shell sort with Knuth gaps: O(n^(3/2)) worst-case, zero recursion/heap */
    size_t gap = 1;
    while (gap < nmemb / 3) {
        gap = gap * 3 + 1;
    }
    while (gap >= 1) {
        for (size_t i = gap; i < nmemb; i++) {
            for (size_t j = i; j >= gap; j -= gap) {
                uint8_t *a = arr + (j - gap) * size;
                uint8_t *b = arr + j * size;
                if (compar(a, b) <= 0) {
                    break;
                }
                for (size_t k = 0; k < size; k++) {
                    uint8_t tmp = a[k];
                    a[k] = b[k];
                    b[k] = tmp;
                }
            }
        }
        gap /= 3;
    }
}

WEAK void *bsearch(const void *key, const void *base, size_t nmemb, size_t size,
                   int (*compar)(const void *, const void *))
{
    if (key == NULL || base == NULL || nmemb == 0 || size == 0 || compar == NULL) {
        return NULL;
    }
    const uint8_t *arr = (const uint8_t *)base;
    size_t lo = 0;
    size_t hi = nmemb;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        const void *elem = arr + mid * size;
        int cmp = compar(key, elem);
        if (cmp < 0) {
            hi = mid;
        } else if (cmp > 0) {
            lo = mid + 1;
        } else {
            return (void *)elem;
        }
    }
    return NULL;
}

/* =========================================================================
 * 4. Time, Clock & Calendar Conversion (for X.509 certificate validation)
 * ========================================================================= */
typedef long shim_time_t;

struct shim_tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
    long tm_gmtoff;
    const char *tm_zone;
};

struct shim_timeval {
    long tv_sec;
    long tv_usec;
};

struct shim_timespec {
    long tv_sec;
    long tv_nsec;
};

/* Default base epoch: 2026-10-18T00:00:00Z (1792281600) */
static int64_t base_epoch_sec = 1792281600LL;
static uint64_t base_tsc = 0;

static inline uint64_t read_tsc(void)
{
    uint32_t lo = 0, hi = 0;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

void libc_shim_set_epoch(int64_t epoch_sec)
{
    base_epoch_sec = epoch_sec;
    base_tsc = read_tsc();
}

static void get_current_time(int64_t *sec_out, int64_t *nsec_out)
{
    if (base_tsc == 0) {
        base_tsc = read_tsc();
    }
    uint64_t delta_cycles = read_tsc() - base_tsc;
    /* Assume ~2.5 GHz nominal TSC for monotonic sub-second progression */
    uint64_t delta_sec = delta_cycles / 2500000000ULL;
    uint64_t rem_cycles = delta_cycles % 2500000000ULL;
    if (sec_out != NULL) {
        *sec_out = base_epoch_sec + (int64_t)delta_sec;
    }
    if (nsec_out != NULL) {
        *nsec_out = (int64_t)((rem_cycles * 2ULL) / 5ULL);
    }
}

WEAK shim_time_t time(shim_time_t *tloc)
{
    int64_t sec = 0;
    get_current_time(&sec, NULL);
    if (tloc != NULL) {
        *tloc = (shim_time_t)sec;
    }
    return (shim_time_t)sec;
}

WEAK int gettimeofday(struct shim_timeval *tv, void *tz)
{
    (void)tz;
    if (tv != NULL) {
        int64_t sec = 0, nsec = 0;
        get_current_time(&sec, &nsec);
        tv->tv_sec = (long)sec;
        tv->tv_usec = (long)(nsec / 1000);
    }
    return 0;
}

WEAK int clock_gettime(int clk_id, struct shim_timespec *tp)
{
    (void)clk_id;
    if (tp != NULL) {
        int64_t sec = 0, nsec = 0;
        get_current_time(&sec, &nsec);
        tp->tv_sec = (long)sec;
        tp->tv_nsec = (long)nsec;
    }
    return 0;
}

/* Howard Hinnant's civil-from-days algorithm for accurate UTC gmtime_r */
WEAK struct shim_tm *gmtime_r(const shim_time_t *timer, struct shim_tm *result)
{
    if (timer == NULL || result == NULL) {
        return NULL;
    }
    int64_t t = (int64_t)(*timer);
    int64_t days = t / 86400;
    int64_t rem = t % 86400;
    if (rem < 0) {
        rem += 86400;
        days -= 1;
    }
    result->tm_hour = (int)(rem / 3600);
    rem %= 3600;
    result->tm_min = (int)(rem / 60);
    result->tm_sec = (int)(rem % 60);
    result->tm_wday = (int)((days + 4) % 7);
    if (result->tm_wday < 0) {
        result->tm_wday += 7;
    }

    int64_t z = days + 719468;
    int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    unsigned doe = (unsigned)(z - era * 146097);
    unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t y = (int64_t)yoe + era * 400;
    unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    unsigned mp = (5 * doy + 2) / 153;
    unsigned d = doy - (153 * mp + 2) / 5 + 1;
    unsigned m = mp < 10 ? mp + 3 : mp - 9;
    y += (m <= 2);

    int is_leap = (y % 4 == 0 && (y % 100 != 0 || y % 400 == 0));
    static const int yday_offset[12] = {
        0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
    };
    int yday = yday_offset[m - 1] + (int)d - 1 + (m > 2 ? is_leap : 0);

    result->tm_year = (int)(y - 1900);
    result->tm_mon = (int)(m - 1);
    result->tm_mday = (int)d;
    result->tm_yday = yday;
    result->tm_isdst = 0;
    result->tm_gmtoff = 0;
    result->tm_zone = "UTC";
    return result;
}

static struct shim_tm static_gmtime_buf;

WEAK struct shim_tm *gmtime(const shim_time_t *timer)
{
    return gmtime_r(timer, &static_gmtime_buf);
}

/* =========================================================================
 * 5. Hardware Entropy (x86_64 RDRAND + RDTSC + SplitMix64 mixing)
 * ========================================================================= */
static uint64_t entropy_counter = 0x9E3779B97F4A7C15ULL;

static int cpu_has_rdrand(void)
{
    static int cached = -1;
    if (cached < 0) {
        uint32_t eax = 1, ebx = 0, ecx = 0, edx = 0;
        __asm__ __volatile__(
            "cpuid"
            : "+a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        );
        cached = (ecx & (1u << 30)) ? 1 : 0;
    }
    return cached;
}

static uint64_t hardware_random_u64(void)
{
    uint64_t rdrand_val = 0;
    if (cpu_has_rdrand()) {
        unsigned char ok = 0;
        for (int i = 0; i < 16; i++) {
            __asm__ __volatile__(
                "rdrand %0; setc %1"
                : "=r"(rdrand_val), "=qm"(ok)
                :
                : "cc"
            );
            if (ok) {
                break;
            }
        }
    }
    uint64_t tsc = read_tsc();
    entropy_counter += 0x9E3779B97F4A7C15ULL;
    uint64_t z = entropy_counter ^ (tsc * 0xBF58476D1CE4E5B9ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    z = z ^ (z >> 31);
    return rdrand_val ^ z;
}

WEAK int getentropy(void *buffer, size_t length)
{
    if (buffer == NULL && length > 0) {
        return -1;
    }
    uint8_t *out = (uint8_t *)buffer;
    size_t pos = 0;
    while (pos < length) {
        uint64_t word = hardware_random_u64();
        size_t chunk = (length - pos < sizeof(word)) ? (length - pos) : sizeof(word);
        memcpy(out + pos, &word, chunk);
        pos += chunk;
    }
    return 0;
}

WEAK long getrandom(void *buffer, size_t length, unsigned int flags)
{
    (void)flags;
    if (getentropy(buffer, length) != 0) {
        return -1;
    }
    return (long)length;
}

WEAK unsigned long ossl_sel4_getauxval(unsigned long type)
{
    (void)type;
    return 0;
}

WEAK unsigned long getauxval(unsigned long type)
{
    (void)type;
    return 0;
}

/* =========================================================================
 * 6. Errno, Process, OS & Unused I/O Stubs
 * ========================================================================= */
static int shim_errno_val = 0;

WEAK int *__errno_location(void)
{
    return &shim_errno_val;
}

WEAK char *getenv(const char *name)
{
    (void)name;
    return NULL;
}

WEAK char *secure_getenv(const char *name)
{
    (void)name;
    return NULL;
}

WEAK int atexit(void (*function)(void))
{
    (void)function;
    return 0;
}

WEAK void abort(void)
{
    for (;;) {
        __asm__ __volatile__("ud2");
    }
}

WEAK void __assert_fail(const char *assertion, const char *file,
                        unsigned int line, const char *function)
{
    (void)assertion;
    (void)file;
    (void)line;
    (void)function;
    abort();
}

WEAK int getpid(void)
{
    return 1;
}

/* Linux x86_64 __NR_getrandom == 318 */
WEAK long syscall(long number, ...)
{
    if (number == 318) {
        __builtin_va_list ap;
        __builtin_va_start(ap, number);
        void *buf = __builtin_va_arg(ap, void *);
        size_t buflen = __builtin_va_arg(ap, size_t);
        unsigned int flags = __builtin_va_arg(ap, unsigned int);
        __builtin_va_end(ap);
        return getrandom(buf, buflen, flags);
    }
    shim_errno_val = 38; /* ENOSYS */
    return -1;
}

WEAK int __xpg_strerror_r(int errnum, char *buf, size_t buflen)
{
    (void)errnum;
    if (buf != NULL && buflen > 0) {
        strncpy(buf, "seL4 freestanding error", buflen);
        buf[buflen - 1] = '\0';
    }
    return 0;
}

WEAK int nanosleep(const void *req, void *rem)
{
    (void)req;
    (void)rem;
    return 0;
}

/* Unused POSIX / File / SysV SHM / Syslog stubs referenced by dead code in libcrypto.a */
WEAK int open(const char *pathname, int flags, ...)
{
    (void)pathname;
    (void)flags;
    shim_errno_val = 2; /* ENOENT */
    return -1;
}

WEAK int close(int fd)
{
    (void)fd;
    return 0;
}

WEAK long read(int fd, void *buf, size_t count)
{
    (void)fd;
    (void)buf;
    (void)count;
    return -1;
}

WEAK int stat(const char *pathname, void *statbuf)
{
    (void)pathname;
    (void)statbuf;
    return -1;
}

WEAK int fstat(int fd, void *statbuf)
{
    (void)fd;
    (void)statbuf;
    return -1;
}

WEAK int select(int nfds, void *readfds, void *writefds, void *exceptfds, void *timeout)
{
    (void)nfds;
    (void)readfds;
    (void)writefds;
    (void)exceptfds;
    (void)timeout;
    return -1;
}

WEAK void *opendir(const char *name)
{
    (void)name;
    return NULL;
}

WEAK void *readdir(void *dirp)
{
    (void)dirp;
    return NULL;
}

WEAK int closedir(void *dirp)
{
    (void)dirp;
    return 0;
}

WEAK int shmget(int key, size_t size, int shmflg)
{
    (void)key;
    (void)size;
    (void)shmflg;
    return -1;
}

WEAK void *shmat(int shmid, const void *shmaddr, int shmflg)
{
    (void)shmid;
    (void)shmaddr;
    (void)shmflg;
    return (void *)-1;
}

WEAK int shmdt(const void *shmaddr)
{
    (void)shmaddr;
    return 0;
}

WEAK int uname(void *buf)
{
    (void)buf;
    return -1;
}

WEAK void openlog(const char *ident, int option, int facility)
{
    (void)ident;
    (void)option;
    (void)facility;
}

WEAK void syslog(int priority, const char *format, ...)
{
    (void)priority;
    (void)format;
}

WEAK void closelog(void)
{
}

WEAK int fclose(void *stream)
{
    (void)stream;
    return 0;
}

WEAK size_t fread(void *ptr, size_t size, size_t nmemb, void *stream)
{
    (void)ptr;
    (void)size;
    (void)nmemb;
    (void)stream;
    return 0;
}

WEAK size_t fwrite(const void *ptr, size_t size, size_t nmemb, void *stream)
{
    (void)ptr;
    (void)size;
    (void)nmemb;
    (void)stream;
    return 0;
}

WEAK int ferror(void *stream)
{
    (void)stream;
    return 1;
}

WEAK void clearerr(void *stream)
{
    (void)stream;
}

WEAK void setbuf(void *stream, char *buf)
{
    (void)stream;
    (void)buf;
}

WEAK int __isoc99_sscanf(const char *str, const char *format, ...)
{
    (void)str;
    (void)format;
    return 0;
}
