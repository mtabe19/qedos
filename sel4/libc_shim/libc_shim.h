/*
 * Freestanding libc + entropy + heap allocator shim for OpenSSL 3.6.1
 * running inside an x86_64 seL4/Microkit Protection Domain.
 */
#ifndef SEL4_LIBC_SHIM_H
#define SEL4_LIBC_SHIM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Heap diagnostics & reset for self-tests and connection lifecycle checks */
void libc_shim_heap_reset(void);
size_t libc_shim_heap_bytes_in_use(void);
size_t libc_shim_heap_capacity(void);

/* Monotonic wall-clock epoch setter (defaults to 2026-10-18T00:00:00Z so X.509 checks succeed) */
void libc_shim_set_epoch(int64_t epoch_sec);

/* Standard allocator API */
void *malloc(size_t size);
void free(void *ptr);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
int posix_memalign(void **memptr, size_t alignment, size_t size);

/* Entropy API (x86_64 RDRAND + RDTSC mixing) */
int getentropy(void *buffer, size_t length);
long getrandom(void *buffer, size_t length, unsigned int flags);
unsigned long ossl_sel4_getauxval(unsigned long type);

#ifdef __cplusplus
}
#endif

#endif /* SEL4_LIBC_SHIM_H */
