/*
 * Freestanding Linux x86_64 _start harness to execute test_tls_shim_run()
 * directly on the host CPU with -nostdlib (zero glibc, 100% libc_shim.o).
 */
#include <stddef.h>

extern int main(void);

long write(int fd, const void *buf, size_t count)
{
    long ret;
    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "a"(1L), "D"((long)fd), "S"(buf), "d"(count)
        : "rcx", "r11", "memory"
    );
    return ret;
}

__attribute__((noreturn)) void _exit_host(int code)
{
    __asm__ __volatile__(
        "syscall"
        :
        : "a"(60L), "D"((long)code)
        : "rcx", "r11", "memory"
    );
    __builtin_unreachable();
}

__attribute__((naked)) void _start(void)
{
    __asm__ __volatile__(
        "xor %%ebp, %%ebp\n\t"
        "and $-16, %%rsp\n\t"
        "call main\n\t"
        "mov %%eax, %%edi\n\t"
        "call _exit_host\n\t"
        :
        :
        : "memory"
    );
}
