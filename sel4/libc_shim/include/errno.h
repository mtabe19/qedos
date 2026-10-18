#ifndef _SEL4_SHIM_ERRNO_H
#define _SEL4_SHIM_ERRNO_H
int *__errno_location(void);
#define errno (*__errno_location())
#define EPERM   1
#define ENOENT  2
#define EINTR   4
#define EIO     5
#define EBADF   9
#define EAGAIN  11
#define ENOMEM  12
#define EACCES  13
#define EFAULT  14
#define EBUSY   16
#define EEXIST  17
#define EINVAL  22
#define ENOSYS  38
#endif
