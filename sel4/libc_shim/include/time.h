#ifndef _SEL4_SHIM_TIME_H
#define _SEL4_SHIM_TIME_H
#include <sys/types.h>
struct tm {
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
struct timespec {
    time_t tv_sec;
    long tv_nsec;
};
time_t time(time_t *tloc);
struct tm *gmtime_r(const time_t *timer, struct tm *result);
struct tm *gmtime(const time_t *timer);
#endif
