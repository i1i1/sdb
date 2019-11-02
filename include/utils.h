#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdint.h>

#include <sys/ptrace.h>


uintmax_t uleb_decode(uint8_t *buf);
intmax_t  sleb_decode(uint8_t *buf);
size_t    leb_len(uint8_t *buf);

void *xmalloc(size_t sz);
void *xrealloc(void *a, size_t sz);

pid_t xwaitpid(pid_t pid, int *wstatus, int options);
void xptrace(int request, pid_t pid, void *addr, void *data);

#endif /* _UTILS_H_ */
