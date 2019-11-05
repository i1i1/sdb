#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdint.h>

#include <sys/ptrace.h>

#if defined(__GNUC__) || defined(__clang__)
/* forcing 128 bit numbers */
typedef __int128 sleb;
typedef unsigned __int128 uleb;
#else
/* using max integers from standart */
typedef intmax_t sleb;
typedef uintmax_t uleb;
#endif

uleb uleb_decode(uint8_t *buf);
sleb sleb_decode(uint8_t *buf);
size_t leb_len(uint8_t *buf);

void *xmalloc(size_t sz);
void *xrealloc(void *a, size_t sz);

pid_t xwaitpid(pid_t pid, int *wstatus, int options);
void xptrace(int request, pid_t pid, void *addr, void *data);

#endif /* _UTILS_H_ */
