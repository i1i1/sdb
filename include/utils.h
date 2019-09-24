#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdint.h>

uintmax_t uleb_decode(uint8_t *buf);

intmax_t  sleb_decode(uint8_t *buf);

size_t    leb_len(uint8_t *buf);

#endif /* _UTILS_H_ */
