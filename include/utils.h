#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdint.h>


uintmax_t uleb_extract(uint8_t *buf);

intmax_t  sleb_extract(uint8_t *buf);

#endif /* _UTILS_H_ */
