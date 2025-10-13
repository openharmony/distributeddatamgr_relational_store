#include "securec.h"
#include <cstring>

errno_t memcpy_s(void *dest, size_t destMax, const void *src, size_t count)
{
    memcpy(dest, src, count);
    return 0;
}