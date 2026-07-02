/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <string.h>

#include "securec.h"

errno_t memset_s(void *dest, size_t destMax, int c, size_t count)
{
    if (dest == nullptr || destMax == 0) {
        return EINVAL;
    }
    if (count > destMax) {
        (void)memset(dest, c, destMax);
        return ERANGE;
    }
    (void)memset(dest, c, count);
    return EOK;
}

errno_t memcpy_s(void *dest, size_t destMax, const void *src, size_t count)
{
    if (dest == nullptr || src == nullptr || destMax == 0) {
        return EINVAL;
    }
    if (count > destMax) {
        return ERANGE;
    }
    if (dest == src) {
        return EOK;
    }
    (void)memcpy(dest, src, count);
    return EOK;
}

errno_t memmove_s(void *dest, size_t destMax, const void *src, size_t count)
{
    if (dest == nullptr || src == nullptr || destMax == 0) {
        return EINVAL;
    }
    if (count > destMax) {
        return ERANGE;
    }
    (void)memmove(dest, src, count);
    return EOK;
}

errno_t strcpy_s(char *dest, size_t destMax, const char *src)
{
    if (dest == nullptr || src == nullptr || destMax == 0) {
        return EINVAL;
    }
    size_t srcLen = strlen(src);
    if (srcLen >= destMax) {
        return ERANGE;
    }
    (void)strcpy(dest, src);
    return EOK;
}

errno_t strncpy_s(char *dest, size_t destMax, const char *src, size_t count)
{
    if (dest == nullptr || src == nullptr || destMax == 0) {
        return EINVAL;
    }
    if (count > destMax) {
        return ERANGE;
    }
    (void)strncpy(dest, src, count);
    if (count < destMax) {
        dest[count] = '\0';
    }
    return EOK;
}

errno_t strcat_s(char *dest, size_t destMax, const char *src)
{
    if (dest == nullptr || src == nullptr || destMax == 0) {
        return EINVAL;
    }
    size_t destLen = strlen(dest);
    size_t srcLen = strlen(src);
    if (destLen + srcLen >= destMax) {
        return ERANGE;
    }
    (void)strcat(dest, src);
    return EOK;
}

errno_t strncat_s(char *dest, size_t destMax, const char *src, size_t count)
{
    if (dest == nullptr || src == nullptr || destMax == 0) {
        return EINVAL;
    }
    size_t destLen = strlen(dest);
    if (destLen + count >= destMax) {
        return ERANGE;
    }
    (void)strncat(dest, src, count);
    return EOK;
}

errno_t sprintf_s(char *dest, size_t destMax, const char *format, ...)
{
    if (dest == nullptr || format == nullptr || destMax == 0) {
        return EINVAL;
    }
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(dest, destMax, format, args);
    va_end(args);
    if (ret < 0 || (size_t)ret >= destMax) {
        return ERANGE;
    }
    return EOK;
}

errno_t snprintf_s(char *dest, size_t destMax, size_t count, const char *format, ...)
{
    if (dest == nullptr || format == nullptr || destMax == 0 || count > destMax) {
        return EINVAL;
    }
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(dest, count, format, args);
    va_end(args);
    if (ret < 0 || (size_t)ret >= count) {
        return ERANGE;
    }
    return EOK;
}

errno_t vsprintf_s(char *dest, size_t destMax, const char *format, va_list arglist)
{
    if (dest == nullptr || format == nullptr || destMax == 0) {
        return EINVAL;
    }
    int ret = vsnprintf(dest, destMax, format, arglist);
    if (ret < 0 || (size_t)ret >= destMax) {
        return ERANGE;
    }
    return EOK;
}

errno_t vsnprintf_s(char *dest, size_t destMax, size_t count, const char *format, va_list arglist)
{
    if (dest == nullptr || format == nullptr || destMax == 0 || count > destMax) {
        return EINVAL;
    }
    int ret = vsnprintf(dest, count, format, arglist);
    if (ret < 0 || (size_t)ret >= count) {
        return ERANGE;
    }
    return EOK;
}