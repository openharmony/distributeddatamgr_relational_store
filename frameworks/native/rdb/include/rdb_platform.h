/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DISTRIBUTEDDATAMGR_NATIVERDB_RDB_PLATFORM_H
#define DISTRIBUTEDDATAMGR_NATIVERDB_RDB_PLATFORM_H

#include <sys/stat.h>

#include <cstdint>
#include <string>

#include "unistd.h"
#ifdef WINDOWS_PLATFORM
#include <dir.h>
#endif
#define UNUSED_FUNCTION __attribute__((unused))
namespace OHOS {
namespace NativeRdb {
static constexpr mode_t DIR_RIGHT = 0771;
static UNUSED_FUNCTION uint32_t GetUid()
{
#ifdef WINDOWS_PLATFORM
    return 0;
#else
    return getuid();
#endif
}

static UNUSED_FUNCTION int MkDir(const std::string &filePath, mode_t dirRight = DIR_RIGHT)
{
#ifdef WINDOWS_PLATFORM
    return mkdir(filePath.c_str());
#else
    return mkdir(filePath.c_str(), dirRight);
#endif
}

static UNUSED_FUNCTION uint64_t GetThreadId()
{
#ifdef WINDOWS_PLATFORM
    return 0;
#else
    return (uint64_t)pthread_self();
#endif
}

} // namespace NativeRdb
} // namespace OHOS
#endif