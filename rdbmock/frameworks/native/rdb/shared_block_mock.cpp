/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#include <cstring>

#include "hisysevent_c.h"
#include "mock.h"
#include "rdb_file_system.h"
#include "rdb_visibility.h"
#include "share_block.h"
#include "sqlite_errno.h"

int OH_HiSysEvent_Write(
    const char *domain, const char *name, HiSysEventEventType type, HiSysEventParam params[], size_t size)
{
    return 0;
}

namespace OHOS {
namespace NativeRdb {
API_EXPORT int gettid()
{
    return 0;
}
#ifdef __cplusplus
extern "C" {
#endif
API_EXPORT int FillSharedBlockOpt(SharedBlockInfo *info, sqlite3_stmt *stmt, int retryTime)
{
    return FillSharedBlock(info, stmt, retryTime);
}

static constexpr int RETRY_TIME = 50;
API_EXPORT int FillSharedBlock(SharedBlockInfo *info, sqlite3_stmt *stmt, int retryTime)
{
    (void)retryTime;
    int retryCount = 0;
    info->totalRows = info->addedRows = 0;
    bool isFull = false;
    bool hasException = false;
    while (!hasException && (!isFull || info->isCountAllRows)) {
        int err = sqlite3_step(stmt);
        if (err == SQLITE_ROW) {
            retryCount = 0;
            info->totalRows += 1;
            if (info->startPos >= info->totalRows || isFull) {
                continue;
            }
            info->isFull = true;
            isFull = info->isFull;
            hasException = info->hasException;
        } else if (err == SQLITE_DONE) {
            break;
        } else if (err == SQLITE_LOCKED || err == SQLITE_BUSY) {
            if (retryCount > RETRY_TIME) {
                hasException = true;
                return E_DATABASE_BUSY;
            } else {
                retryCount++;
            }
        } else {
            hasException = true;
            return SQLiteError::ErrNo(err);
        }
    }
    return E_OK;
}

API_EXPORT bool ResetStatement(SharedBlockInfo *info, sqlite3_stmt *stmt)
{
    (void)info;
    (void)stmt;
    return true;
}
std::vector<std::string> RdbFileSystem::GetEntries(const std::string &path)
{
    return {};
}
std::pair<size_t, int32_t> RdbFileSystem::RemoveAll(const std::string &path, bool removeSelf)
{
    return std::make_pair(0, 0);
}

std::string RdbFileSystem::RealPath(const std::string &path)
{
    return "";
}

#ifdef __cplusplus
}
#endif
} // namespace NativeRdb
} // namespace OHOS