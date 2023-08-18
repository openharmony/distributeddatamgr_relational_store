/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "sqlite_config.h"
#include "sqlite_global_config.h"

namespace OHOS {
namespace NativeRdb {
SqliteConfig::SqliteConfig(const RdbStoreConfig &config)
{
    path = config.GetPath();
    storageMode = config.GetStorageMode();
    readOnly = config.IsReadOnly();
    journalMode = config.GetJournalMode();
    databaseFileType = config.GetDatabaseFileType();
    syncMode = config.GetSyncMode();
    if (journalMode.empty()) {
        journalMode = SqliteGlobalConfig::GetDefaultJournalMode();
    }
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    isEncrypt = config.IsEncrypt();
    isCreateNecessary = config.IsCreateNecessary();
    bundleName = config.GetBundleName();
#endif
}

SqliteConfig::~SqliteConfig() = default;

std::string SqliteConfig::GetPath() const
{
    return path;
}

void SqliteConfig::SetPath(std::string newPath)
{
    this->path = newPath;
}


StorageMode SqliteConfig::GetStorageMode() const
{
    return storageMode;
}

std::string SqliteConfig::GetJournalMode() const
{
    return journalMode;
}

std::string SqliteConfig::GetSyncMode() const
{
    return syncMode;
}

bool SqliteConfig::IsReadOnly() const
{
    return readOnly;
}

std::string SqliteConfig::GetDatabaseFileType() const
{
    return databaseFileType;
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
bool SqliteConfig::IsEncrypt() const
{
    return isEncrypt;
}

std::string SqliteConfig::GetBundleName() const
{
    return bundleName;
}
bool SqliteConfig::IsCreateNecessary() const
{
    return isCreateNecessary;
}

void SqliteConfig::SetCreateNecessary(bool CreateNecessary)
{
    this->isCreateNecessary = CreateNecessary;
}

#endif
} // namespace NativeRdb
} // namespace OHOS