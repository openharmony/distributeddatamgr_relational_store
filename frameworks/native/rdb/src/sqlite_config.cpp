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
    encryptKey = config.GetEncryptKey();
    encrypted = !encryptKey.empty();
    initEncrypted = !encryptKey.empty();
    journalMode = config.GetJournalMode();
    databaseFileType = config.GetDatabaseFileType();
    securityLevel = config.GetSecurityLevel();
    syncMode = config.GetSyncMode();
    if (journalMode.empty()) {
        journalMode = SqliteGlobalConfig::GetDefaultJournalMode();
    }
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    isEncrypt = config.IsEncrypt();
#endif
    this->autoCheck = config.IsAutoCheck();
    this->journalSize = config.GetJournalSize();
    this->pageSize = config.GetPageSize();
    this->encryptAlgo = config.GetEncryptAlgo();
}

SqliteConfig::~SqliteConfig()
{
    ClearEncryptKey();
}

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

bool SqliteConfig::IsAutoCheck() const
{
    return autoCheck;
}
void SqliteConfig::SetAutoCheck(bool autoCheck)
{
    this->autoCheck = autoCheck;
}
int SqliteConfig::GetJournalSize() const
{
    return journalSize;
}
void SqliteConfig::SetJournalSize(int journalSize)
{
    this->journalSize = journalSize;
}
int SqliteConfig::GetPageSize() const
{
    return pageSize;
}
void SqliteConfig::SetPageSize(int pageSize)
{
    this->pageSize = pageSize;
}

 std::string SqliteConfig::GetEncryptAlgo() const
{
    return encryptAlgo;
}
void SqliteConfig::SetEncryptAlgo(const std::string &encryptAlgo)
{
    this->encryptAlgo = encryptAlgo;
}

bool SqliteConfig::IsEncrypted() const
{
    return encrypted;
}

bool SqliteConfig::IsInitEncrypted() const
{
    return initEncrypted;
}

std::vector<uint8_t> SqliteConfig::GetEncryptKey() const
{
    return encryptKey;
}

void SqliteConfig::UpdateEncryptKey(const std::vector<uint8_t> &newKey)
{
    std::fill(encryptKey.begin(), encryptKey.end(), 0);
    encryptKey = newKey;
    encrypted = !encryptKey.empty();
}

void SqliteConfig::ClearEncryptKey()
{
    std::fill(encryptKey.begin(), encryptKey.end(), 0);
    encryptKey.clear();
}

int32_t SqliteConfig::GetSecurityLevel() const
{
    return securityLevel;
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
#endif
} // namespace NativeRdb
} // namespace OHOS