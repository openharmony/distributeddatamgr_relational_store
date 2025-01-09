/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <utility>

#include "aip_errors.h"
#include "gdb_store_config.h"

namespace OHOS::DistributedDataAip {
StoreConfig::StoreConfig(
    std::string name, std::string path, DBType dbType, bool status, const std::vector<uint8_t> &encryptKey)
    : name_(std::move(name)), path_(std::move(path)), dbType_(dbType), isEncrypt_(status), encryptKey_(encryptKey)
{
}

void StoreConfig::SetName(std::string name)
{
    name_ = std::move(name);
}

void StoreConfig::SetPath(std::string path)
{
    path_ = std::move(path);
}

void StoreConfig::SetDbType(DBType dbType)
{
    dbType_ = dbType;
}

void StoreConfig::SetEncryptStatus(const bool status)
{
    isEncrypt_ = status;
}

bool StoreConfig::IsEncrypt() const
{
    return isEncrypt_;
}

std::string StoreConfig::GetJson() const
{
    return "{\"pageSize\":" + std::to_string(pageSize_) + "}";
}

std::string StoreConfig::GetFullPath() const
{
    return path_ + "/" + name_ + ".db";
}

std::string StoreConfig::GetPath() const
{
    return path_;
}

std::string StoreConfig::GetName() const
{
    return name_;
}

DBType StoreConfig::GetDbType() const
{
    return dbType_;
}

int32_t StoreConfig::GetIter() const
{
    return iter_;
}

void StoreConfig::SetIter(int32_t iter) const
{
    iter_ = iter;
}

int StoreConfig::GetWriteTime() const
{
    return writeTimeout_;
}

void StoreConfig::SetWriteTime(int timeout)
{
    writeTimeout_ = std::max(MIN_TIMEOUT, std::min(MAX_TIMEOUT, timeout));
}

int StoreConfig::GetReadTime() const
{
    return readTimeout_;
}

void StoreConfig::SetReadTime(int timeout)
{
    readTimeout_ = std::max(MIN_TIMEOUT, std::min(MAX_TIMEOUT, timeout));
}

int StoreConfig::GetReadConSize() const
{
    return readConSize_;
}

void StoreConfig::SetReadConSize(int readConSize)
{
    readConSize_ = readConSize;
}

void StoreConfig::SetSecurityLevel(int32_t securityLevel)
{
    securityLevel_ = securityLevel;
}

int32_t StoreConfig::GetSecurityLevel() const
{
    return securityLevel_;
}

int StoreConfig::SetBundleName(const std::string &bundleName)
{
    if (bundleName.empty()) {
        return E_ERROR;
    }
    bundleName_ = bundleName;
    return E_OK;
}

std::string StoreConfig::GetBundleName() const
{
    return bundleName_;
}

std::vector<uint8_t> StoreConfig::GetEncryptKey() const
{
    return encryptKey_;
}

void StoreConfig::GenerateEncryptedKey(const std::vector<uint8_t> &encryptKey) const
{
    encryptKey_.assign(encryptKey_.size(), 0);
    encryptKey_ = encryptKey;
}
} // namespace OHOS::DistributedDataAip