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

#ifndef OHOS_DISTRIBUTED_DATA_INTERFACE_GDB_STORE_CONFIG_H
#define OHOS_DISTRIBUTED_DATA_INTERFACE_GDB_STORE_CONFIG_H

#include <cstdint>
#include <string>
#include <vector>

#include "rdb_store_config.h"
#include "rdb_visibility.h"

namespace OHOS::DistributedDataAip {
enum SecurityLevel : int32_t {
    S1 = 1,
    S2,
    S3,
    S4,
    LAST,
};

enum class DBType : int {
    /**
     * The graph database.
    */
    DB_GRAPH,

    /**
     * The vector database.
    */
    DB_VECTOR,
    /**
     * The BUTT of database.
    */
    DB_BUTT
};

class API_EXPORT StoreConfig {
public:
    API_EXPORT StoreConfig() = default;
    API_EXPORT ~StoreConfig();
    API_EXPORT StoreConfig(std::string name, std::string path, DBType dbType = DBType::DB_GRAPH, bool isEncrypt = false,
        const std::vector<uint8_t> &encryptKey = std::vector<uint8_t>());
    API_EXPORT void SetName(std::string name);
    API_EXPORT void SetPath(std::string path);
    API_EXPORT void SetDbType(DBType dbType);
    API_EXPORT void SetEncryptStatus(bool status);
    API_EXPORT void SetSecurityLevel(int32_t securityLevel);
    API_EXPORT bool IsEncrypt() const;
    API_EXPORT std::string GetJson() const;
    API_EXPORT std::string GetFullPath() const;
    API_EXPORT std::string GetPath() const;
    API_EXPORT std::string GetName() const;
    API_EXPORT int32_t GetSecurityLevel() const;
    API_EXPORT DBType GetDbType() const;
    API_EXPORT void SetIter(int32_t iter) const;
    API_EXPORT int32_t GetIter() const;
    API_EXPORT int GetWriteTime() const;
    API_EXPORT void SetWriteTime(int timeout);
    API_EXPORT int GetReadTime() const;
    API_EXPORT void SetReadTime(int timeout);
    API_EXPORT int GetReadConSize() const;
    API_EXPORT void SetReadConSize(int readConSize);
    API_EXPORT std::vector<uint8_t> GetEncryptKey() const;
    API_EXPORT int SetBundleName(const std::string &bundleName);
    API_EXPORT std::string GetBundleName() const;
    void GenerateEncryptedKey() const;
    std::vector<uint8_t> GetNewEncryptKey() const;
    void ChangeEncryptKey() const;

private:
    std::string name_;
    std::string path_;
    std::string bundleName_;
    DBType dbType_ = DBType::DB_GRAPH;
    bool isEncrypt_ = false;
    mutable std::vector<uint8_t> encryptKey_{};
    mutable std::vector<uint8_t> newEncryptKey_{};
    int32_t pageSize_ = 4;
    int32_t defaultIsolationLevel_ = 3;  // serialization
    mutable int32_t iter_ = 0;
    int32_t writeTimeout_ = 2; // seconds
    int32_t readTimeout_ = 1;  // seconds
    int32_t readConSize_ = 4;
    int32_t securityLevel_ = SecurityLevel::S1;

    [[maybe_unused]] int32_t redoFlushByTrx_ = 0;
    [[maybe_unused]] int32_t redoPubBufSize_ = 1024;
    [[maybe_unused]] int32_t maxConnNum_ = 100;
    [[maybe_unused]] int32_t bufferPoolSize_ = 1024;
    [[maybe_unused]] int32_t crcCheckEnable_ = 1;
    std::string bufferPoolPolicy_ = "BUF_PRIORITY_TABLE";

    [[maybe_unused]] int32_t sharedModeEnable_ = 0;
    [[maybe_unused]] int32_t MetaInfoBak_ = 0;
    [[maybe_unused]] int32_t dbFileSize_ = 128 * 1024 * 1024;

    static constexpr int MAX_TIMEOUT = 300; // seconds
    static constexpr int MIN_TIMEOUT = 1;   // seconds
    void ClearEncryptKey();
};
} // namespace OHOS::DistributedDataAip
#endif //OHOS_DISTRIBUTED_DATA_INTERFACE_GDB_STORE_CONFIG_H