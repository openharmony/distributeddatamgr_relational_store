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

#ifndef NATIVE_RDB_RDB_STORE_CONFIG_H
#define NATIVE_RDB_RDB_STORE_CONFIG_H

#include <string>
#include <vector>
#include <map>
#include <functional>

namespace OHOS::NativeRdb {
// indicates the type of the storage
enum class StorageMode {
    MODE_MEMORY = 101,
    MODE_DISK,
};

enum class JournalMode {
    MODE_DELETE,
    MODE_TRUNCATE,
    MODE_PERSIST,
    MODE_MEMORY,
    MODE_WAL,
    MODE_OFF,
};

enum class SyncMode {
    MODE_OFF,
    MODE_NORMAL,
    MODE_FULL,
    MODE_EXTRA,
};

enum class DatabaseFileType {
    NORMAL,
    BACKUP,
    CORRUPT,
};

enum class SecurityLevel : int32_t {
    S1 = 1,
    S2,
    S3,
    S4,
    LAST
};

enum RoleType : uint32_t {
    OWNER = 0,
    VISITOR,
};

enum DBType : uint32_t {
    DB_SQLITE = 0,
    DB_VECTOR,
    DB_BUTT
};

using ScalarFunction = std::function<std::string(const std::vector<std::string>&)>;

struct ScalarFunctionInfo {
    ScalarFunctionInfo(ScalarFunction function, int argc) : function_(function), argc_(argc) {}
    ScalarFunction function_;
    int argc_;
};

class RdbStoreConfig {
public:
    static constexpr int DB_PAGE_SIZE = 4096;    /* default page size : 4k */
    static constexpr int DB_JOURNAL_SIZE = 1024 * 1024; /* default file size : 1M */
    static constexpr char DB_DEFAULT_JOURNAL_MODE[] = "WAL";
    static constexpr char DB_DEFAULT_ENCRYPT_ALGO[] = "sha256";
    RdbStoreConfig(const std::string &path, StorageMode storageMode = StorageMode::MODE_DISK, bool readOnly = false,
        const std::vector<uint8_t> &encryptKey = std::vector<uint8_t>(),
        const std::string &journalMode = DB_DEFAULT_JOURNAL_MODE,
        const std::string &syncMode = "", const std::string &databaseFileType = "",
        SecurityLevel securityLevel = SecurityLevel::LAST, bool isCreateNecessary = true,
        bool autoCheck = false, int journalSize = 1048576, int pageSize = 4096,
        const std::string &encryptAlgo = "sha256");
    ~RdbStoreConfig();
    std::string GetName() const;
    std::string GetPath() const;
    StorageMode GetStorageMode() const;
    std::string GetJournalMode() const;
    std::string GetSyncMode() const;
    std::vector<uint8_t> GetEncryptKey() const;
    bool IsReadOnly() const;
    bool IsMemoryRdb() const;
    std::string GetDatabaseFileType() const;
    SecurityLevel GetSecurityLevel() const;
    void SetEncryptStatus(const bool status);
    bool IsEncrypt() const;
    bool IsCreateNecessary() const;

    // set the journal mode, if not set, the default mode is WAL
    void SetName(std::string name);
    void SetJournalMode(JournalMode journalMode);
    void SetPath(std::string path);
    void SetReadOnly(bool readOnly);
    void SetStorageMode(StorageMode storageMode);
    void SetDatabaseFileType(DatabaseFileType type);
    void SetEncryptKey(const std::vector<uint8_t> &encryptKey);
    void SetSecurityLevel(SecurityLevel secLevel);
    void ClearEncryptKey();

    // distributed rdb
    int SetBundleName(const std::string &bundleName);
    std::string GetBundleName() const;
    void SetModuleName(const std::string& moduleName);
    std::string GetModuleName() const;
    void SetServiceName(const std::string& serviceName);
    void SetArea(int32_t area);
    int32_t GetArea() const;
    void SetCreateNecessary(bool isCreateNecessary);
    void SetAutoClean(bool isAutoClean);
    bool GetAutoClean() const;
    void SetIsVector(bool isVector);
    bool IsVector() const;

    static std::string GetJournalModeValue(JournalMode journalMode);
    static std::string GetSyncModeValue(SyncMode syncMode);
    static std::string GetDatabaseFileTypeValue(DatabaseFileType databaseFileType);
    bool IsAutoCheck() const;
    void SetAutoCheck(bool autoCheck);
    int GetJournalSize() const;
    void SetJournalSize(int journalSize);
    int GetPageSize() const;
    void SetPageSize(int pageSize);
    const std::string GetEncryptAlgo() const;
    void SetEncryptAlgo(const std::string &encryptAlgo);
    int GetReadConSize() const;
    void SetReadConSize(int readConSize);
    void SetScalarFunction(const std::string &functionName, int argc, ScalarFunction function);
    void SetDataGroupId(const std::string &dataGroupId);
    std::string GetDataGroupId() const;
    void SetCustomDir(const std::string &customDir);
    std::string GetCustomDir() const;
    std::map<std::string, ScalarFunctionInfo> GetScalarFunctions() const;
    bool IsSearchable() const;
    void SetSearchable(bool searchable);
    int GetWriteTime() const;
    void SetWriteTime(int timeout);
    int GetReadTime() const;
    void SetReadTime(int timeout);
    void SetVisitorDir(const std::string &visitorDir);
    std::string GetVisitorDir() const;
    void SetRoleType(RoleType role);
    uint32_t GetRoleType() const;
    void SetAllowRebuild(bool allowRebuild);
    bool GetAllowRebuild() const;
    void SetDBType(int32_t dbType);
    int32_t GetDBType() const;

    bool operator==(const RdbStoreConfig &config) const
    {
        if (this->customScalarFunctions.size() != config.customScalarFunctions.size()) {
            return false;
        }

        auto iter1 = this->customScalarFunctions.begin();
        auto iter2 = config.customScalarFunctions.begin();
        for (; iter1 != this->customScalarFunctions.end(); ++iter1, ++iter2) {
            if (iter1->first != iter2->first) {
                return false;
            }
        }

        if (this->encryptKey_.size() != config.encryptKey_.size()) {
            return false;
        }

        for (size_t i = 0; i < encryptKey_.size(); i++) {
            if (this->encryptKey_[i] != config.encryptKey_[i]) {
                return false;
            }
        }

        return this->path == config.path && this->storageMode == config.storageMode
               && this->storageMode == config.storageMode && this->journalMode == config.journalMode
               && this->syncMode == config.syncMode && this->databaseFileType == config.databaseFileType
               && this->isEncrypt_ == config.isEncrypt_ && this->securityLevel == config.securityLevel
               && this->journalSize == config.journalSize && this->pageSize == config.pageSize
               && this->readConSize_ == config.readConSize_ && this->customDir_ == config.customDir_
               && this->allowRebuilt_ == config.allowRebuilt_;
    }

private:
    bool readOnly = false;
    bool isEncrypt_ = false;
    bool isCreateNecessary_;
    bool isSearchable_ = false;
    bool autoCheck_;
    bool isAutoClean_ = true;
    bool isVector_ = false;
    int32_t journalSize;
    int32_t pageSize;
    int32_t readConSize_ = 4;
    int32_t area_ = 0;
    int32_t writeTimeout_ = 2; // seconds
    int32_t readTimeout_ = 1; // seconds
    int32_t dbType_ = DB_SQLITE;
    SecurityLevel securityLevel = SecurityLevel::LAST;
    RoleType role_ = OWNER;
    StorageMode storageMode;
    std::string name;
    std::string path;
    std::string journalMode;
    std::string syncMode;
    std::string databaseFileType;
    // distributed rdb
    std::string bundleName_;
    std::string moduleName_;
    std::string visitorDir_;
    std::string encryptAlgo;
    std::string dataGroupId_;
    std::string customDir_;
    std::vector<uint8_t> encryptKey_{};
    std::map<std::string, ScalarFunctionInfo> customScalarFunctions;
    
    static constexpr int MAX_TIMEOUT = 300; // seconds
    static constexpr int MIN_TIMEOUT = 1;   // seconds
    bool allowRebuilt_ = false;
};
} // namespace OHOS::NativeRdb

#endif