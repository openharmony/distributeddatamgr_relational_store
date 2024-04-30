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
#include "rdb_types.h"
#include "rdb_visibility.h"

namespace OHOS::NativeRdb {
/**
 * @brief Indicates the type of the storage.
 */
enum class StorageMode {
    /** Indicates the database storage is memory.*/
    MODE_MEMORY = 101,
    /** Indicates the database storage is disk.*/
    MODE_DISK,
};

/**
 * @brief Indicates the type of the journal.
 */
enum class JournalMode {
    /** Indicates the database journal mode is delete.*/
    MODE_DELETE,
    /** Indicates the database journal mode is truncate.*/
    MODE_TRUNCATE,
    /** Indicates the database journal mode is persist.*/
    MODE_PERSIST,
    /** Indicates the database journal mode is memory.*/
    MODE_MEMORY,
    /** Indicates the database journal mode is wal.*/
    MODE_WAL,
    /** Indicates the database journal mode is off.*/
    MODE_OFF,
};

/**
 * @brief Indicates the database synchronization mode.
 */
enum class SyncMode {
    /** Indicates the sync mode is off.*/
    MODE_OFF,
    /** Indicates the sync mode is normal.*/
    MODE_NORMAL,
    /** Indicates the sync mode is full.*/
    MODE_FULL,
    /** Indicates the sync mode is extra.*/
    MODE_EXTRA,
};

/**
 * @brief Indicates the database file type.
 */
enum class DatabaseFileType {
    /** Indicates the database file type is normal.*/
    NORMAL,
    /** Indicates the database file type is backup.*/
    BACKUP,
    /** Indicates the database file type is corrupt.*/
    CORRUPT,
};

/**
 * @brief Describes the {@link RdbStore} type.
 */
enum class SecurityLevel : int32_t {
    /**
     * @brief S1: means the db is low level security.
     *
     * There are some low impact, when the data is leaked.
     */
    S1 = 1,
    /**
     * @brief S2: means the db is middle level security.
     *
     * There are some major impact, when the data is leaked.
     */
    S2,
    /**
     * @brief S3: means the db is high level security
     *
     * There are some severity impact, when the data is leaked.
     */
    S3,
    /**
     * @brief S3: means the db is critical level security
     *
     * There are some critical impact, when the data is leaked.
     */
    S4,
    /**
     * @brief LAST: This is a boundary judgment value.
     */
    LAST
};

enum RoleType : uint32_t {
    /**
      * The user has administrative rights.
    */
    OWNER = 0,
    /**
      * The user has read-only permission.
    */
    VISITOR,
};

enum DBType : uint32_t {
    /**
     * The SQLITE database.
    */
    DB_SQLITE = 0,

    /**
     * The vector database.
    */
    DB_VECTOR,
    /**
     * The BUTT of database.
    */
    DB_BUTT
};

/**
 * @brief Use DistributedType replace OHOS::DistributedRdb::RdbDistributedType.
 */
using DistributedType = OHOS::DistributedRdb::RdbDistributedType;

/**
 * @brief Use ScalarFunction replace std::function<std::string(const std::vector<std::string>&)>.
 */
using ScalarFunction = std::function<std::string(const std::vector<std::string>&)>;

struct ScalarFunctionInfo {
    ScalarFunctionInfo(ScalarFunction function, int argc) : function_(function), argc_(argc) {}
    ScalarFunction function_;
    int argc_;
};
/**
 * Manages relational database configurations.
 */
class API_EXPORT RdbStoreConfig {
public:
    /**
    * @brief The constant indicates the database default page size.
    */
    static constexpr int DB_PAGE_SIZE = 4096;    /* default page size : 4k */

    /**
    * @brief The constant indicates the database default journal size.
    */
    static constexpr int DB_JOURNAL_SIZE = 1024 * 1024; /* default file size : 1M */

    /**
    * @brief The constant indicates the database default journal mode.
    */
    static constexpr char DB_DEFAULT_JOURNAL_MODE[] = "WAL";

    /**
    * @brief The constant indicates the database default encrypt algorithm.
    */
    static constexpr char DB_DEFAULT_ENCRYPT_ALGO[] = "sha256";

    /**
     * @brief Constructor.
     *
     * A parameterized constructor used to create an RdbStoreConfig instance.
     *
     * @param path Indicates the path of the database.
     * @param storageMode Indicates the storage mode of the database.
     * @param readOnly Indicates whether the database is read-only.
     * @param encryptKey Indicates the encrypt key of the database.
     * @param journalMode Indicates the journal mode of the database.
     * @param syncMode Indicates the sync mode of the database.
     * @param databaseFileType Indicates the file table of the database.
     * @param securityLevel Indicates the security level of the database.
     * @param isCreateNecessary Indicates whether the database is create necessary.
     * @param autoCheck Indicates whether the database is auto check.
     * @param journalSize Indicates the journal size of the database.
     * @param pageSize Indicates the page size of the database.
     * @param encryptAlgo Indicates the encrypt algorithm of the database.
     */
    API_EXPORT RdbStoreConfig(const std::string &path, StorageMode storageMode = StorageMode::MODE_DISK,
        bool readOnly = false, const std::vector<uint8_t> &encryptKey = std::vector<uint8_t>(),
        const std::string &journalMode = DB_DEFAULT_JOURNAL_MODE, const std::string &syncMode = "",
        const std::string &databaseFileType = "", SecurityLevel securityLevel = SecurityLevel::LAST,
        bool isCreateNecessary = true, bool autoCheck = false, int journalSize = DB_JOURNAL_SIZE,
        int pageSize = DB_PAGE_SIZE, const std::string &encryptAlgo = DB_DEFAULT_ENCRYPT_ALGO);
    /**
     * @brief Destructor.
     */
    API_EXPORT ~RdbStoreConfig();

    /**
     * @brief Obtains the database name.
     */
    API_EXPORT std::string GetName() const;

    /**
     * @brief Obtains the database path.
     */
    API_EXPORT std::string GetPath() const;

    /**
     * @brief Obtains the storage mode.
     */
    API_EXPORT StorageMode GetStorageMode() const;

    /**
     * @brief Obtains the journal mode in this {@code StoreConfig} object.
     */
    API_EXPORT std::string GetJournalMode() const;

    /**
     * @brief Obtains the synchronization mode in this {@code StoreConfig} object.
     */
    API_EXPORT std::string GetSyncMode() const;

    /**
     * @brief Checks whether the database is read-only.
     */
    API_EXPORT bool IsReadOnly() const;

    /**
     * @brief Checks whether the database is memory.
     */
    API_EXPORT bool IsMemoryRdb() const;

    /**
     * @brief Obtains the database file type in this {@code StoreConfig} object.
     */
    API_EXPORT std::string GetDatabaseFileType() const;

    /**
     * @brief Obtains the database security level in this {@code StoreConfig} object.
     */
    API_EXPORT SecurityLevel GetSecurityLevel() const;

    /**
     * @brief Set encrypt status for the current database.
     */
    API_EXPORT void SetEncryptStatus(const bool status);

    /**
     * @brief Checks whether the database is encrypt.
     */
    API_EXPORT bool IsEncrypt() const;

    /**
     * @brief Checks whether the database is create necessary.
     */
    API_EXPORT bool IsCreateNecessary() const;

    /**
     * @brief Sets the name for the object.
     */
    API_EXPORT void SetName(std::string name);

    /**
     * @brief Sets the journal mode, if not set, the default mode is WAL
     */
    API_EXPORT void SetJournalMode(JournalMode journalMode);

    /**
     * @brief Sets the path for the object.
     */
    API_EXPORT void SetPath(std::string path);

    /**
     * @brief Sets whether the database is read-only.
     */
    API_EXPORT void SetReadOnly(bool readOnly);

    /**
     * @brief Sets the storage mode for the object.
     */
    API_EXPORT void SetStorageMode(StorageMode storageMode);

    /**
     * @brief Sets database file type.
     */
    API_EXPORT void SetDatabaseFileType(DatabaseFileType type);

    /**
     * @brief Sets database security level.
     */
    API_EXPORT void SetSecurityLevel(SecurityLevel secLevel);

    /**
     * @brief Sets whether the database is create necessary.
     */
    API_EXPORT void SetCreateNecessary(bool isCreateNecessary);

    /**
     * @brief Sets the bundle name for the object.
     */
    API_EXPORT int SetBundleName(const std::string &bundleName);

    /**
     * @brief Obtains the bundle name in this {@code StoreConfig} object.
     */
    API_EXPORT std::string GetBundleName() const;

    /**
     * @brief Sets the distributed type for the object.
     */
    API_EXPORT int SetDistributedType(DistributedType type);

    /**
     * @brief Obtains the distributed type in this {@code StoreConfig} object.
     */
    API_EXPORT DistributedType GetDistributedType() const;

    /**
     * @brief Sets the module name for the object.
     */
    API_EXPORT void SetModuleName(const std::string& moduleName);

    /**
     * @brief Obtains the module name in this {@code StoreConfig} object.
     */
    API_EXPORT std::string GetModuleName() const;

    /**
     * @brief Sets the service name for the object.
     */
    API_EXPORT void SetServiceName(const std::string& serviceName);

    /**
     * @brief Sets the area for the object.
     */
    API_EXPORT void SetArea(int32_t area);

    /**
     * @brief Obtains the area in this {@code StoreConfig} object.
     */
    API_EXPORT int32_t GetArea() const;

    /**
     * @brief Obtains the journal mode value in this {@code StoreConfig} object.
     */
    API_EXPORT static std::string GetJournalModeValue(JournalMode journalMode);

    /**
     * @brief Obtains the sync mode value in this {@code StoreConfig} object.
     */
    API_EXPORT static std::string GetSyncModeValue(SyncMode syncMode);

    /**
     * @brief Obtains the database file type in this {@code StoreConfig} object.
     */
    API_EXPORT static std::string GetDatabaseFileTypeValue(DatabaseFileType databaseFileType);

    /**
     * @brief Checks whether the database is auto check.
     */
    API_EXPORT bool IsAutoCheck() const;

    /**
     * @brief Sets whether the database is auto check.
     */
    API_EXPORT void SetAutoCheck(bool autoCheck);

    /**
     * @brief Obtains the journal size in this {@code StoreConfig} object.
     */
    API_EXPORT int GetJournalSize() const;

    /**
     * @brief Sets the journal size for the object.
     */
    API_EXPORT void SetJournalSize(int journalSize);

    /**
     * @brief Obtains the page size in this {@code StoreConfig} object.
     */
    API_EXPORT int GetPageSize() const;

    /**
     * @brief Sets the page size for the object.
     */
    API_EXPORT void SetPageSize(int pageSize);

    /**
     * @brief Obtains the encrypt algorithm in this {@code StoreConfig} object.
     */
    API_EXPORT const std::string GetEncryptAlgo() const;

    /**
     * @brief Sets the encrypt algorithm for the object.
     */
    API_EXPORT void SetEncryptAlgo(const std::string &encryptAlgo);

    /**
     * @brief Obtains the read connection size in this {@code StoreConfig} object.
     */
    API_EXPORT int GetReadConSize() const;

    /**
     * @brief Sets the read connection size for the object.
     */
    API_EXPORT void SetReadConSize(int readConSize);

    /**
     * @brief Sets the encrypt key for the object.
     */
    void SetEncryptKey(const std::vector<uint8_t> &encryptKey);

    /**
     * @brief Obtains the encrypt key in this {@code StoreConfig} object.
     */
    std::vector<uint8_t> GetEncryptKey() const;

    /**
     * @brief Sets the scalar function for the object.
     */
    API_EXPORT void SetScalarFunction(const std::string &functionName, int argc, ScalarFunction function);

    /**
     * @brief Obtains the registered scalar functions in this {@code StoreConfig} object.
     */
    API_EXPORT std::map<std::string, ScalarFunctionInfo> GetScalarFunctions() const;

    /**
     * @brief Sets the module name for the object.
     */
    void SetDataGroupId(const std::string &DataGroupId);

    /**
     * @brief Obtains the module name in this {@code StoreConfig} object.
     */
    std::string GetDataGroupId() const;

    /**
     * @brief Sets the autoCleanDirtyData for the object.
     */
    void SetAutoClean(bool isAutoClean);

    /**
     * @brief Obtains the autoCleanDirtyData in this {@code StoreConfig} object.
     */
    bool GetAutoClean() const;

    /**
     * @brief Set the isVector field in this {@code StoreConfig} object.
     */
    void SetIsVector(bool isVector);

    /**
     * @brief Obtains the isVector field in this {@code StoreConfig} object.
     */
    bool IsVector() const;

    /**
     * @brief Sets the customDir directory for the object.
     */
    void SetCustomDir(const std::string &customDir);

    /**
     * @brief Obtains the customDir directory in this {@code StoreConfig} object.
     */
    std::string GetCustomDir() const;

    /**
     * @brief Sets the visitorDir for the object.
     */
    API_EXPORT void SetVisitorDir(const std::string &visitorDir);

    /**
     * @brief Obtains the visitorDir in this {@code StoreConfig} object.
     */
    API_EXPORT std::string GetVisitorDir() const;

    /**
     * @brief Overload the line number operator.
     */
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

    /**
     * @brief Checks whether the database isSearchable necessary.
     */
    bool IsSearchable() const;
    /**
     * @brief Sets whether the database Searchable necessary.
     */
    void SetSearchable(bool searchable);

    /**
     * @brief Sets the timeout to get write connection for the object.
     */
    int GetWriteTime() const;

    /**
     * @brief Gets the timeout to get write connection for the object.
     */
    void SetWriteTime(int timeout);

    /**
     * @brief Sets the timeout to get read connection for the object.
     */
    int GetReadTime() const;

    /**
     * @brief Gets the timeout to get read connection for the object.
     */
    void SetReadTime(int timeout);

    void SetRoleType(RoleType role);

    uint32_t GetRoleType() const;

    void SetAllowRebuild(bool allowRebuild);

    bool GetAllowRebuild() const;

    void SetDBType(int32_t dbType);

    int32_t GetDBType() const;

private:
    void ClearEncryptKey();
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
    DistributedType distributedType_ = DistributedRdb::RdbDistributedType::RDB_DEVICE_COLLABORATION;
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
