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

enum class DatabaseFileSecurityLevel : int32_t {
    NO_LEVEL = 0,
    S0,
    S1,
    S2,
    S3,
    S4,
    LAST,
};

static const char *DatabaseFileSecurityLabel[] = { "", "S0", "S1", "S2", "S3", "S4" };
static constexpr int DB_PAGE_SIZE = 4096;    /* default page size : 4k */
static constexpr int DB_JOURNAL_SIZE = 1048576; /* default file size : 1M */
static constexpr char DB_DEFAULT_JOURNAL_MODE[] = "delete";
static constexpr char DB_DEFAULT_ENCRYPT_ALGO[] = "sha256";

class RdbStoreConfig {
public:
    RdbStoreConfig(const RdbStoreConfig &config);
    RdbStoreConfig(const std::string &path, StorageMode storageMode = StorageMode::MODE_DISK, bool readOnly = false,
        const std::vector<uint8_t> &encryptKey = std::vector<uint8_t>(), const std::string &journalMode = "",
        const std::string &syncMode = "", const std::string &databaseFileType = "",
        const std::string &databaseFileSecurityLevel = "",
        bool autoCheck = false, int journalSize = DB_JOURNAL_SIZE, int pageSize = DB_PAGE_SIZE,
        const std::string encryptAlgo = DB_DEFAULT_ENCRYPT_ALGO);
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
    std::string GetDatabaseFileSecurityLevel() const;
    int32_t GetSecurityLevel() const;
    void SetEncryptStatus(const bool status);
    bool IsEncrypt() const;

    // set the journal mode, if not set, the default mode is WAL
    void SetName(std::string name);
    void SetJournalMode(JournalMode journalMode);
    void SetPath(std::string path);
    void SetReadOnly(bool readOnly);
    void SetStorageMode(StorageMode storageMode);
    void SetDatabaseFileType(DatabaseFileType type);
    void SetEncryptKey(const std::vector<uint8_t> &encryptKey);
    void SetSecurityLevel(const int32_t& secLevel);
    void ClearEncryptKey();

    // distributed rdb
    int SetBundleName(const std::string &bundleName);
    std::string GetBundleName() const;
    void SetModuleName(const std::string& moduleName);
    std::string GetModuleName() const;
    void SetServiceName(const std::string& serviceName);
    void SetArea(int32_t area);
    int32_t GetArea() const;
    std::string GetUri() const;
    void SetUri(const std::string& uri);
    std::string GetReadPermission() const;
    void SetReadPermission(const std::string& permission);
    std::string GetWritePermission() const;
    void SetWritePermission(const std::string& permission);

    static std::string GetJournalModeValue(JournalMode journalMode);
    static std::string GetSyncModeValue(SyncMode syncMode);
    static std::string GetDatabaseFileTypeValue(DatabaseFileType databaseFileType);
    static std::string GetDatabaseFileSecurityLevelValue(DatabaseFileSecurityLevel databaseFileSecurityLevel);
    bool IsAutoCheck() const;
    void SetAutoCheck(bool autoCheck);
    int GetJournalSize() const;
    void SetJournalSize(int journalSize);
    int GetPageSize() const;
    void SetPageSize(int pageSize);
    const std::string GetEncryptAlgo() const;
    void SetEncryptAlgo(const std::string &encryptAlgo);

private:
    std::string name;
    std::string path;
    StorageMode storageMode;
    std::string journalMode;
    std::string syncMode;
    std::vector<uint8_t> encryptKey;
    bool readOnly;
    std::string databaseFileType;
    std::string databaseFileSecurityLevel;

    int32_t area_ = 0;
    std::string bundleName_;
    std::string moduleName_;

    bool isEncrypt_ = false;
    int32_t securityLevel_ = 0;
    std::string uri_;
    std::string readPermission_;
    std::string writePermission_;

    bool autoCheck;
    int journalSize;
    int pageSize;
    std::string encryptAlgo;
};
} // namespace OHOS::NativeRdb

#endif
