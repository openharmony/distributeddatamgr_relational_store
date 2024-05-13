/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#define LOG_TAG "SqliteConnection"
#include "sqlite_connection.h"

#include <cerrno>
#include <memory>
#include <sqlite3sym.h>
#include <sstream>
#include <string>
#include <sys/stat.h>

#include "sqlite3.h"
#include "value_object.h"

#ifdef RDB_SUPPORT_ICU
#include <unicode/ucol.h>
#endif

#include <unistd.h>

#include "file_ex.h"
#include "logger.h"
#include "raw_data_parser.h"
#include "rdb_errno.h"
#include "relational_store_client.h"
#include "sqlite_errno.h"
#include "sqlite_global_config.h"
#include "sqlite_utils.h"
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
#include "rdb_security_manager.h"
#include "relational/relational_store_sqlite_ext.h"
#endif

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using namespace std::chrono;

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
using RdbKeyFile = RdbSecurityManager::KeyFileType;
#endif

__attribute__((used))
const int32_t SqliteConnection::g_reg = Connection::RegisterCreator(DB_SQLITE, SqliteConnection::Create);

std::pair<int32_t, std::shared_ptr<Connection>> SqliteConnection::Create(const RdbStoreConfig &config, bool isWrite)
{
    std::pair<int32_t, std::shared_ptr<Connection>> result;
    auto &[errCode, conn] = result;
    for (size_t i = 0; i < ITERS_COUNT; i++) {
        std::shared_ptr<SqliteConnection> connection(new (std::nothrow) SqliteConnection(isWrite));
        if (connection == nullptr) {
            LOG_ERROR("SqliteConnection::Open new failed, connection is nullptr");
            break;
        }
        errCode = connection->InnerOpen(config, i);
        if (errCode == E_OK) {
            conn = connection;
            break;
        }
    }
    return result;
}

SqliteConnection::SqliteConnection(bool isWriteConnection)
    : dbHandle(nullptr), isWriter_(isWriteConnection), isReadOnly(false), openFlags(0), maxVariableNumber_(0),
      filePath("")
{
}

int SqliteConnection::InnerOpen(const RdbStoreConfig &config, uint32_t retry)
{
    std::string dbPath;
    auto ret = SqliteGlobalConfig::GetDbPath(config, dbPath);
    if (ret != E_OK) {
        return ret;
    }

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    bool isDbFileExist = access(dbPath.c_str(), F_OK) == 0;
    if (!isDbFileExist && (!config.IsCreateNecessary())) {
        LOG_ERROR("SqliteConnection InnerOpen db not exist");
        return E_DB_NOT_EXIST;
    }
#endif
    isReadOnly = !isWriter_ || config.IsReadOnly();
    int openFileFlags = config.IsReadOnly() ? (SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX)
                                            : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
    int errCode = sqlite3_open_v2(dbPath.c_str(), &dbHandle, openFileFlags, nullptr);
    if (errCode != SQLITE_OK) {
        LOG_ERROR("SqliteConnection InnerOpen fail to open database err = %{public}d", errCode);
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
        auto const pos = dbPath.find_last_of("\\/");
        if (pos != std::string::npos) {
            std::string filepath = dbPath.substr(0, pos);
            if (access(filepath.c_str(), F_OK | W_OK) != 0) {
                LOG_ERROR("The path to the database file to be created is not valid, err = %{public}d", errno);
                return E_INVALID_FILE_PATH;
            }
        }
#endif
        return SQLiteError::ErrNo(errCode);
    }
    maxVariableNumber_ = sqlite3_limit(dbHandle, SQLITE_LIMIT_VARIABLE_NUMBER, -1);
    errCode = Configure(config, retry, dbPath);
    isConfigured_ = true;
    if (errCode != E_OK) {
        return errCode;
    }

    if (isWriter_) {
        TryCheckPoint();
    }

    filePath = dbPath;
    openFlags = openFileFlags;

    return E_OK;
}

int SqliteConnection::SetCustomFunctions(const RdbStoreConfig &config)
{
    customScalarFunctions_ = config.GetScalarFunctions();
    for (auto &it : customScalarFunctions_) {
        int errCode = SetCustomScalarFunction(it.first, it.second.argc_, &it.second.function_);
        if (errCode != E_OK) {
            return errCode;
        }
    }
    return E_OK;
}

static void CustomScalarFunctionCallback(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    if (ctx == nullptr || argv == nullptr) {
        LOG_ERROR("ctx or argv is nullptr");
        return;
    }
    auto function = static_cast<ScalarFunction *>(sqlite3_user_data(ctx));
    if (function == nullptr) {
        LOG_ERROR("function is nullptr");
        return;
    }

    std::vector<std::string> argsVector;
    for (int i = 0; i < argc; ++i) {
        auto arg = reinterpret_cast<const char *>(sqlite3_value_text(argv[i]));
        if (arg == nullptr) {
            LOG_ERROR("arg is nullptr, index is %{public}d", i);
            sqlite3_result_null(ctx);
            return;
        }
        argsVector.emplace_back(std::string(arg));
    }

    std::string result = (*function)(argsVector);
    if (result.empty()) {
        sqlite3_result_null(ctx);
        return;
    }
    sqlite3_result_text(ctx, result.c_str(), -1, SQLITE_TRANSIENT);
}

int SqliteConnection::SetCustomScalarFunction(const std::string &functionName, int argc, ScalarFunction *function)
{
    int err = sqlite3_create_function_v2(dbHandle, functionName.c_str(), argc, SQLITE_UTF8, function,
        &CustomScalarFunctionCallback, nullptr, nullptr, nullptr);
    if (err != SQLITE_OK) {
        LOG_ERROR("SetCustomScalarFunction errCode is %{public}d", err);
    }
    return err;
}

int SqliteConnection::Configure(const RdbStoreConfig &config, uint32_t retry, std::string &dbPath)
{
    if (retry >= ITERS_COUNT) {
        return E_INVALID_ARGS;
    }

    if (config.GetStorageMode() == StorageMode::MODE_MEMORY) {
        return E_OK;
    }

    if (config.GetRoleType() == VISITOR) {
        return E_OK;
    }

    auto errCode = RegDefaultFunctions(dbHandle);
    if (errCode != E_OK) {
        return errCode;
    }

    SetBusyTimeout(DEFAULT_BUSY_TIMEOUT_MS);

    LimitPermission(dbPath);

    errCode = SetPersistWal();
    if (errCode != E_OK) {
        return errCode;
    }

    errCode = SetPageSize(config);
    if (errCode != E_OK) {
        return errCode;
    }

    errCode = SetEncryptKey(config, ITERS[retry]);
    if (errCode != E_OK) {
        return errCode;
    }

    errCode = SetJournalMode(config);
    if (errCode != E_OK) {
        return errCode;
    }

    errCode = SetJournalSizeLimit(config);
    if (errCode != E_OK) {
        return errCode;
    }

    errCode = SetAutoCheckpoint(config);
    if (errCode != E_OK) {
        return errCode;
    }

    errCode = SetCustomFunctions(config);
    if (errCode != E_OK) {
        return errCode;
    }

    return E_OK;
}

SqliteConnection::~SqliteConnection()
{
    if (dbHandle != nullptr) {
        if (hasClientObserver_) {
            UnRegisterClientObserver(dbHandle);
        }
        if (isWriter_) {
            UnregisterStoreObserver(dbHandle);
        }

        int errCode = sqlite3_close_v2(dbHandle);
        if (errCode != SQLITE_OK) {
            LOG_ERROR("SqliteConnection ~SqliteConnection: could not close database err = %{public}d", errCode);
        }
    }
}

int32_t SqliteConnection::OnInitialize()
{
    return 0;
}

std::pair<int, std::shared_ptr<Statement>> SqliteConnection::CreateStatement(const std::string &sql,
    std::shared_ptr<Connection> conn)
{
    sqlite3_stmt *stmt = nullptr;
    int errCode = sqlite3_prepare_v2(dbHandle, sql.c_str(), sql.length(), &stmt, nullptr);
    if (errCode != SQLITE_OK) {
        auto time = static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
        LOG_ERROR("prepare_v2 ret is %{public}d %{public}" PRIu64 ".", errCode, time);
        if (stmt != nullptr) {
            sqlite3_finalize(stmt);
        }
        return { SQLiteError::ErrNo(errCode), nullptr };
    }
    std::shared_ptr<SqliteStatement> statement = std::make_shared<SqliteStatement>();
    statement->stmt_ = stmt;
    statement->sql_ = sql;
    statement->readOnly_ = (sqlite3_stmt_readonly(stmt) != 0);
    statement->columnCount_ = sqlite3_column_count(stmt);
    statement->numParameters_ = sqlite3_bind_parameter_count(stmt);
    statement->types_ = std::vector<int32_t>(statement->columnCount_, 0);
    statement->conn_ = conn;
    return { E_OK, statement };
}

bool SqliteConnection::IsWriter() const
{
    return isWriter_;
}

int SqliteConnection::SubscribeTableChanges(const Connection::Notifier &notifier)
{
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    if (!isWriter_ || notifier == nullptr) {
        return E_OK;
    }
    hasClientObserver_ = true;
    int32_t status = RegisterClientObserver(dbHandle, [notifier](const ClientChangedData &clientData) {
        std::set<std::string> tables;
        for (auto &[key, val] : clientData.tableData) {
            if (val.isTrackedDataChange) {
                tables.insert(key);
            }
        }
        notifier(tables);
    });
    if (status != E_OK) {
        LOG_ERROR("RegisterClientObserver error, status:%{public}d", status);
    }
    return status;
#endif
    return E_OK;
}

int SqliteConnection::GetMaxVariable() const
{
    return maxVariableNumber_;
}

int32_t SqliteConnection::GetJournalMode()
{
    return (int32_t)mode_;
}

int32_t SqliteConnection::GetDBType() const
{
    return DB_SQLITE;
}

int SqliteConnection::SetPageSize(const RdbStoreConfig &config)
{
    if (isReadOnly || config.GetPageSize() == GlobalExpr::DB_PAGE_SIZE) {
        return E_OK;
    }

    int targetValue = config.GetPageSize();
    int64_t value = 0;
    int errCode = ExecuteGetLong(value, "PRAGMA page_size");
    if (errCode != E_OK) {
        LOG_ERROR("SqliteConnection SetPageSize fail to get page size : %{public}d", errCode);
        return errCode;
    }

    if (value == targetValue) {
        return E_OK;
    }

    errCode = ExecuteSql("PRAGMA page_size=" + std::to_string(targetValue));
    if (errCode != E_OK) {
        LOG_ERROR("SqliteConnection SetPageSize fail to set page size : %{public}d", errCode);
    }
    return errCode;
}

int SqliteConnection::ExecuteEncryptSql(const RdbStoreConfig &config, uint32_t iter)
{
    int errCode = E_ERROR;
    if (iter != NO_ITER) {
        errCode = ExecuteSql(GlobalExpr::CIPHER_DEFAULT_ALGO);
        if (errCode != E_OK) {
            LOG_ERROR("set cipher algo failed, err = %{public}d", errCode);
            return errCode;
        }
        errCode = ExecuteSql(std::string(GlobalExpr::CIPHER_KDF_ITER) + std::to_string(iter));
        if (errCode != E_OK) {
            LOG_ERROR("set kdf iter number V1 failed, err = %{public}d", errCode);
            return errCode;
        }
    }

    errCode = ExecuteSql(GlobalExpr::CODEC_HMAC_ALGO);
    if (errCode != E_OK) {
        LOG_ERROR("set codec hmac algo failed, err = %{public}d", errCode);
        return errCode;
    }

    errCode = ExecuteSql(GlobalExpr::CODEC_REKEY_HMAC_ALGO);
    if (errCode != E_OK) {
        LOG_ERROR("set rekey sha algo failed, err = %{public}d", errCode);
        return errCode;
    }

    std::string version;
    errCode = ExecuteGetString(version, GlobalExpr::PRAGMA_VERSION);
    if (errCode != E_OK || version.empty()) {
        LOG_ERROR("test failed, iter = %{public}d, err = %{public}d, name = %{public}s", iter, errCode,
            config.GetName().c_str());
        return errCode;
    }

    return errCode;
}

int SqliteConnection::ReSetKey(const RdbStoreConfig &config)
{
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    auto rdbPwd = RdbSecurityManager::GetInstance().GetRdbPassword(config.GetPath(), RdbKeyFile::PUB_KEY_FILE_NEW_KEY);
    if (!rdbPwd.IsValid()) {
        RdbSecurityManager::GetInstance().DelRdbSecretDataFile(config.GetPath(), RdbKeyFile::PUB_KEY_FILE_NEW_KEY);
        LOG_ERROR("new key is not valid.");
        return E_OK;
    }

    auto key = std::vector<uint8_t>(rdbPwd.GetData(), rdbPwd.GetData() + rdbPwd.GetSize());
    int errCode = sqlite3_rekey(dbHandle, static_cast<const void *>(key.data()), static_cast<int>(key.size()));
    key.assign(key.size(), 0);
    if (errCode != SQLITE_OK) {
        LOG_ERROR("ReKey failed, err = %{public}d", errCode);
        RdbSecurityManager::GetInstance().DelRdbSecretDataFile(config.GetPath(), RdbKeyFile::PUB_KEY_FILE_NEW_KEY);
        return E_OK;
    }

    RdbSecurityManager::GetInstance().UpdateKeyFile(config.GetPath());
#endif
    return E_OK;
}

std::string SqliteConnection::GetSecManagerName(const RdbStoreConfig &config)
{
    auto name = config.GetBundleName();
    if (name.empty()) {
        LOG_WARN("Bundle name is empty, using path instead.");
        return std::string(config.GetPath()).substr(0, config.GetPath().rfind("/") + 1);
    }
    return name;
}

int SqliteConnection::SetEncryptKey(const RdbStoreConfig &config, uint32_t iter)
{
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    std::vector<uint8_t> key = config.GetEncryptKey();
    bool isKeyExpired = false;
    int32_t errCode = E_OK;
    if (config.IsEncrypt()) {
        errCode = RdbSecurityManager::GetInstance().Init(GetSecManagerName(config));
        if (errCode != E_OK) {
            key.assign(key.size(), 0);
            return errCode;
        }
        auto rdbPwd = RdbSecurityManager::GetInstance().GetRdbPassword(config.GetPath(), RdbKeyFile::PUB_KEY_FILE);
        key.assign(key.size(), 0);
        key = std::vector<uint8_t>(rdbPwd.GetData(), rdbPwd.GetData() + rdbPwd.GetSize());
        isKeyExpired = rdbPwd.isKeyExpired;
    } else if (key.empty()) {
        return E_OK;
    }

    errCode = sqlite3_key(dbHandle, static_cast<const void *>(key.data()), static_cast<int>(key.size()));
    key.assign(key.size(), 0);
    if (errCode != SQLITE_OK) {
        if (RdbSecurityManager::GetInstance().IsKeyFileExists(config.GetPath(), RdbKeyFile::PUB_KEY_FILE_NEW_KEY)) {
            auto rdbPwd =
                RdbSecurityManager::GetInstance().GetRdbPassword(config.GetPath(), RdbKeyFile::PUB_KEY_FILE_NEW_KEY);
            key = std::vector<uint8_t>(rdbPwd.GetData(), rdbPwd.GetData() + rdbPwd.GetSize());
            errCode = sqlite3_key(dbHandle, static_cast<const void *>(key.data()), static_cast<int>(key.size()));
            key.assign(key.size(), 0);
            if (errCode != SQLITE_OK) {
                LOG_ERROR("SqliteConnection SetEncryptKey fail with new key, err = %{public}d", errCode);
                return SQLiteError::ErrNo(errCode);
            }
            RdbSecurityManager::GetInstance().UpdateKeyFile(config.GetPath());
        }
        if (errCode != SQLITE_OK) {
            LOG_ERROR("SqliteConnection SetEncryptKey fail, err = %{public}d", errCode);
            return SQLiteError::ErrNo(errCode);
        }
    }

    errCode = ExecuteEncryptSql(config, iter);
    if (errCode != E_OK) {
        LOG_ERROR("execute encrypt sql failed, err = %{public}d", errCode);
        return errCode;
    }

    if (isKeyExpired) {
        ReSetKey(config);
    }
#endif
    return E_OK;
}

int SqliteConnection::SetPersistWal()
{
    int opcode = 1;
    int errCode = sqlite3_file_control(dbHandle, "main", SQLITE_FCNTL_PERSIST_WAL, &opcode);
    if (errCode != SQLITE_OK) {
        LOG_ERROR("failed");
        return E_SET_PERSIST_WAL;
    }
    return E_OK;
}

int SqliteConnection::SetBusyTimeout(int timeout)
{
    auto errCode = sqlite3_busy_timeout(dbHandle, timeout);
    if (errCode != SQLITE_OK) {
        LOG_ERROR("set buys timeout failed, errCode=%{public}d", errCode);
        return errCode;
    }
    return E_OK;
}

int SqliteConnection::RegDefaultFunctions(sqlite3 *dbHandle)
{
    if (dbHandle == nullptr) {
        return SQLITE_OK;
    }
    // The number of parameters is 2
    return sqlite3_create_function_v2(dbHandle, MERGE_ASSETS_FUNC, 2, SQLITE_UTF8 | SQLITE_DETERMINISTIC, nullptr,
        &MergeAssets, nullptr, nullptr, nullptr);
}

int SqliteConnection::SetJournalMode(const RdbStoreConfig &config)
{
    if (isReadOnly) {
        return E_OK;
    }
    std::string currentMode;
    int errCode = ExecuteGetString(currentMode, "PRAGMA journal_mode");
    if (errCode != E_OK) {
        LOG_ERROR("SqliteConnection SetJournalMode fail to get journal mode : %{public}d", errCode);
        return errCode;
    }

    if (config.GetJournalMode().compare(currentMode) == 0) {
        return E_OK;
    }

    currentMode = SqliteUtils::StrToUpper(currentMode);
    if (currentMode != config.GetJournalMode()) {
        std::string result;
        int errorCode = ExecuteGetString(result, "PRAGMA journal_mode=" + config.GetJournalMode());
        if (errorCode != E_OK) {
            LOG_ERROR("SqliteConnection SetJournalMode: fail to set journal mode err=%{public}d", errorCode);
            return errorCode;
        }

        if (SqliteUtils::StrToUpper(result) != config.GetJournalMode()) {
            LOG_ERROR("SqliteConnection SetJournalMode: result incorrect");
            return E_EXECUTE_RESULT_INCORRECT;
        }
    }

    if (config.GetJournalMode() == "WAL") {
        errCode = SetWalSyncMode(config.GetSyncMode());
    }
    if (config.GetJournalMode() == "TRUNCATE") {
        mode_ = JournalMode::MODE_TRUNCATE;
    }
    return errCode;
}

int SqliteConnection::SetJournalSizeLimit(const RdbStoreConfig &config)
{
    if (isReadOnly || config.GetJournalSize() == GlobalExpr::DB_JOURNAL_SIZE) {
        return E_OK;
    }

    int targetValue = SqliteGlobalConfig::GetJournalFileSize();
    int64_t currentValue = 0;
    int errCode = ExecuteGetLong(currentValue, "PRAGMA journal_size_limit");
    if (errCode != E_OK) {
        LOG_ERROR("SqliteConnection SetJournalSizeLimit fail to get journal_size_limit : %{public}d", errCode);
        return errCode;
    }

    if (currentValue == targetValue) {
        return E_OK;
    }

    int64_t result;
    errCode = ExecuteGetLong(result, "PRAGMA journal_size_limit=" + std::to_string(targetValue));
    if (errCode != E_OK) {
        LOG_ERROR("SqliteConnection SetJournalSizeLimit fail to set journal_size_limit : %{public}d", errCode);
    }
    return errCode;
}

int SqliteConnection::SetAutoCheckpoint(const RdbStoreConfig &config)
{
    if (isReadOnly || config.IsAutoCheck() == GlobalExpr::DB_AUTO_CHECK) {
        return E_OK;
    }

    int targetValue = SqliteGlobalConfig::GetWalAutoCheckpoint();
    int64_t value = 0;
    int errCode = ExecuteGetLong(value, "PRAGMA wal_autocheckpoint");
    if (errCode != E_OK) {
        LOG_ERROR("SqliteConnection SetAutoCheckpoint fail to get wal_autocheckpoint : %{public}d", errCode);
        return errCode;
    }

    if (value == targetValue) {
        return E_OK;
    }

    int64_t result;
    errCode = ExecuteGetLong(result, "PRAGMA wal_autocheckpoint=" + std::to_string(targetValue));
    if (errCode != E_OK) {
        LOG_ERROR("SqliteConnection SetAutoCheckpoint fail to set wal_autocheckpoint : %{public}d", errCode);
    }
    return errCode;
}

int SqliteConnection::SetWalSyncMode(const std::string &syncMode)
{
    std::string targetValue = SqliteGlobalConfig::GetSyncMode();
    if (syncMode.length() != 0) {
        targetValue = syncMode;
    }

    std::string value;
    int errCode = ExecuteGetString(value, "PRAGMA synchronous");
    if (errCode != E_OK) {
        LOG_ERROR("SqliteConnection setWalSyncMode fail to get synchronous mode : %{public}d", errCode);
        return errCode;
    }

    value = SqliteUtils::StrToUpper(value);
    if (value == targetValue) {
        return E_OK;
    }

    errCode = ExecuteSql("PRAGMA synchronous=" + targetValue);
    if (errCode != E_OK) {
        LOG_ERROR("SqliteConnection setWalSyncMode fail to set synchronous mode : %{public}d", errCode);
    }
    return errCode;
}

int SqliteConnection::ExecuteSql(const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    auto [errCode, statement] = CreateStatement(sql, nullptr);
    if (statement == nullptr || errCode != E_OK) {
        return errCode;
    }
    return statement->Execute(bindArgs);
}

int SqliteConnection::ExecuteGetLong(int64_t &outValue, const std::string &sql,
    const std::vector<ValueObject> &bindArgs)
{
    auto [errCode, statement] = CreateStatement(sql, nullptr);
    if (statement == nullptr || errCode != E_OK) {
        return errCode;
    }
    ValueObject object;
    std::tie(errCode, object) = statement->ExecuteForValue(bindArgs);
    if (errCode != E_OK) {
        LOG_ERROR("failed, %{public}d sql:%{public}s, args size:%{public}zu", SQLiteError::ErrNo(errCode), sql.c_str(),
            bindArgs.size());
    }
    outValue = object;
    return errCode;
}

int SqliteConnection::ExecuteGetString(std::string &outValue, const std::string &sql,
    const std::vector<ValueObject> &bindArgs)
{
    auto [errCode, statement] = CreateStatement(sql, nullptr);
    if (statement == nullptr || errCode != E_OK) {
        return errCode;
    }
    ValueObject object;
    std::tie(errCode, object) = statement->ExecuteForValue(bindArgs);
    if (errCode != E_OK) {
        LOG_ERROR("failed, %{public}d sql:%{public}s, args size:%{public}zu", SQLiteError::ErrNo(errCode), sql.c_str(),
            bindArgs.size());
    }
    outValue = static_cast<std::string>(object);
    return errCode;
}

int SqliteConnection::ClearCache()
{
    if (dbHandle != nullptr && mode_ == JournalMode::MODE_WAL) {
        sqlite3_db_release_memory(dbHandle);
    }
    return E_OK;
}

void SqliteConnection::LimitPermission(const std::string &dbPath) const
{
    struct stat st = { 0 };
    if (stat(dbPath.c_str(), &st) == 0) {
        if ((st.st_mode & (S_IXUSR | S_IXGRP | S_IRWXO)) != 0) {
            int ret = chmod(dbPath.c_str(), st.st_mode & (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP));
            if (ret != 0) {
                LOG_DEBUG("SqliteConnection LimitPermission chmod fail, err = %{public}d", errno);
            }
        }
    } else {
        LOG_ERROR("SqliteConnection LimitPermission stat fail, err = %{public}d", errno);
    }
}

#ifdef RDB_SUPPORT_ICU
int Collate8Compare(void *p, int n1, const void *v1, int n2, const void *v2)
{
    UCollator *coll = reinterpret_cast<UCollator *>(p);
    UCharIterator i1;
    UCharIterator i2;
    UErrorCode status = U_ZERO_ERROR;

    uiter_setUTF8(&i1, (const char *)v1, n1);
    uiter_setUTF8(&i2, (const char *)v2, n2);

    UCollationResult result = ucol_strcollIter(coll, &i1, &i2, &status);

    if (U_FAILURE(status)) {
        LOG_ERROR("Ucol strcoll error.");
    }

    if (result == UCOL_LESS) {
        return -1;
    } else if (result == UCOL_GREATER) {
        return 1;
    }
    return 0;
}

void LocalizedCollatorDestroy(UCollator *collator)
{
    ucol_close(collator);
}
#endif

/**
 * The database locale.
 */
int SqliteConnection::ConfigLocale(const std::string &localeStr)
{
#ifdef RDB_SUPPORT_ICU
    std::unique_lock<std::mutex> lock(mutex_);
    UErrorCode status = U_ZERO_ERROR;
    UCollator *collator = ucol_open(localeStr.c_str(), &status);
    if (U_FAILURE(status)) {
        LOG_ERROR("Can not open collator.");
        return E_ERROR;
    }
    ucol_setAttribute(collator, UCOL_STRENGTH, UCOL_PRIMARY, &status);
    if (U_FAILURE(status)) {
        LOG_ERROR("Set attribute of collator failed.");
        return E_ERROR;
    }

    int err = sqlite3_create_collation_v2(dbHandle, "LOCALES", SQLITE_UTF8, collator, Collate8Compare,
        (void (*)(void *))LocalizedCollatorDestroy);
    if (err != SQLITE_OK) {
        LOG_ERROR("SCreate collator in sqlite3 failed.");
        return err;
    }
#endif
    return E_OK;
}

int SqliteConnection::CleanDirtyData(const std::string &table, uint64_t cursor)
{
    if (table.empty()) {
        return E_ERROR;
    }
    uint64_t tmpCursor = cursor == UINT64_MAX ? 0 : cursor;
    auto status = DropLogicDeletedData(dbHandle, table, tmpCursor);
    return status == DistributedDB::DBStatus::OK ? E_OK : E_ERROR;
}

int SqliteConnection::TryCheckPoint()
{
    if (!isWriter_) {
        return E_NOT_SUPPORT;
    }

    std::string walName = sqlite3_filename_wal(sqlite3_db_filename(dbHandle, "main"));
    int fileSize = SqliteUtils::GetFileSize(walName);
    if (fileSize <= GlobalExpr::DB_WAL_SIZE_LIMIT_MIN) {
        return E_OK;
    }
    int errCode = sqlite3_wal_checkpoint_v2(dbHandle, nullptr, SQLITE_CHECKPOINT_TRUNCATE, nullptr, nullptr);
    if (errCode != SQLITE_OK) {
        LOG_WARN("sqlite3_wal_checkpoint_v2 failed err %{public}d.", errCode);
        return E_ERROR;
    }
    return E_OK;
}

int SqliteConnection::LimitWalSize()
{
    if (!isConfigured_ || !isWriter_) {
        return E_OK;
    }

    std::string walName = sqlite3_filename_wal(sqlite3_db_filename(dbHandle, "main"));
    int fileSize = SqliteUtils::GetFileSize(walName);
    if (fileSize > GlobalExpr::DB_WAL_SIZE_LIMIT_MAX) {
        LOG_ERROR("the WAL file size over default limit, %{public}s size is %{public}d",
            SqliteUtils::Anonymous(walName).c_str(), fileSize);
        return E_WAL_SIZE_OVER_LIMIT;
    }
    return E_OK;
}

void SqliteConnection::MergeAssets(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    // 2 is the number of parameters
    if (ctx == nullptr || argc != 2 || argv == nullptr) {
        LOG_ERROR("Parameter does not meet restrictions.");
        return;
    }
    std::map<std::string, ValueObject::Asset> assets;
    auto data = static_cast<const uint8_t *>(sqlite3_value_blob(argv[0]));
    if (data != nullptr) {
        int len = sqlite3_value_bytes(argv[0]);
        RawDataParser::ParserRawData(data, len, assets);
    }
    std::map<std::string, ValueObject::Asset> newAssets;
    data = static_cast<const uint8_t *>(sqlite3_value_blob(argv[1]));
    if (data != nullptr) {
        int len = sqlite3_value_bytes(argv[1]);
        RawDataParser::ParserRawData(data, len, newAssets);
    }
    CompAssets(assets, newAssets);
    auto blob = RawDataParser::PackageRawData(assets);
    sqlite3_result_blob(ctx, blob.data(), blob.size(), SQLITE_TRANSIENT);
}

void SqliteConnection::CompAssets(std::map<std::string, ValueObject::Asset> &assets,
    std::map<std::string, ValueObject::Asset> &newAssets)
{
    using Status = ValueObject::Asset::Status;
    auto oldIt = assets.begin();
    auto newIt = newAssets.begin();
    for (; oldIt != assets.end() && newIt != newAssets.end();) {
        if (oldIt->first == newIt->first) {
            if (newIt->second.status == Status::STATUS_DELETE) {
                oldIt->second.status = Status::STATUS_DELETE;
                oldIt->second.hash = "";
                oldIt->second.modifyTime = "";
                oldIt->second.size = "";
            } else {
                MergeAsset(oldIt->second, newIt->second);
            }
            oldIt++;
            newIt = newAssets.erase(newIt);
            continue;
        }
        if (oldIt->first < newIt->first) {
            ++oldIt;
            continue;
        }
        newIt++;
    }
    for (auto &[key, value] : newAssets) {
        value.status = ValueObject::Asset::Status::STATUS_INSERT;
        assets.insert(std::pair{ key, std::move(value) });
    }
}

void SqliteConnection::MergeAsset(ValueObject::Asset &oldAsset, ValueObject::Asset &newAsset)
{
    using Status = ValueObject::Asset::Status;
    auto status = static_cast<int32_t>(oldAsset.status);
    switch (status) {
        case Status::STATUS_UNKNOWN:  // fallthrough
        case Status::STATUS_NORMAL:   // fallthrough
        case Status::STATUS_ABNORMAL: // fallthrough
        case Status::STATUS_INSERT:   // fallthrough
        case Status::STATUS_UPDATE:   // fallthrough
            if (oldAsset.modifyTime != newAsset.modifyTime || oldAsset.size != newAsset.size ||
                oldAsset.uri != newAsset.uri || oldAsset.path != newAsset.path) {
                if (oldAsset.modifyTime != newAsset.modifyTime || oldAsset.size != newAsset.size ||
                    oldAsset.uri == newAsset.uri || oldAsset.path == newAsset.path) {
                    oldAsset.expiresTime = newAsset.expiresTime;
                    oldAsset.hash = newAsset.hash;
                    oldAsset.status = Status::STATUS_UPDATE;
                }
                oldAsset.version = newAsset.version;
                oldAsset.uri = newAsset.uri;
                oldAsset.createTime = newAsset.createTime;
                oldAsset.modifyTime = newAsset.modifyTime;
                oldAsset.size = newAsset.size;
                oldAsset.path = newAsset.path;
            }
            return;
        default:
            return;
    }
}

int32_t SqliteConnection::Subscribe(const std::string &event, const std::shared_ptr<RdbStoreObserver> &observer)
{
    if (!isWriter_ || observer == nullptr) {
        return E_OK;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    rdbStoreLocalDbObservers_.try_emplace(event);
    auto &list = rdbStoreLocalDbObservers_.find(event)->second;
    for (auto it = list.begin(); it != list.end(); it++) {
        if ((*it)->GetObserver() == observer) {
            LOG_ERROR("duplicate subscribe");
            return E_OK;
        }
    }
    auto localStoreObserver = std::make_shared<RdbStoreLocalDbObserver>(observer);
    int32_t errCode = RegisterStoreObserver(dbHandle, localStoreObserver);
    if (errCode != E_OK) {
        LOG_ERROR("subscribe failed.");
        return errCode;
    }
    rdbStoreLocalDbObservers_[event].push_back(std::move(localStoreObserver));
    return E_OK;
}

int32_t SqliteConnection::Unsubscribe(const std::string &event, const std::shared_ptr<RdbStoreObserver> &observer)
{
    if (!isWriter_) {
        return E_OK;
    }
    if (observer) {
        return UnsubscribeLocalDetail(event, observer);
    }
    return UnsubscribeLocalDetailAll(event);
}

int32_t SqliteConnection::UnsubscribeLocalDetail(const std::string &event,
    const std::shared_ptr<RdbStoreObserver> &observer)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto observers = rdbStoreLocalDbObservers_.find(event);
    if (observers == rdbStoreLocalDbObservers_.end()) {
        return E_OK;
    }

    auto &list = observers->second;
    for (auto it = list.begin(); it != list.end(); it++) {
        if ((*it)->GetObserver() == observer) {
            int32_t err = UnregisterStoreObserver(dbHandle, *it);
            if (err != 0) {
                LOG_ERROR("unsubscribeLocalShared failed.");
                return err;
            }
            list.erase(it);
            break;
        }
    }
    if (list.empty()) {
        rdbStoreLocalDbObservers_.erase(event);
    }
    return E_OK;
}

int32_t SqliteConnection::UnsubscribeLocalDetailAll(const std::string &event)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto observers = rdbStoreLocalDbObservers_.find(event);
    if (observers == rdbStoreLocalDbObservers_.end()) {
        return E_OK;
    }

    auto &list = observers->second;
    auto it = list.begin();
    while (it != list.end()) {
        int32_t err = UnregisterStoreObserver(dbHandle, *it);
        if (err != 0) {
            LOG_ERROR("unsubscribe failed.");
            return err;
        }
        it = list.erase(it);
    }

    rdbStoreLocalDbObservers_.erase(event);
    return E_OK;
}
} // namespace NativeRdb
} // namespace OHOS
