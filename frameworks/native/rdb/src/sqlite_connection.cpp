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

#include <dlfcn.h>
#include <sqlite3sym.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <memory>
#include <sstream>
#include <string>

#include "logger.h"
#include "raw_data_parser.h"
#include "rdb_errno.h"
#include "rdb_fault_hiview_reporter.h"
#include "rdb_security_manager.h"
#include "rdb_sql_statistic.h"
#include "rdb_store_config.h"
#include "relational_store_client.h"
#include "sqlite3.h"
#include "sqlite_errno.h"
#include "sqlite_default_function.h"
#include "sqlite_global_config.h"
#include "sqlite_utils.h"
#include "value_object.h"
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
#include "rdb_manager_impl.h"
#include "relational/relational_store_sqlite_ext.h"
#endif
#include "task_executor.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using namespace std::chrono;
using RdbKeyFile = RdbSecurityManager::KeyFileType;
using Reportor = RdbFaultHiViewReporter;
constexpr const char *INTEGRITIES[] = { nullptr, "PRAGMA quick_check", "PRAGMA integrity_check" };
constexpr SqliteConnection::Suffix SqliteConnection::FILE_SUFFIXES[];
constexpr int SqliteConnection::DEFAULT_BUSY_TIMEOUT_MS;
constexpr int SqliteConnection::BACKUP_PAGES_PRE_STEP; // 1024 * 4 * 12800 == 50m
constexpr int SqliteConnection::BACKUP_PRE_WAIT_TIME;
constexpr ssize_t SqliteConnection::SLAVE_WAL_SIZE_LIMIT;
constexpr ssize_t SqliteConnection::SLAVE_INTEGRITY_CHECK_LIMIT;
constexpr uint32_t SqliteConnection::NO_ITER;
constexpr uint32_t SqliteConnection::DB_INDEX;
constexpr uint32_t SqliteConnection::WAL_INDEX;
constexpr uint32_t SqliteConnection::ITER_V1;
constexpr uint32_t SqliteConnection::SQLITE_CKSUMVFS_RESERVE_BYTES;
__attribute__((used))
const int32_t SqliteConnection::regCreator_ = Connection::RegisterCreator(DB_SQLITE, SqliteConnection::Create);
__attribute__((used))
const int32_t SqliteConnection::regRepairer_ = Connection::RegisterRepairer(DB_SQLITE, SqliteConnection::Repair);
__attribute__((used))
const int32_t SqliteConnection::regDeleter_ = Connection::RegisterDeleter(DB_SQLITE, SqliteConnection::Delete);
__attribute__((used))
const int32_t SqliteConnection::regCollector_ = Connection::RegisterCollector(DB_SQLITE, SqliteConnection::Collect);
__attribute__((used))
const int32_t SqliteConnection::regRestorer_ = Connection::RegisterRestorer(DB_SQLITE, SqliteConnection::Restore);

std::pair<int32_t, std::shared_ptr<Connection>> SqliteConnection::Create(const RdbStoreConfig &config, bool isWrite)
{
    std::pair<int32_t, std::shared_ptr<Connection>> result = { E_ERROR, nullptr };
    auto &[errCode, conn] = result;
    std::tie(errCode, conn) = InnerCreate(config, isWrite);
    return result;
}

int32_t SqliteConnection::Delete(const RdbStoreConfig &config)
{
    auto path = config.GetPath();
    auto slavePath = SqliteUtils::GetSlavePath(path);
    Delete(path);
    Delete(slavePath);
    return E_OK;
}

int32_t SqliteConnection::Delete(const std::string &path)
{
    for (const auto &suffix : FILE_SUFFIXES) {
        SqliteUtils::DeleteFile(path + suffix.suffix_);
    }
    return E_OK;
}

std::map<std::string, Connection::Info> SqliteConnection::Collect(const RdbStoreConfig &config)
{
    std::map<std::string, Connection::Info> collection;
    std::string path;
    SqliteGlobalConfig::GetDbPath(config, path);
    for (auto &suffix : FILE_SUFFIXES) {
        if (suffix.debug_ == nullptr) {
            continue;
        }
        auto file = path + suffix.suffix_;
        std::pair<int32_t, RdbDebugInfo> fileInfo = SqliteUtils::Stat(file);
        if (fileInfo.first == E_OK) {
            collection.insert(std::pair{ suffix.debug_, fileInfo.second });
        }
    }
    RdbSecurityManager::KeyFiles keyFiles(path);
    std::string keyPath =  keyFiles.GetKeyFile(RdbSecurityManager::PUB_KEY_FILE);
    std::pair<int32_t, RdbDebugInfo> fileInfo = SqliteUtils::Stat(keyPath);
    if (fileInfo.first == E_OK) {
        collection.insert(std::pair{ "key", fileInfo.second });
    }
    std::string newKeyPath = keyFiles.GetKeyFile(RdbSecurityManager::PUB_KEY_FILE_NEW_KEY);
    fileInfo = SqliteUtils::Stat(newKeyPath);
    if (fileInfo.first == E_OK) {
        collection.insert(std::pair{ "newKey", fileInfo.second });
    }
    return collection;
}

SqliteConnection::SqliteConnection(const RdbStoreConfig &config, bool isWriteConnection)
    : dbHandle_(nullptr), isWriter_(isWriteConnection), isReadOnly_(false), maxVariableNumber_(0), filePath(""),
      config_(config)
{
    backupId_ = TaskExecutor::INVALID_TASK_ID;
}

std::pair<int32_t, std::shared_ptr<SqliteConnection>> SqliteConnection::CreateSlaveConnection(
    const RdbStoreConfig &config, SlaveOpenPolicy slaveOpenPolicy)
{
    std::pair<int32_t, std::shared_ptr<SqliteConnection>> result = { E_ERROR, nullptr };
    auto &[errCode, conn] = result;
    std::map<std::string, DebugInfo> bugInfo = Connection::Collect(config);
    bool isSlaveExist = access(config.GetPath().c_str(), F_OK) == 0;
    bool isSlaveLockExist = SqliteUtils::IsSlaveInterrupted(config_.GetPath());
    bool hasFailure = SqliteUtils::IsSlaveInvalid(config_.GetPath());
    bool walOverLimit = bugInfo.find(FILE_SUFFIXES[WAL_INDEX].debug_) != bugInfo.end() &&
                        bugInfo[FILE_SUFFIXES[WAL_INDEX].debug_].size_ > SLAVE_WAL_SIZE_LIMIT;
    LOG_INFO("slave cfg:[%{public}d,%{public}d,%{public}d,%{public}d,%{public}d,%{public}d,%{public}d]%{public}s "
             "%{public}s,[%{public}d,%{public}d,%{public}d,%{public}d]",
        config.GetDBType(), config.GetHaMode(), config.IsEncrypt(), config.GetArea(), config.GetSecurityLevel(),
        config.GetRoleType(), config.IsReadOnly(),
        SqliteUtils::FormatDebugInfoBrief(bugInfo, SqliteUtils::Anonymous(config.GetName())).c_str(),
        SqliteUtils::FormatDebugInfoBrief(Connection::Collect(config_), "master").c_str(), isSlaveExist,
        isSlaveLockExist, hasFailure, walOverLimit);
    if (config.GetHaMode() == HAMode::MANUAL_TRIGGER && (slaveOpenPolicy == SlaveOpenPolicy::OPEN_IF_DB_VALID &&
        (!isSlaveExist || isSlaveLockExist || hasFailure || walOverLimit))) {
        if (walOverLimit) {
            SqliteUtils::SetSlaveInvalid(config_.GetPath());
            Reportor::ReportCorrupted(Reportor::Create(config, E_SQLITE_ERROR, "ErrorType: slaveWalOverLimit"));
        }
        return result;
    }

    std::shared_ptr<SqliteConnection> connection = std::make_shared<SqliteConnection>(config, true);
    errCode = connection->InnerOpen(config);
    if (errCode != E_OK) {
        SqliteUtils::SetSlaveInvalid(config_.GetPath());
        if (errCode == E_SQLITE_CORRUPT) {
            LOG_WARN("slave corrupt, rebuild:%{public}s", SqliteUtils::Anonymous(config.GetPath()).c_str());
            (void)Delete(config.GetPath());
            // trigger mode does not require rebuild the slave
            if (config.GetHaMode() == HAMode::MANUAL_TRIGGER) {
                return result;
            }
            errCode = connection->InnerOpen(config);
            if (errCode != E_OK) {
                LOG_ERROR("reopen slave failed:%{public}d", errCode);
                return result;
            }
        } else {
            LOG_WARN(
                "open slave failed:%{public}d, %{public}s", errCode, SqliteUtils::Anonymous(config.GetPath()).c_str());
            return result;
        }
    }
    conn = connection;
    return result;
}

RdbStoreConfig SqliteConnection::GetSlaveRdbStoreConfig(const RdbStoreConfig &rdbConfig)
{
    RdbStoreConfig rdbStoreConfig(SqliteUtils::GetSlavePath(rdbConfig.GetPath()));
    rdbStoreConfig.SetEncryptStatus(rdbConfig.IsEncrypt());
    rdbStoreConfig.SetSearchable(rdbConfig.IsSearchable());
    rdbStoreConfig.SetIsVector(rdbConfig.IsVector());
    rdbStoreConfig.SetAutoClean(rdbConfig.GetAutoClean());
    rdbStoreConfig.SetSecurityLevel(rdbConfig.GetSecurityLevel());
    rdbStoreConfig.SetDataGroupId(rdbConfig.GetDataGroupId());
    rdbStoreConfig.SetName(SqliteUtils::GetSlavePath(rdbConfig.GetName()));
    rdbStoreConfig.SetCustomDir(rdbConfig.GetCustomDir());
    rdbStoreConfig.SetAllowRebuild(rdbConfig.GetAllowRebuild());
    rdbStoreConfig.SetReadOnly(rdbConfig.IsReadOnly());
    rdbStoreConfig.SetAutoCheck(rdbConfig.IsAutoCheck());
    rdbStoreConfig.SetCreateNecessary(rdbConfig.IsCreateNecessary());
    rdbStoreConfig.SetJournalSize(rdbConfig.GetJournalSize());
    rdbStoreConfig.SetPageSize(rdbConfig.GetPageSize());
    rdbStoreConfig.SetReadConSize(rdbConfig.GetReadConSize());
    rdbStoreConfig.SetReadTime(rdbConfig.GetReadTime());
    rdbStoreConfig.SetDBType(rdbConfig.GetDBType());
    rdbStoreConfig.SetVisitorDir(rdbConfig.GetVisitorDir());
    rdbStoreConfig.SetScalarFunctions(rdbConfig.GetScalarFunctions());
    rdbStoreConfig.SetJournalMode(rdbConfig.GetJournalMode());

    rdbStoreConfig.SetModuleName(rdbConfig.GetModuleName());
    rdbStoreConfig.SetPluginLibs(rdbConfig.GetPluginLibs());
    rdbStoreConfig.SetHaMode(rdbConfig.GetHaMode());

    rdbStoreConfig.SetCryptoParam(rdbConfig.GetCryptoParam());
    return rdbStoreConfig;
}

int SqliteConnection::InnerOpen(const RdbStoreConfig &config)
{
    std::string dbPath;
    auto errCode = SqliteGlobalConfig::GetDbPath(config, dbPath);
    if (errCode != E_OK) {
        return errCode;
    }
    SetTokenizer(config);

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    bool isDbFileExist = access(dbPath.c_str(), F_OK) == 0;
    if (!isDbFileExist && (!config.IsCreateNecessary())) {
        Reportor::ReportFault(RdbFaultDbFileEvent(FT_EX_FILE, E_DB_NOT_EXIST, config, "db not exist"));
        LOG_ERROR("db not exist errno is %{public}d", errno);
        return E_DB_NOT_EXIST;
    }
#endif
    isReadOnly_ = !isWriter_ || config.IsReadOnly();
    int openFileFlags = config.IsReadOnly() ? (SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX)
                                            : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
    errCode = OpenDatabase(dbPath, openFileFlags);
    if (errCode != E_OK) {
        Reportor::ReportFault(RdbFaultDbFileEvent(FT_OPEN, errCode, config, "", true));
        return errCode;
    }

    maxVariableNumber_ = sqlite3_limit(dbHandle_, SQLITE_LIMIT_VARIABLE_NUMBER, -1);
    errCode = Configure(config, dbPath);
    isConfigured_ = true;
    if (errCode != E_OK) {
        return errCode;
    }

    if (isWriter_) {
        ValueObject checkResult{"ok"};
        auto index = static_cast<uint32_t>(config.GetIntegrityCheck());
        if (index < static_cast<uint32_t>(sizeof(INTEGRITIES) / sizeof(INTEGRITIES[0]))) {
            auto sql = INTEGRITIES[index];
            if (sql != nullptr) {
                LOG_INFO("%{public}s : %{public}s, ", sql, SqliteUtils::Anonymous(config.GetName()).c_str());
                std::tie(errCode, checkResult) = ExecuteForValue(sql);
            }
            if (errCode == E_OK && static_cast<std::string>(checkResult) != "ok") {
                LOG_ERROR("%{public}s integrity check result is %{public}s, sql:%{public}s",
                    SqliteUtils::Anonymous(config.GetName()).c_str(), static_cast<std::string>(checkResult).c_str(),
                    sql);
                Reportor::ReportCorruptedOnce(Reportor::Create(config, errCode, static_cast<std::string>(checkResult)));
            }
        }
    }

    filePath = dbPath;
    return E_OK;
}

int32_t SqliteConnection::OpenDatabase(const std::string &dbPath, int openFileFlags)
{
    int errCode = sqlite3_open_v2(dbPath.c_str(), &dbHandle_, openFileFlags, nullptr);
    if (errCode != SQLITE_OK) {
        LOG_ERROR("fail to open database errCode=%{public}d, dbPath=%{public}s, flags=%{public}d, errno=%{public}d",
            errCode, SqliteUtils::Anonymous(dbPath).c_str(), openFileFlags, errno);
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
        if (errCode == SQLITE_NOTADB) {
            Reportor::ReportFault(RdbFaultDbFileEvent(FT_OPEN, E_SQLITE_NOT_DB, config_, "", true));
        }
        return SQLiteError::ErrNo(errCode);
    }
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
        LOG_ERROR("ctx or argv is nullptr.");
        return;
    }
    auto function = static_cast<ScalarFunction *>(sqlite3_user_data(ctx));
    if (function == nullptr) {
        LOG_ERROR("function is nullptr.");
        return;
    }

    std::vector<std::string> argsVector;
    for (int i = 0; i < argc; ++i) {
        auto arg = reinterpret_cast<const char *>(sqlite3_value_text(argv[i]));
        if (arg == nullptr) {
            LOG_ERROR("arg is nullptr, index is %{public}d, errno is %{public}d", i, errno);
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
    int err = sqlite3_create_function_v2(dbHandle_, functionName.c_str(), argc, SQLITE_UTF8, function,
        &CustomScalarFunctionCallback, nullptr, nullptr, nullptr);
    if (err != SQLITE_OK) {
        LOG_ERROR("SetCustomScalarFunction errCode is %{public}d, errno is %{public}d.", err, errno);
    }
    return err;
}

int SqliteConnection::Configure(const RdbStoreConfig &config, std::string &dbPath)
{
    if (config.GetStorageMode() == StorageMode::MODE_MEMORY || config.GetRoleType() == VISITOR) {
        return E_OK;
    }

    auto errCode = SetCrcCheck(config);
    if (errCode != E_OK) {
        return errCode;
    }

    errCode = RegDefaultFunctions(dbHandle_);
    if (errCode != E_OK) {
        return errCode;
    }

    SetBusyTimeout(DEFAULT_BUSY_TIMEOUT_MS);

    LimitPermission(dbPath);

    SetDwrEnable(config);

    errCode = SetPersistWal();
    if (errCode != E_OK) {
        return errCode;
    }

    errCode = SetPageSize(config);
    if (errCode != E_OK) {
        return errCode;
    }

    errCode = SetEncrypt(config);
    if (errCode != E_OK) {
        return errCode;
    }

    errCode = SetJournalMode(config);
    if (errCode != E_OK) {
        return errCode;
    }

    // set the user version to the wal file;
    SetWalFile(config);

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

    return LoadExtension(config, dbHandle_);
}

SqliteConnection::~SqliteConnection()
{
    if (backupId_ != TaskExecutor::INVALID_TASK_ID) {
        auto pool = TaskExecutor::GetInstance().GetExecutor();
        if (pool != nullptr) {
            pool->Remove(backupId_, true);
        }
    }
    if (dbHandle_ != nullptr) {
        if (hasClientObserver_) {
            UnRegisterClientObserver(dbHandle_);
        }
        if (isWriter_) {
            UnregisterStoreObserver(dbHandle_);
        }

        int errCode = sqlite3_close_v2(dbHandle_);
        if (errCode != SQLITE_OK) {
            LOG_ERROR("could not close database err = %{public}d, errno = %{public}d", errCode, errno);
        }
    }
}

int32_t SqliteConnection::OnInitialize()
{
    return 0;
}

std::pair<int, std::shared_ptr<Statement>> SqliteConnection::CreateStatement(
    const std::string &sql, std::shared_ptr<Connection> conn)
{
    std::shared_ptr<SqliteStatement> statement = std::make_shared<SqliteStatement>();
    statement->config_ = &config_;
    int errCode = statement->Prepare(dbHandle_, sql);
    if (errCode != E_OK) {
        return { errCode, nullptr };
    }
    statement->conn_ = conn;
    if (slaveConnection_ && IsWriter()) {
        auto slaveStmt = std::make_shared<SqliteStatement>();
        slaveStmt->config_ = &slaveConnection_->config_;
        errCode = slaveStmt->Prepare(slaveConnection_->dbHandle_, sql);
        if (errCode != E_OK) {
            LOG_WARN("prepare slave stmt failed:%{public}d, app self can check the SQL", errCode);
            SqliteUtils::SetSlaveInvalid(config_.GetPath());
            return { E_OK, statement };
        }
        statement->slave_ = slaveStmt;
    }
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
    int32_t status = RegisterClientObserver(dbHandle_, [notifier](const ClientChangedData &clientData) {
        DistributedRdb::RdbChangedData rdbChangedData;
        for (auto &[key, val] : clientData.tableData) {
            if (val.isTrackedDataChange || val.isP2pSyncDataChange) {
                rdbChangedData.tableData[key].isTrackedDataChange = val.isTrackedDataChange;
                rdbChangedData.tableData[key].isP2pSyncDataChange = val.isP2pSyncDataChange;
            }
        }
        notifier(rdbChangedData);
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
    if (isReadOnly_ || config.GetPageSize() == GlobalExpr::DB_PAGE_SIZE) {
        return E_OK;
    }

    int targetValue = config.GetPageSize();
    auto [errCode, object] = ExecuteForValue("PRAGMA page_size");
    if (errCode != E_OK) {
        LOG_ERROR("SetPageSize fail to get page size : %{public}d", errCode);
        return errCode;
    }

    if (static_cast<int64_t>(object) == targetValue) {
        return E_OK;
    }

    errCode = ExecuteSql("PRAGMA page_size=" + std::to_string(targetValue));
    if (errCode != E_OK) {
        LOG_ERROR("SetPageSize fail to set page size : %{public}d", errCode);
    }
    return errCode;
}

int SqliteConnection::SetEncryptAgo(const RdbStoreConfig &config)
{
    if (!config.GetCryptoParam().IsValid()) {
        LOG_ERROR("Invalid crypto param: %{public}s, %{public}d, %{public}d, %{public}d, %{public}d, %{public}u",
            SqliteUtils::Anonymous(config.GetName()).c_str(), config.GetCryptoParam().iterNum,
            config.GetCryptoParam().encryptAlgo, config.GetCryptoParam().hmacAlgo, config.GetCryptoParam().kdfAlgo,
            config.GetCryptoParam().cryptoPageSize);
        return E_INVALID_ARGS;
    }

    if (config.GetIter() != NO_ITER) {
        auto errCode = ExecuteSql(std::string(GlobalExpr::CIPHER_ALGO_PREFIX) +
                                  SqliteUtils::EncryptAlgoDescription(config.GetEncryptAlgo()) +
                                  std::string(GlobalExpr::ALGO_SUFFIX));
        if (errCode != E_OK) {
            LOG_ERROR("set cipher algo failed, err = %{public}d", errCode);
            return errCode;
        }

        errCode = ExecuteSql(std::string(GlobalExpr::CIPHER_KDF_ITER) + std::to_string(config.GetIter()));
        if (errCode != E_OK) {
            LOG_ERROR("set kdf iter number V1 failed, err = %{public}d", errCode);
            return errCode;
        }
    }

    auto errCode = ExecuteSql(std::string(GlobalExpr::CODEC_HMAC_ALGO_PREFIX) +
                              SqliteUtils::HmacAlgoDescription(config.GetCryptoParam().hmacAlgo) +
                              std::string(GlobalExpr::ALGO_SUFFIX));
    if (errCode != E_OK) {
        LOG_ERROR("set codec hmac algo failed, err = %{public}d", errCode);
        return errCode;
    }

    errCode = ExecuteSql(std::string(GlobalExpr::CODEC_KDF_ALGO_PREFIX) +
                         SqliteUtils::KdfAlgoDescription(config.GetCryptoParam().kdfAlgo) +
                         std::string(GlobalExpr::ALGO_SUFFIX));
    if (errCode != E_OK) {
        LOG_ERROR("set codec kdf algo failed, err = %{public}d", errCode);
        return errCode;
    }

    errCode = ExecuteSql(
        std::string(GlobalExpr::CODEC_PAGE_SIZE_PREFIX) + std::to_string(config.GetCryptoParam().cryptoPageSize));
    if (errCode != E_OK) {
        LOG_ERROR("set codec page size failed, err = %{public}d", errCode);
        return errCode;
    }

    errCode = ExecuteSql(GlobalExpr::CODEC_REKEY_HMAC_ALGO);
    if (errCode != E_OK) {
        LOG_ERROR("set rekey sha algo failed, err = %{public}d", errCode);
        return errCode;
    }
    return E_OK;
}

int SqliteConnection::ReSetKey(const RdbStoreConfig &config)
{
    if (!IsWriter()) {
        return E_OK;
    }
    LOG_INFO(
        "name = %{public}s, iter = %{public}d", SqliteUtils::Anonymous(config.GetName()).c_str(), config.GetIter());
    std::vector<uint8_t> newKey = config.GetNewEncryptKey();
    int errCode = sqlite3_rekey(dbHandle_, static_cast<const void *>(newKey.data()), static_cast<int>(newKey.size()));
    newKey.assign(newKey.size(), 0);
    if (errCode != SQLITE_OK) {
        LOG_ERROR("ReKey failed, err = %{public}d, errno = %{public}d", errCode, errno);
        RdbSecurityManager::GetInstance().DelKeyFile(config.GetPath(), RdbKeyFile::PUB_KEY_FILE_NEW_KEY);
        return E_OK;
    }
    config.ChangeEncryptKey();
    return E_OK;
}

int SqliteConnection::SetCrcCheck(const RdbStoreConfig &config)
{
    if (config.IsEncrypt()) {
        return E_OK;
    }
    int n = -1;
    auto errCode = SQLiteError::ErrNo(sqlite3_file_control(dbHandle_, 0, SQLITE_FCNTL_RESERVE_BYTES, &n));
    if (errCode != E_OK) {
        LOG_ERROR("failed to set sqlite reserved bytes(SQLITE_FCNTL_RESERVE_BYTES), errCode=%{public}d", errCode);
        return errCode;
    }
    if (n == 0) {
        n = SQLITE_CKSUMVFS_RESERVE_BYTES;
        (void)sqlite3_file_control(dbHandle_, 0, SQLITE_FCNTL_RESERVE_BYTES, &n);
    }
    return E_OK;
}

void SqliteConnection::SetDwrEnable(const RdbStoreConfig &config)
{
    if (config.IsEncrypt()) {
        return;
    }
    auto errCode = ExecuteSql(GlobalExpr::PRAGMA_META_DOUBLE_WRITE);
    if (errCode == E_SQLITE_META_RECOVERED) {
        Reportor::ReportFault(RdbFaultDbFileEvent(FT_OPEN, errCode, config, "", true));
    } else if (errCode != E_OK) {
        LOG_ERROR("meta double failed %{public}d", errCode);
    }
}

int SqliteConnection::SetEncrypt(const RdbStoreConfig &config)
{
    if (!config.IsEncrypt()) {
        return E_OK;
    }

    std::vector<uint8_t> key = config.GetEncryptKey();
    std::vector<uint8_t> newKey = config.GetNewEncryptKey();
    auto errCode = SetEncryptKey(key, config);
    key.assign(key.size(), 0);
    if (errCode != E_OK) {
        Reportor::ReportFault(RdbFaultDbFileEvent(FT_OPEN, E_SET_ENCRYPT_FAIL, config, "LOG:SetEncryptKey errcode=" +
            std::to_string(errCode) + ",iter=" + std::to_string(config.GetIter()), true));
        if (!newKey.empty()) {
            LOG_INFO("use new key, iter=%{public}d err=%{public}d errno=%{public}d name=%{public}s", config.GetIter(),
                errCode, errno, SqliteUtils::Anonymous(config.GetName()).c_str());
            errCode = SetEncryptKey(newKey, config);
            if (errCode != E_OK) {
                Reportor::ReportFault(RdbFaultDbFileEvent(FT_OPEN, E_SET_NEW_ENCRYPT_FAIL, config,
                    "LOG:new key SetEncryptKey errcode= "+ std::to_string(errCode) +
                    ",iter=" + std::to_string(config.GetIter()), true));
            }
        }
        newKey.assign(newKey.size(), 0);
        if (errCode != E_OK) {
            errCode = SetServiceKey(config, errCode);
            LOG_ERROR("fail, iter=%{public}d err=%{public}d errno=%{public}d name=%{public}s", config.GetIter(),
                errCode, errno, SqliteUtils::Anonymous(config.GetName()).c_str());
            if (errCode != E_OK) {
                bool sameKey = (key == config.GetEncryptKey()) || (newKey == config.GetEncryptKey());
                Reportor::ReportFault(RdbFaultDbFileEvent(FT_OPEN, E_SET_SERVICE_ENCRYPT_FAIL, config,
                    "LOG:service key SetEncryptKey errcode=" + std::to_string(errCode) +
                    ",iter=" + std::to_string(config.GetIter()) + ",samekey=" + std::to_string(sameKey), true));
            }
            return errCode;
        }
        config.ChangeEncryptKey();
        newKey = {};
    }

    if (!newKey.empty()) {
        ReSetKey(config);
    }
    newKey.assign(newKey.size(), 0);
    return E_OK;
}

int SqliteConnection::SetEncryptKey(const std::vector<uint8_t> &key, const RdbStoreConfig &config)
{
    if (key.empty()) {
        return E_INVALID_SECRET_KEY;
    }

    auto errCode = sqlite3_key(dbHandle_, static_cast<const void *>(key.data()), static_cast<int>(key.size()));
    if (errCode != SQLITE_OK) {
        return SQLiteError::ErrNo(errCode);
    }

    errCode = SetEncryptAgo(config);
    if (errCode != E_OK) {
        return errCode;
    }

    if (IsWriter()) {
        ValueObject version;
        std::tie(errCode, version) = ExecuteForValue(GlobalExpr::PRAGMA_VERSION);
        if (errCode != E_OK || version.GetType() == ValueObject::TYPE_NULL) {
            return errCode;
        }
        return E_OK;
    }
    return errCode;
}

int SqliteConnection::SetPersistWal()
{
    int opcode = 1;
    int errCode = sqlite3_file_control(dbHandle_, "main", SQLITE_FCNTL_PERSIST_WAL, &opcode);
    if (errCode != SQLITE_OK) {
        LOG_ERROR("failed.");
        return E_SET_PERSIST_WAL;
    }
    return E_OK;
}

int SqliteConnection::SetBusyTimeout(int timeout)
{
    auto errCode = sqlite3_busy_timeout(dbHandle_, timeout);
    if (errCode != SQLITE_OK) {
        LOG_ERROR("set buys timeout failed, errCode=%{public}d, errno=%{public}d", errCode, errno);
        return errCode;
    }
    return E_OK;
}

int SqliteConnection::RegDefaultFunctions(sqlite3 *dbHandle)
{
    if (dbHandle == nullptr) {
        return SQLITE_OK;
    }

    auto [funcs, funcCount] = SqliteFunctionRegistry::GetFunctions();

    for (size_t i = 0; i < funcCount; i++) {
        const SqliteFunction& func = funcs[i];
        int errCode = sqlite3_create_function_v2(dbHandle, func.name, func.numArgs,
            SQLITE_UTF8 | SQLITE_DETERMINISTIC, nullptr, func.function, nullptr, nullptr, nullptr);
        if (errCode != SQLITE_OK) {
            LOG_ERROR("register function %{public}s failed, errCode=0x%{public}x, errno=%{public}d", func.name,
                errCode, errno);
            return SQLiteError::ErrNo(errCode);
        }
    }
    return E_OK;
}

int SqliteConnection::SetJournalMode(const RdbStoreConfig &config)
{
    if (isReadOnly_) {
        return E_OK;
    }

    auto [errCode, object] = ExecuteForValue("PRAGMA journal_mode");
    if (errCode != E_OK) {
        LOG_ERROR("SetJournalMode fail to get journal mode : %{public}d, errno %{public}d", errCode, errno);
        // errno: 28 No space left on device
        return (errCode == E_SQLITE_IOERR && sqlite3_system_errno(dbHandle_) == 28) ? E_SQLITE_IOERR_FULL : errCode;
    }

    if (config.GetJournalMode().compare(static_cast<std::string>(object)) == 0) {
        return E_OK;
    }

    std::string currentMode = SqliteUtils::StrToUpper(static_cast<std::string>(object));
    if (currentMode != config.GetJournalMode()) {
        auto [errorCode, journalMode] = ExecuteForValue("PRAGMA journal_mode=" + config.GetJournalMode());
        if (errorCode != E_OK) {
            LOG_ERROR("SqliteConnection SetJournalMode: fail to set journal mode err=%{public}d", errorCode);
            return errorCode;
        }

        if (SqliteUtils::StrToUpper(static_cast<std::string>(journalMode)) != config.GetJournalMode()) {
            LOG_ERROR("SqliteConnection SetJournalMode: result incorrect.");
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
    if (isReadOnly_ || config.GetJournalSize() == GlobalExpr::DB_JOURNAL_SIZE) {
        return E_OK;
    }

    int targetValue = SqliteGlobalConfig::GetJournalFileSize();
    auto [errCode, currentValue] = ExecuteForValue("PRAGMA journal_size_limit");
    if (errCode != E_OK) {
        LOG_ERROR("SqliteConnection SetJournalSizeLimit fail to get journal_size_limit : %{public}d", errCode);
        return errCode;
    }

    if (static_cast<int64_t>(currentValue) == targetValue) {
        return E_OK;
    }

    std::tie(errCode, currentValue) = ExecuteForValue("PRAGMA journal_size_limit=" + std::to_string(targetValue));
    if (errCode != E_OK) {
        LOG_ERROR("SqliteConnection SetJournalSizeLimit fail to set journal_size_limit : %{public}d", errCode);
    }
    return errCode;
}

int SqliteConnection::SetAutoCheckpoint(const RdbStoreConfig &config)
{
    if (isReadOnly_ || !config.IsAutoCheck()) {
        return E_OK;
    }

    int targetValue = SqliteGlobalConfig::GetWalAutoCheckpoint();
    auto [errCode, value] = ExecuteForValue("PRAGMA wal_autocheckpoint");
    if (errCode != E_OK) {
        LOG_ERROR("SqliteConnection SetAutoCheckpoint fail to get wal_autocheckpoint : %{public}d", errCode);
        return errCode;
    }

    if (static_cast<int64_t>(value) == targetValue) {
        return E_OK;
    }

    std::tie(errCode, value) = ExecuteForValue("PRAGMA wal_autocheckpoint=" + std::to_string(targetValue));
    if (errCode != E_OK) {
        LOG_ERROR("SqliteConnection SetAutoCheckpoint fail to set wal_autocheckpoint : %{public}d", errCode);
    }
    return errCode;
}

int SqliteConnection::SetTokenizer(const RdbStoreConfig &config)
{
    auto tokenizer = config.GetTokenizer();
    if (tokenizer == NONE_TOKENIZER || tokenizer == CUSTOM_TOKENIZER) {
        return E_OK;
    }
    if (tokenizer == ICU_TOKENIZER) {
        sqlite3_config(SQLITE_CONFIG_ENABLE_ICU, 1);
        return E_OK;
    }
    LOG_ERROR("fail to set Tokenizer: %{public}d", tokenizer);
    return E_INVALID_ARGS;
}

int SqliteConnection::SetWalFile(const RdbStoreConfig &config)
{
    if (!IsWriter()) {
        return E_OK;
    }
    auto [errCode, version] = ExecuteForValue(GlobalExpr::PRAGMA_VERSION);
    if (errCode != E_OK) {
        return errCode;
    }
    return ExecuteSql(std::string(GlobalExpr::PRAGMA_VERSION) + "=?", { std::move(version) });
}

int SqliteConnection::SetWalSyncMode(const std::string &syncMode)
{
    std::string targetValue = SqliteGlobalConfig::GetSyncMode();
    if (syncMode.length() != 0) {
        targetValue = syncMode;
    }

    auto [errCode, object] = ExecuteForValue("PRAGMA synchronous");
    if (errCode != E_OK) {
        LOG_ERROR("get wal sync mode fail, errCode:%{public}d", errCode);
        return errCode;
    }

    std::string walSyncMode = SqliteUtils::StrToUpper(static_cast<std::string>(object));
    if (walSyncMode == targetValue) {
        return E_OK;
    }

    errCode = ExecuteSql("PRAGMA synchronous=" + targetValue);
    if (errCode != E_OK) {
        LOG_ERROR("set wal sync mode fail, errCode:%{public}d", errCode);
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

std::pair<int32_t, ValueObject> SqliteConnection::ExecuteForValue(
    const std::string &sql, const std::vector<ValueObject> &bindArgs)
{
    auto [errCode, statement] = CreateStatement(sql, nullptr);
    if (statement == nullptr || errCode != E_OK) {
        return { static_cast<int32_t>(errCode), ValueObject() };
    }

    ValueObject object;
    std::tie(errCode, object) = statement->ExecuteForValue(bindArgs);
    if (errCode != E_OK) {
        LOG_ERROR("execute sql failed, errCode:%{public}d, app self can check the SQL, args size:%{public}zu",
            SQLiteError::ErrNo(errCode), bindArgs.size());
    }
    return { errCode, object };
}

int SqliteConnection::ClearCache()
{
    if (dbHandle_ != nullptr && mode_ == JournalMode::MODE_WAL) {
        sqlite3_db_release_memory(dbHandle_);
    }
    if (slaveConnection_) {
        int errCode = slaveConnection_->ClearCache();
        if (errCode != E_OK) {
            LOG_ERROR("slaveConnection clearCache failed:%{public}d", errCode);
        }
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

int SqliteConnection::ConfigLocale(const std::string &localeStr)
{
    static void *handle = dlopen("librelational_store_icu.z.so", RTLD_LAZY);
    if (handle == nullptr) {
        LOG_ERROR("dlopen(librelational_store_icu) failed(%{public}d)!", errno);
        return E_NOT_SUPPORT;
    }
    auto func = reinterpret_cast<int32_t (*)(sqlite3 *, const std::string &str)>(dlsym(handle, "ConfigICULocal"));
    if (func == nullptr) {
        LOG_ERROR("dlsym(librelational_store_icu) failed(%{public}d)!", errno);
        return E_ERROR;
    }
    func(dbHandle_, localeStr);
    return E_OK;
}

int SqliteConnection::CleanDirtyData(const std::string &table, uint64_t cursor)
{
    if (table.empty()) {
        LOG_ERROR("table is empty");
        return E_INVALID_ARGS;
    }
    uint64_t tmpCursor = cursor == UINT64_MAX ? 0 : cursor;
    auto status = DropLogicDeletedData(dbHandle_, table, tmpCursor);
    LOG_INFO("status:%{public}d, table:%{public}s, cursor:%{public}" PRIu64 "", status,
        SqliteUtils::Anonymous(table).c_str(), cursor);
    return status == DistributedDB::DBStatus::OK ? E_OK : E_ERROR;
}

int SqliteConnection::TryCheckPoint(bool timeout)
{
    if (!isWriter_ || config_.IsMemoryRdb()) {
        return E_NOT_SUPPORT;
    }

    std::shared_ptr<Connection> autoCheck(slaveConnection_.get(), [this, timeout](Connection *conn) {
        if (conn != nullptr && backupId_ == TaskExecutor::INVALID_TASK_ID) {
            conn->TryCheckPoint(timeout);
        }
    });
    std::string walName = sqlite3_filename_wal(sqlite3_db_filename(dbHandle_, "main"));
    ssize_t size = SqliteUtils::GetFileSize(walName);
    if (size < 0) {
        LOG_ERROR("Invalid size for WAL:%{public}s size:%{public}zd", SqliteUtils::Anonymous(walName).c_str(), size);
        return E_ERROR;
    }

    if (size <= config_.GetStartCheckpointSize()) {
        return E_OK;
    }

    if (!timeout && size < config_.GetCheckpointSize()) {
        return E_INNER_WARNING;
    }

    (void)sqlite3_busy_timeout(dbHandle_, CHECKPOINT_TIME);
    int errCode = sqlite3_wal_checkpoint_v2(dbHandle_, nullptr, SQLITE_CHECKPOINT_TRUNCATE, nullptr, nullptr);
    (void)sqlite3_busy_timeout(dbHandle_, DEFAULT_BUSY_TIMEOUT_MS);
    if (errCode != SQLITE_OK) {
        Reportor::ReportFault(RdbFaultDbFileEvent(FT_CP, E_CHECK_POINT_FAIL, config_,
            "LOG:cp fail, errcode=" + std::to_string(errCode), true));
        LOG_WARN("sqlite3_wal_checkpoint_v2 failed err:%{public}d,size:%{public}zd,wal:%{public}s.", errCode, size,
            SqliteUtils::Anonymous(walName).c_str());
        return SQLiteError::ErrNo(errCode);
    }
    return E_OK;
}

int SqliteConnection::LimitWalSize()
{
    if (!isConfigured_ || !isWriter_ || config_.IsMemoryRdb()) {
        return E_OK;
    }

    std::string walName = sqlite3_filename_wal(sqlite3_db_filename(dbHandle_, "main"));
    ssize_t fileSize = SqliteUtils::GetFileSize(walName);
    if (fileSize < 0 || fileSize > config_.GetWalLimitSize()) {
        std::stringstream ss;
        ss << "The WAL file size exceeds the limit,name=" << SqliteUtils::Anonymous(walName).c_str()
            << ",file size=" << fileSize
            << ",limit size=" << config_.GetWalLimitSize();
        LOG_ERROR("%{public}s", ss.str().c_str());
        Reportor::ReportFault(RdbFaultDbFileEvent(FT_OPEN, E_WAL_SIZE_OVER_LIMIT, config_, ss.str()));
        return E_WAL_SIZE_OVER_LIMIT;
    }
    return E_OK;
}

int32_t SqliteConnection::Subscribe(const std::string &event, const std::shared_ptr<RdbStoreObserver> &observer)
{
    if (!isWriter_ || observer == nullptr) {
        return E_OK;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    observers_.try_emplace(event);
    auto &list = observers_.find(event)->second;
    for (auto it = list.begin(); it != list.end(); it++) {
        if ((*it)->GetObserver() == observer) {
            LOG_ERROR("duplicate subscribe.");
            return E_OK;
        }
    }
    auto localStoreObserver = std::make_shared<RdbStoreLocalDbObserver>(observer);
    int32_t errCode = RegisterStoreObserver(dbHandle_, localStoreObserver);
    if (errCode != E_OK) {
        LOG_ERROR("subscribe failed.");
        return errCode;
    }
    observers_[event].push_back(std::move(localStoreObserver));
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

int32_t SqliteConnection::UnsubscribeLocalDetail(
    const std::string &event, const std::shared_ptr<RdbStoreObserver> &observer)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto observers = observers_.find(event);
    if (observers == observers_.end()) {
        return E_OK;
    }

    auto &list = observers->second;
    for (auto it = list.begin(); it != list.end(); it++) {
        if ((*it)->GetObserver() == observer) {
            int32_t err = UnregisterStoreObserver(dbHandle_, *it);
            if (err != 0) {
                LOG_ERROR("unsubscribeLocalShared failed.");
                return err;
            }
            list.erase(it);
            break;
        }
    }
    if (list.empty()) {
        observers_.erase(event);
    }
    return E_OK;
}

int32_t SqliteConnection::UnsubscribeLocalDetailAll(const std::string &event)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto observers = observers_.find(event);
    if (observers == observers_.end()) {
        return E_OK;
    }

    auto &list = observers->second;
    auto it = list.begin();
    while (it != list.end()) {
        int32_t err = UnregisterStoreObserver(dbHandle_, *it);
        if (err != 0) {
            LOG_ERROR("unsubscribe failed.");
            return err;
        }
        it = list.erase(it);
    }

    observers_.erase(event);
    return E_OK;
}

int32_t SqliteConnection::Backup(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey,
    bool isAsync, SlaveStatus &slaveStatus)
{
    if (slaveStatus == SlaveStatus::BACKING_UP) {
        LOG_INFO("backing up, return:%{public}s", config_.GetName().c_str());
        return E_OK;
    }
    LOG_INFO(
        "begin backup to slave:%{public}s, isAsync:%{public}d", SqliteUtils::Anonymous(databasePath).c_str(), isAsync);
    if (!isAsync) {
        if (slaveConnection_ == nullptr) {
            RdbStoreConfig rdbSlaveStoreConfig = GetSlaveRdbStoreConfig(config_);
            auto [errCode, conn] = CreateSlaveConnection(rdbSlaveStoreConfig, SlaveOpenPolicy::FORCE_OPEN);
            if (errCode != E_OK) {
                return errCode;
            }
            slaveConnection_ = conn;
        }
        return ExchangeSlaverToMaster(false, true, slaveStatus);
    }

    if (backupId_ == TaskExecutor::INVALID_TASK_ID) {
        auto pool = TaskExecutor::GetInstance().GetExecutor();
        if (pool == nullptr) {
            LOG_WARN("task pool err when restore");
            return E_OK;
        }
        backupId_ = pool->Execute([this, &slaveStatus]() {
            auto [err, conn] = InnerCreate(config_, true);
            if (err != E_OK) {
                return;
            }
            err = conn->ExchangeSlaverToMaster(false, true, slaveStatus);
            if (err != E_OK) {
                LOG_WARN("master backup to slave failed:%{public}d", err);
            }
            backupId_ = TaskExecutor::INVALID_TASK_ID;
        });
    }
    return E_OK;
}

int32_t SqliteConnection::Restore(
    const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey, SlaveStatus &slaveStatus)
{
    return ExchangeSlaverToMaster(true, true, slaveStatus);
};

int SqliteConnection::LoadExtension(const RdbStoreConfig &config, sqlite3 *dbHandle)
{
    auto pluginLibs = config.GetPluginLibs();
    if (config.GetTokenizer() == CUSTOM_TOKENIZER) {
        pluginLibs.push_back("libcustomtokenizer.z.so");
    }
    if (pluginLibs.empty() || dbHandle == nullptr) {
        return E_OK;
    }
    if (pluginLibs.size() >
        SqliteUtils::MAX_LOAD_EXTENSION_COUNT + (config.GetTokenizer() == CUSTOM_TOKENIZER ? 1 : 0)) {
        LOG_ERROR("failed, size %{public}zu is too large", pluginLibs.size());
        return E_INVALID_ARGS;
    }
    int err = sqlite3_db_config(
        dbHandle, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, SqliteUtils::ENABLE_LOAD_EXTENSION, nullptr);
    if (err != SQLITE_OK) {
        LOG_ERROR("enable failed, err=%{public}d, errno=%{public}d", err, errno);
        return SQLiteError::ErrNo(err);
    }
    for (auto &path : pluginLibs) {
        if (path.empty()) {
            continue;
        }
        err = sqlite3_load_extension(dbHandle, path.c_str(), nullptr, nullptr);
        if (err != SQLITE_OK) {
            LOG_ERROR("load error. err=%{public}d, errno=%{public}d, errmsg:%{public}s, lib=%{public}s", err, errno,
                sqlite3_errmsg(dbHandle), SqliteUtils::Anonymous(path).c_str());
            if (access(path.c_str(), F_OK) != 0) {
                return E_INVALID_FILE_PATH;
            }
            break;
        }
    }
    int ret = sqlite3_db_config(
        dbHandle, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, SqliteUtils::DISABLE_LOAD_EXTENSION, nullptr);
    if (ret != SQLITE_OK) {
        LOG_ERROR("disable failed, err=%{public}d, errno=%{public}d", err, errno);
    }
    return SQLiteError::ErrNo(err == SQLITE_OK ? ret : err);
}

int SqliteConnection::SetServiceKey(const RdbStoreConfig &config, int32_t errCode)
{
    DistributedRdb::RdbSyncerParam param;
    param.bundleName_ = config.GetBundleName();
    param.hapName_ = config.GetModuleName();
    param.storeName_ = config.GetName();
    param.customDir_ = config.GetCustomDir();
    param.area_ = config.GetArea();
    param.level_ = static_cast<int32_t>(config.GetSecurityLevel());
    param.type_ = config.GetDistributedType();
    param.isEncrypt_ = config.IsEncrypt();
    param.isAutoClean_ = config.GetAutoClean();
    param.isSearchable_ = config.IsSearchable();
    param.haMode_ = config.GetHaMode();
    param.password_ = {};
    std::vector<std::vector<uint8_t>> keys;
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    auto [svcErr, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(param);
    if (svcErr != E_OK) {
        return errCode;
    }
    svcErr = service->GetPassword(param, keys);
    if (svcErr != RDB_OK) {
        return errCode;
    }
#endif

    for (const auto &key : keys) {
        errCode = SetEncryptKey(key, config);
        if (errCode == E_OK) {
            config.RestoreEncryptKey(key);
            break;
        }
    }
    for (auto &key : keys) {
        key.assign(key.size(), 0);
    }
    return errCode;
}

int SqliteConnection::ExchangeSlaverToMaster(bool isRestore, bool verifyDb, SlaveStatus &curStatus)
{
    curStatus = SlaveStatus::BACKING_UP;
    int err = verifyDb ? ExchangeVerify(isRestore) : E_OK;
    if (err != E_OK) {
        curStatus = SlaveStatus::UNDEFINED;
        return err;
    }
    return SqliteNativeBackup(isRestore, curStatus);
}

int SqliteConnection::SqliteNativeBackup(bool isRestore, SlaveStatus &curStatus)
{
    sqlite3 *dbFrom = isRestore ? dbHandle_ : slaveConnection_->dbHandle_;
    sqlite3 *dbTo = isRestore ? slaveConnection_->dbHandle_ : dbHandle_;
    sqlite3_backup *pBackup = sqlite3_backup_init(dbFrom, "main", dbTo, "main");
    if (pBackup == nullptr) {
        LOG_WARN("slave backup init failed");
        curStatus = SlaveStatus::UNDEFINED;
        return E_OK;
    }
    int rc = SQLITE_OK;
    do {
        if (!isRestore && curStatus == SlaveStatus::BACKUP_INTERRUPT) {
            rc = E_CANCEL;
            break;
        }
        rc = sqlite3_backup_step(pBackup, BACKUP_PAGES_PRE_STEP);
        LOG_INFO("backup slave process cur/total:%{public}d/%{public}d, rs:%{public}d, isRestore:%{public}d",
            sqlite3_backup_pagecount(pBackup) - sqlite3_backup_remaining(pBackup), sqlite3_backup_pagecount(pBackup),
            rc, isRestore);
        if (!isRestore) {
            sqlite3_sleep(BACKUP_PRE_WAIT_TIME);
        }
    } while (sqlite3_backup_pagecount(pBackup) != 0 && (rc == SQLITE_OK || rc == SQLITE_BUSY || rc == SQLITE_LOCKED));
    (void)sqlite3_backup_finish(pBackup);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("backup slave err:%{public}d, isRestore:%{public}d", rc, isRestore);
        if (!isRestore) {
            RdbStoreConfig slaveConfig(slaveConnection_->config_.GetPath());
            if (rc != SQLITE_BUSY && rc != SQLITE_LOCKED) {
                slaveConnection_ = nullptr;
                (void)SqliteConnection::Delete(slaveConfig.GetPath());
            }
            curStatus = SlaveStatus::BACKUP_INTERRUPT;
            Reportor::ReportCorrupted(Reportor::Create(slaveConfig, SQLiteError::ErrNo(rc), "ErrorType: slaveBackup"));
        }
        return rc == E_CANCEL ? E_CANCEL : SQLiteError::ErrNo(rc);
    }
    rc = isRestore ? TryCheckPoint(true) : slaveConnection_->TryCheckPoint(true);
    if (rc != E_OK && config_.GetHaMode() == HAMode::MANUAL_TRIGGER) {
        if (!isRestore) {
            curStatus = SlaveStatus::BACKUP_INTERRUPT;
        }
        LOG_WARN("CheckPoint failed err:%{public}d, isRestore:%{public}d", rc, isRestore);
        return E_OK;
    }
    curStatus = SlaveStatus::BACKUP_FINISHED;
    SqliteUtils::SetSlaveValid(config_.GetPath());
    LOG_INFO("backup slave success, isRestore:%{public}d", isRestore);
    return E_OK;
}

ExchangeStrategy SqliteConnection::GenerateExchangeStrategy(const SlaveStatus &status)
{
    if (dbHandle_ == nullptr || slaveConnection_ == nullptr || slaveConnection_->dbHandle_ == nullptr ||
        config_.GetHaMode() == HAMode::SINGLE || status == SlaveStatus::BACKING_UP) {
        return ExchangeStrategy::NOT_HANDLE;
    }
    static const std::string querySql = "SELECT COUNT(*) FROM sqlite_master WHERE type='table';";
    auto [mRet, mObj] = ExecuteForValue(querySql);
    if (mRet == E_SQLITE_CORRUPT) {
        LOG_WARN("main abnormal, err:%{public}d", mRet);
        return ExchangeStrategy::RESTORE;
    }
    int64_t mCount = static_cast<int64_t>(mObj);
    // trigger mode only does restore, not backup
    if (config_.GetHaMode() == HAMode::MANUAL_TRIGGER) {
        return mCount == 0 ? ExchangeStrategy::RESTORE : ExchangeStrategy::NOT_HANDLE;
    }
    auto [sRet, sObj] = slaveConnection_->ExecuteForValue(querySql);
    if (sRet == E_SQLITE_CORRUPT) {
        LOG_WARN("slave db abnormal, need backup, err:%{public}d", sRet);
        return ExchangeStrategy::BACKUP;
    }
    if (status == SlaveStatus::DB_NOT_EXITS || status == SlaveStatus::BACKUP_INTERRUPT) {
        return ExchangeStrategy::BACKUP;
    }
    int64_t sCount = static_cast<int64_t>(sObj);
    if ((mCount == sCount) && !SqliteUtils::IsSlaveInvalid(config_.GetPath())) {
        LOG_INFO("equal, main:%{public}" PRId64 ",slave:%{public}" PRId64, mCount, sCount);
        return ExchangeStrategy::NOT_HANDLE;
    }
    if (mCount == 0) {
        LOG_INFO("main empty, main:%{public}" PRId64 ",slave:%{public}" PRId64, mCount, sCount);
        return ExchangeStrategy::RESTORE;
    }
    LOG_INFO("backup, main:%{public}" PRId64 ",slave:%{public}" PRId64, mCount, sCount);
    return ExchangeStrategy::BACKUP;
}

int32_t SqliteConnection::Repair(const RdbStoreConfig &config)
{
    if (config.GetHaMode() == HAMode::MANUAL_TRIGGER) {
        return SqliteConnection::Restore(config, SqliteUtils::GetSlavePath(config.GetPath()), config.GetPath());
    }
    std::shared_ptr<SqliteConnection> connection = std::make_shared<SqliteConnection>(config, true);
    if (connection == nullptr) {
        return E_ERROR;
    }
    RdbStoreConfig rdbSlaveStoreConfig = connection->GetSlaveRdbStoreConfig(config);
    if (access(rdbSlaveStoreConfig.GetPath().c_str(), F_OK) != 0) {
        return E_NOT_SUPPORT;
    }
    auto [ret, conn] = connection->CreateSlaveConnection(rdbSlaveStoreConfig, SlaveOpenPolicy::FORCE_OPEN);
    if (ret != E_OK) {
        return ret;
    }
    connection->slaveConnection_ = conn;
    ret = connection->VeritySlaveIntegrity();
    if (ret != E_OK) {
        return ret;
    }
    (void)SqliteConnection::Delete(config.GetPath());
    ret = connection->InnerOpen(config);
    if (ret != E_OK) {
        LOG_ERROR("reopen db failed, err:%{public}d", ret);
        return ret;
    }
    connection->TryCheckPoint(true);
    SlaveStatus curStatus;
    ret = connection->ExchangeSlaverToMaster(true, false, curStatus);
    if (ret != E_OK) {
        LOG_ERROR("repair failed, [%{public}s]->[%{public}s], err:%{public}d", rdbSlaveStoreConfig.GetName().c_str(),
            SqliteUtils::Anonymous(config.GetName()).c_str(), ret);
    } else {
        LOG_INFO("repair main success:%{public}s", SqliteUtils::Anonymous(config.GetPath()).c_str());
    }
    return ret;
}

int SqliteConnection::ExchangeVerify(bool isRestore)
{
    if (isRestore) {
        int err = VeritySlaveIntegrity();
        if (err != E_OK) {
            return err;
        }
        if (IsDbVersionBelowSlave()) {
            return E_OK;
        }
        if (SqliteUtils::IsSlaveInvalid(config_.GetPath())) {
            LOG_ERROR("incomplete slave, %{public}s", config_.GetName().c_str());
            return E_SQLITE_CORRUPT;
        }
        return E_OK;
    }
    if (slaveConnection_ == nullptr) {
        return E_ALREADY_CLOSED;
    }
    if (access(config_.GetPath().c_str(), F_OK) != 0) {
        LOG_WARN("main no exist, isR:%{public}d, %{public}s", isRestore, config_.GetName().c_str());
        return E_DB_NOT_EXIST;
    }
    auto [cRet, cObj] = ExecuteForValue(INTEGRITIES[1]); // 1 is quick_check
    if (cRet == E_OK && (static_cast<std::string>(cObj) != "ok")) {
        LOG_ERROR("main corrupt, cancel, %{public}s, ret:%{public}s, qRet:%{public}d",
            SqliteUtils::Anonymous(config_.GetName()).c_str(), static_cast<std::string>(cObj).c_str(), cRet);
        return E_SQLITE_CORRUPT;
    }
    SqliteUtils::SetSlaveInterrupted(config_.GetPath());
    return E_OK;
}

std::pair<int32_t, std::shared_ptr<SqliteConnection>> SqliteConnection::InnerCreate(
    const RdbStoreConfig &config, bool isWrite)
{
    std::pair<int32_t, std::shared_ptr<SqliteConnection>> result = { E_ERROR, nullptr };
    auto &[errCode, conn] = result;
    std::shared_ptr<SqliteConnection> connection = std::make_shared<SqliteConnection>(config, isWrite);
    if (connection == nullptr) {
        LOG_ERROR("connection is nullptr.");
        return result;
    }

    errCode = connection->InnerOpen(config);
    if (errCode != E_OK) {
        return result;
    }
    conn = connection;
    if (isWrite && config.GetHaMode() != HAMode::SINGLE) {
        RdbStoreConfig slaveCfg = connection->GetSlaveRdbStoreConfig(config);
        auto [err, slaveConn] = connection->CreateSlaveConnection(slaveCfg, SlaveOpenPolicy::OPEN_IF_DB_VALID);
        if (err == E_OK) {
            conn->slaveConnection_ = slaveConn;
        }
    }
    return result;
}

int SqliteConnection::VeritySlaveIntegrity()
{
    if (slaveConnection_ == nullptr) {
        return E_ALREADY_CLOSED;
    }

    RdbStoreConfig slaveCfg = GetSlaveRdbStoreConfig(config_);
    std::map<std::string, DebugInfo> bugInfo = Connection::Collect(slaveCfg);
    LOG_INFO("%{public}s", SqliteUtils::FormatDebugInfoBrief(bugInfo,
        SqliteUtils::Anonymous(slaveCfg.GetName())).c_str());

    if (SqliteUtils::IsSlaveInterrupted(config_.GetPath())) {
        return E_SQLITE_CORRUPT;
    }

    std::string sql = "SELECT COUNT(*) FROM sqlite_master WHERE type='table';";
    auto [err, obj] = slaveConnection_->ExecuteForValue(sql);
    auto val = std::get_if<int64_t>(&obj.value);
    if (err == E_SQLITE_CORRUPT || (val != nullptr && static_cast<int64_t>(*val) == 0L)) {
        LOG_ERROR("slave %{public}d", err);
        return E_SQLITE_CORRUPT;
    }

    int64_t mCount = 0L;
    if (dbHandle_ != nullptr) {
        std::tie(err, obj) = ExecuteForValue(sql);
        val = std::get_if<int64_t>(&obj.value);
        if (val != nullptr) {
            mCount = static_cast<int64_t>(*val);
        }
    }
    bool isSlaveDbOverLimit = bugInfo.find(FILE_SUFFIXES[DB_INDEX].debug_) != bugInfo.end() &&
                              bugInfo[FILE_SUFFIXES[DB_INDEX].debug_].size_ > SLAVE_INTEGRITY_CHECK_LIMIT;
    if (isSlaveDbOverLimit && mCount == 0L) {
        return SqliteUtils::IsSlaveInvalid(config_.GetPath()) ? E_SQLITE_CORRUPT : E_OK;
    }

    std::tie(err, obj) = slaveConnection_->ExecuteForValue(INTEGRITIES[2]); // 2 is integrity_check
    if (err == E_OK && (static_cast<std::string>(obj) != "ok")) {
        LOG_ERROR("slave corrupt, ret:%{public}s, cRet:%{public}d, %{public}d", static_cast<std::string>(obj).c_str(),
            err, errno);
        SqliteUtils::SetSlaveInvalid(config_.GetPath());
        return E_SQLITE_CORRUPT;
    }
    return E_OK;
}

bool SqliteConnection::IsDbVersionBelowSlave()
{
    if (slaveConnection_ == nullptr) {
        return false;
    }

    auto [cRet, cObj] = ExecuteForValue("SELECT COUNT(*) FROM sqlite_master WHERE type='table';");
    auto cVal = std::get_if<int64_t>(&cObj.value);
    if (cRet == E_SQLITE_CORRUPT || (cVal != nullptr && (static_cast<int64_t>(*cVal) == 0L))) {
        LOG_INFO("main empty, %{public}d, %{public}s", cRet, config_.GetName().c_str());
        return true;
    }

    std::tie(cRet, cObj) = ExecuteForValue(GlobalExpr::PRAGMA_VERSION);
    if (cVal == nullptr || (cVal != nullptr && static_cast<int64_t>(*cVal) == 0L)) {
        std::tie(cRet, cObj) = slaveConnection_->ExecuteForValue(GlobalExpr::PRAGMA_VERSION);
        cVal = std::get_if<int64_t>(&cObj.value);
        if (cVal != nullptr && static_cast<int64_t>(*cVal) > 0L) {
            LOG_INFO("version, %{public}" PRId64, static_cast<int64_t>(*cVal));
            return true;
        }
    }
    return false;
}

int SqliteConnection::CopyDb(const RdbStoreConfig &config, const std::string &srcPath, const std::string &destPath)
{
    RdbStoreConfig srcConfig(config);
    srcConfig.SetPath(srcPath);
    srcConfig.SetIntegrityCheck(IntegrityCheck::FULL);
    srcConfig.SetHaMode(HAMode::SINGLE);
    auto [ret, conn] = Connection::Create(srcConfig, true);
    if (ret == E_SQLITE_CORRUPT && srcConfig.IsEncrypt() && srcConfig.GetIter() != ITER_V1) {
        srcConfig.SetIter(ITER_V1);
        std::tie(ret, conn) = Connection::Create(srcConfig, true);
    }
    if (ret != E_OK) {
        LOG_ERROR("backup file is corrupted, %{public}s", SqliteUtils::Anonymous(srcPath).c_str());
        return E_SQLITE_CORRUPT;
    }
    conn = nullptr;

    auto walFile = srcPath + "-wal";
    if (SqliteUtils::GetFileSize(walFile) != 0) {
        LOG_ERROR("Wal file exist.");
        return E_SQLITE_CORRUPT;
    }
    SqliteUtils::DeleteFile(srcPath + "-shm");
    SqliteUtils::DeleteFile(srcPath + "-wal");
    Connection::Delete(config);

    if (config.GetPath() != destPath) {
        RdbStoreConfig dstConfig(destPath);
        Connection::Delete(dstConfig);
    }

    if (!SqliteUtils::CopyFile(srcPath, destPath)) {
        return E_ERROR;
    }
    return E_OK;
}

int32_t SqliteConnection::Restore(const RdbStoreConfig &config, const std::string &srcPath, const std::string &destPath)
{
    if (config.GetHaMode() == HAMode::SINGLE || !SqliteUtils::IsSlaveDbName(srcPath)) {
        return SqliteConnection::CopyDb(config, srcPath, destPath);
    }
    std::shared_ptr<SqliteConnection> connection = std::make_shared<SqliteConnection>(config, true);
    if (connection == nullptr) {
        return E_ERROR;
    }
    RdbStoreConfig slaveConfig = connection->GetSlaveRdbStoreConfig(config);
    if (access(slaveConfig.GetPath().c_str(), F_OK) != 0) {
        return E_NOT_SUPPORT;
    }
    auto [ret, conn] = connection->CreateSlaveConnection(slaveConfig, SlaveOpenPolicy::FORCE_OPEN);
    if (ret != E_OK) {
        return ret;
    }
    connection->slaveConnection_ = conn;

    int openMainRes = connection->InnerOpen(config);
    ret = connection->VeritySlaveIntegrity();
    if (ret != E_OK) {
        return ret;
    }
    if (openMainRes == E_OK && SqliteUtils::IsSlaveInvalid(config.GetPath()) && !connection->IsDbVersionBelowSlave()) {
        return E_SQLITE_CORRUPT;
    }

    ret = SQLiteError::ErrNo(sqlite3_wal_checkpoint_v2(connection->slaveConnection_->dbHandle_, nullptr,
        SQLITE_CHECKPOINT_TRUNCATE, nullptr, nullptr));
    if (ret != E_OK) {
        LOG_ERROR("chk %{public}d %{public}d %{public}s", ret, errno, SqliteUtils::Anonymous(config.GetName()).c_str());
        return ret;
    }
    connection->slaveConnection_ = nullptr;
    connection = nullptr;

    if (!SqliteUtils::RenameFile(slaveConfig.GetPath(), config.GetPath())) {
        LOG_ERROR("rename %{public}d %{public}s", errno, SqliteUtils::Anonymous(config.GetName()).c_str());
        return E_ERROR;
    }
    for (auto &suffix : FILE_SUFFIXES) {
        if (suffix.suffix_ != nullptr && !std::string(suffix.suffix_).empty()) {
            SqliteUtils::DeleteFile(config.GetPath() + suffix.suffix_);
        }
    }
    Connection::Delete(slaveConfig.GetPath());
    return E_OK;
}

bool SqliteConnection::IsInTrans() const
{
    return sqlite3_get_autocommit(dbHandle_) == 0;
}
} // namespace NativeRdb
} // namespace OHOS