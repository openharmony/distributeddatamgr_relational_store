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
#include <securec.h>
#include <sqlite3sym.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <memory>
#include <sstream>
#include <string>

#include "global_resource.h"
#include "logger.h"
#include "raw_data_parser.h"
#include "rdb_errno.h"
#include "rdb_fault_hiview_reporter.h"
#include "rdb_icu_manager.h"
#include "rdb_local_db_observer.h"
#include "rdb_security_manager.h"
#include "rdb_sql_log.h"
#include "rdb_sql_statistic.h"
#include "rdb_store_config.h"
#include "relational_store_client.h"
#include "rdb_time_utils.h"
#include "sqlite3.h"
#include "sqlite_default_function.h"
#include "sqlite_errno.h"
#include "sqlite_global_config.h"
#include "sqlite_utils.h"
#include "string_utils.h"
#include "suspender.h"
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
constexpr int SqliteConnection::RESTORE_PRE_WAIT_TIME;
constexpr ssize_t SqliteConnection::SLAVE_WAL_SIZE_LIMIT;
constexpr ssize_t SqliteConnection::SLAVE_INTEGRITY_CHECK_LIMIT;
constexpr uint32_t SqliteConnection::NO_ITER;
constexpr unsigned short SqliteConnection::BINLOG_FILE_NUMS_LIMIT;
constexpr uint32_t SqliteConnection::BINLOG_FILE_SIZE_LIMIT;
constexpr uint32_t SqliteConnection::DB_INDEX;
constexpr uint32_t SqliteConnection::WAL_INDEX;
constexpr int32_t SERVICE_GID = 3012;
constexpr int32_t BINLOG_FILE_REPLAY_LIMIT = 50;
constexpr char const *SUFFIX_BINLOG = "_binlog/";
ConcurrentMap<std::string, std::weak_ptr<SqliteConnection>> SqliteConnection::reusableReplicas_ = {};
__attribute__((used))
const int32_t SqliteConnection::regCreator_ = Connection::RegisterCreator(DB_SQLITE, SqliteConnection::Create);
__attribute__((used))
const int32_t SqliteConnection::regRepairer_ = Connection::RegisterRepairer(DB_SQLITE, SqliteConnection::Repair);
__attribute__((used))
const int32_t SqliteConnection::regDeleter_ = Connection::RegisterDeleter(DB_SQLITE, SqliteConnection::Delete);
__attribute__((used))
const int32_t SqliteConnection::regCollector_ = Connection::RegisterCollector(DB_SQLITE, SqliteConnection::Collect);
__attribute__((used)) const int32_t SqliteConnection::regGetDbFileser_ =
    Connection::RegisterGetDbFileser(DB_SQLITE, SqliteConnection::GetDbFiles);
__attribute__((used)) const int32_t SqliteConnection::regReplicaChecker_ =
    Connection::RegisterReplicaChecker(DB_SQLITE, SqliteConnection::CheckReplicaIntegrity);
__attribute__((used)) const int32_t SqliteConnection::regDbClientCleaner_ =
    GlobalResource::RegisterClean(GlobalResource::DB_CLIENT, SqliteConnection::ClientCleanUp);
__attribute__((used)) const int32_t SqliteConnection::regOpenSSLCleaner_ =
    GlobalResource::RegisterClean(GlobalResource::OPEN_SSL, SqliteConnection::OpenSSLCleanUp);
__attribute__((used)) const int32_t SqliteConnection::regRekeyExcuter_ =
    Connection::RegisterRekeyExcuter(DB_SQLITE, SqliteConnection::RekeyEx);

std::pair<int32_t, std::shared_ptr<Connection>> SqliteConnection::Create(const RdbStoreConfig &config, bool isWrite)
{
    std::pair<int32_t, std::shared_ptr<Connection>> result = { E_ERROR, nullptr };
    auto &[errCode, conn] = result;
    std::tie(errCode, conn) = InnerCreate(config, isWrite, true);
    return result;
}

int32_t SqliteConnection::Delete(const RdbStoreConfig &config)
{
    auto path = config.GetPath();
    auto binlogFolder = GetBinlogFolderPath(path);
    size_t num = SqliteUtils::DeleteFolder(binlogFolder);
    if (num > 0 && IsSupportBinlog(config)) {
        LOG_INFO("removed %{public}zu binlog related items", num);
    }
    auto slavePath = SqliteUtils::GetSlavePath(path);
    Delete(slavePath);
    Delete(path);
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
    if (config.IsMemoryRdb()) {
        return collection;
    }
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

std::vector<std::string> SqliteConnection::GetDbFiles(const RdbStoreConfig &config)
{
    std::vector<std::string> dbFiles;
    if (config.IsMemoryRdb()) {
        return dbFiles;
    }
    std::string path;
    SqliteGlobalConfig::GetDbPath(config, path);
    for (auto &suffix : FILE_SUFFIXES) {
        auto file = path + suffix.suffix_;
        struct stat fileStat;
        if (stat(file.c_str(), &fileStat) == 0) {
            dbFiles.push_back(StringUtils::ExtractFileName(file));
        }
    }
    if (config.GetHaMode() == HAMode::SINGLE) {
        return dbFiles;
    }
    path = SqliteUtils::GetSlavePath(path);
    for (auto &suffix : FILE_SUFFIXES) {
        auto file = path + suffix.suffix_;
        struct stat fileStat;
        if (stat(file.c_str(), &fileStat) == 0) {
            dbFiles.push_back(StringUtils::ExtractFileName(file));
        }
    }
    return dbFiles;
}

SqliteConnection::SqliteConnection(const RdbStoreConfig &config, bool isWriteConnection, bool isSlave)
    : dbHandle_(nullptr), isWriter_(isWriteConnection), isReadOnly_(false), isSlave_(isSlave), maxVariableNumber_(0),
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
             "%{public}s,[%{public}d,%{public}d,%{public}d,%{public}d,%{public}d]",
        config.GetDBType(), config.GetHaMode(), config.IsEncrypt(), config.GetArea(), config.GetSecurityLevel(),
        config.GetRoleType(), config.IsReadOnly(),
        SqliteUtils::FormatDebugInfoBrief(bugInfo, SqliteUtils::Anonymous(config.GetName())).c_str(),
        SqliteUtils::FormatDebugInfoBrief(Connection::Collect(config_), "master").c_str(), isSlaveExist,
        isSlaveLockExist, hasFailure, walOverLimit, IsSupportBinlog(config_));
    if (config.GetHaMode() == HAMode::MANUAL_TRIGGER && (slaveOpenPolicy == SlaveOpenPolicy::OPEN_IF_DB_VALID &&
        (!isSlaveExist || isSlaveLockExist || hasFailure || walOverLimit))) {
        if (walOverLimit) {
            SqliteUtils::SetSlaveInvalid(config_.GetPath());
            Reportor::ReportCorrupted(Reportor::Create(config, E_SQLITE_ERROR, "ErrorType: slaveWalOverLimit"));
        }
        return result;
    }

    std::shared_ptr<SqliteConnection> connection = std::make_shared<SqliteConnection>(config, true, true);
    connection->SetIsSupportBinlog(IsSupportBinlog(config_));
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
    uint32_t openFileFlags = config.IsReadOnly() ? (SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX)
                                                 : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
    if (config.IsMemoryRdb()) {
        openFileFlags |= SQLITE_OPEN_URI;
    }
    errCode = OpenDatabase(dbPath, static_cast<int>(openFileFlags));
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
                    SqliteUtils::SqlAnonymous(sql).c_str());
                Reportor::ReportCorruptedOnce(Reportor::Create(config, errCode, static_cast<std::string>(checkResult)));
            }
        }
    }
    return E_OK;
}

int32_t SqliteConnection::OpenDatabase(const std::string &dbPath, int openFileFlags)
{
    const char *option = isSlave_ && isSupportBinlog_ ? "compressvfs" : nullptr;
    int errCode = sqlite3_open_v2(dbPath.c_str(), &dbHandle_, openFileFlags, option);
    if (errCode != SQLITE_OK) {
        LOG_ERROR("fail to open database errCode=%{public}d, dbPath=%{public}s, flags=%{public}d, errno=%{public}d",
            errCode, SqliteUtils::Anonymous(dbPath).c_str(), openFileFlags, errno);
        if (isSlave_ && errCode == SQLITE_WARNING &&
            sqlite3_extended_errcode(dbHandle_) == SQLITE_WARNING_NOTCOMPRESSDB) {
            LOG_WARN("slave db is not using compress");
            return E_SQLITE_CORRUPT;
        }
        if (errCode == SQLITE_CANTOPEN) {
            std::pair<int32_t, RdbDebugInfo> fileInfo = SqliteUtils::Stat(dbPath);
            if (fileInfo.first != E_OK) {
                LOG_ERROR("The stat error, errno=%{public}d, parent dir modes: %{public}s", errno,
                    SqliteUtils::GetParentModes(dbPath).c_str());
            }
            Reportor::ReportFault(RdbFaultDbFileEvent(FT_OPEN, E_SQLITE_CANTOPEN, config_,
                "failed to openDB errno[ " + std::to_string(errno) + "]," +
                    SqliteUtils::GetFileStatInfo(fileInfo.second) +
                    "parent dir modes:" + SqliteUtils::GetParentModes(dbPath),
                true));
        }
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
    Suspender suspender(Suspender::SQL_STATISTIC);
    // there is a read-only dependency
    if (!config.GetCollatorLocales().empty()) {
        ConfigLocale(config.GetCollatorLocales());
    }

    if (config.GetRoleType() == VISITOR) {
        return E_OK;
    }

    auto errCode = RegDefaultFunctions(dbHandle_);
    if (errCode != E_OK) {
        return errCode;
    }

    SetBusyTimeout(DEFAULT_BUSY_TIMEOUT_MS);

    LimitPermission(config, dbPath);

    SetDwrEnable(config);
    errCode = SetPersistWal(config);
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

    errCode = SetAutoCheckpoint(config);
    if (errCode != E_OK) {
        return errCode;
    }

    errCode = SetCustomFunctions(config);
    if (errCode != E_OK) {
        return errCode;
    }
    RegisterHookIfNecessary();
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
        int errCode = sqlite3_close_v2(dbHandle_);
        if (errCode != SQLITE_OK) {
            LOG_ERROR("could not close database err = %{public}d, errno = %{public}d", errCode, errno);
        }
    }
    if (isWriter_ && slaveConnection_ != nullptr && IsSupportBinlog(config_)) {
        reusableReplicas_.ComputeIfPresent(slaveConnection_->config_.GetPath(),
            [slaveConn = slaveConnection_](auto &key, auto &weakPtr) {
            auto sharedPtr = weakPtr.lock();
            if (sharedPtr != nullptr && slaveConn == sharedPtr) {
                LOG_INFO("replica connection removed when close");
                return false;
            }
            return true;
        });
    }
}

int32_t SqliteConnection::VerifyAndRegisterHook(const RdbStoreConfig &config)
{
    if (!isWriter_  || config_.IsEqualRegisterInfo(config)) {
        return E_OK;
    }
    for (auto &eventInfo : onEventHandlers_) {
        if (config.GetRegisterInfo(eventInfo.Type) && !config_.GetRegisterInfo(eventInfo.Type)) {
            config_.SetRegisterInfo(eventInfo.Type, true);
            (this->*(eventInfo.handle))();
        }
    }
    return E_OK;
}

int32_t SqliteConnection::RegisterHookIfNecessary()
{
    if (!isWriter_) {
        return E_OK;
    }
    for (auto &eventInfo : onEventHandlers_) {
        if (config_.GetRegisterInfo(eventInfo.Type)) {
            (this->*(eventInfo.handle))();
        }
    }
    return E_OK;
}

int SqliteConnection::RegisterStoreObs()
{
    RegisterDbHook(dbHandle_);
    auto status = CreateDataChangeTempTrigger(dbHandle_);
    if (status != E_OK) {
        LOG_ERROR("CreateDataChangeTempTrigger failed. status %{public}d", status);
        return status;
    }
    return E_OK;
}

int SqliteConnection::RegisterClientObs()
{
    RegisterDbHook(dbHandle_);
    return E_OK;
}

int32_t SqliteConnection::CheckReplicaIntegrity(const RdbStoreConfig &config)
{
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
    if (IsSupportBinlog(config)) {
        SqliteConnection::ReplayBinlog(config.GetPath(), conn, false);
    }
    return connection->VerifySlaveIntegrity();
}

int SqliteConnection::CheckReplicaForRestore()
{
    return ExchangeVerify(true);
}

std::pair<int, std::shared_ptr<Statement>> SqliteConnection::CreateStatement(const std::string &sql,
    std::shared_ptr<Connection> conn)
{
    return CreateStatementInner(sql, conn, dbHandle_, false);
}

std::pair<int, std::shared_ptr<Statement>> SqliteConnection::CreateReplicaStatement(const std::string &sql,
    std::shared_ptr<Connection> conn)
{
    sqlite3 *db = dbHandle_;
    RdbStoreConfig rdbSlaveStoreConfig = GetSlaveRdbStoreConfig(config_);
    if (slaveConnection_ == nullptr && access(rdbSlaveStoreConfig.GetPath().c_str(), F_OK) == 0) {
        auto [errCode, slaveConn] = CreateSlaveConnection(rdbSlaveStoreConfig, SlaveOpenPolicy::FORCE_OPEN);
        if (errCode == E_OK) {
            slaveConnection_ = slaveConn;
            db = slaveConnection_->dbHandle_;
        }
        LOG_INFO("create slave conn ret=%{public}d, %{public}d", errCode, IsWriter());
    }
    return CreateStatementInner(sql, conn, db, true);
}

std::pair<int, std::shared_ptr<Statement>> SqliteConnection::CreateStatementInner(const std::string &sql,
    std::shared_ptr<Connection> conn, sqlite3 *db, bool isFromReplica)
{
    std::shared_ptr<SqliteStatement> statement = std::make_shared<SqliteStatement>(&config_);
    // When memory is not cleared, quick_check reads memory pages and detects damage but does not report it
    if (sql == INTEGRITIES[1] && db != nullptr && mode_ == JournalMode::MODE_WAL) {
        sqlite3_db_release_memory(db);
    }
    int errCode = statement->Prepare(db, sql);
    if (errCode != E_OK) {
        return { errCode, nullptr };
    }
    statement->conn_ = conn;
    if (!isFromReplica && slaveConnection_ && IsWriter() && !IsSupportBinlog(config_) &&
        !SqliteUtils::IsSlaveRestoring(config_.GetPath())) {
        auto slaveStmt = std::make_shared<SqliteStatement>();
        if (sql == INTEGRITIES[1] && dbHandle_ != nullptr && mode_ == JournalMode::MODE_WAL) {
            sqlite3_db_release_memory(dbHandle_);
        }
        slaveStmt->config_ = &slaveConnection_->config_;
        slaveStmt->conn_ = slaveConnection_;
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

    int32_t status = RegisterClientObserver(dbHandle_, [notifier](const ClientChangedData &clientData) {
        DistributedRdb::RdbChangedData rdbChangedData;
        for (auto &[key, val] : clientData.tableData) {
            if (val.isTrackedDataChange || val.isP2pSyncDataChange || val.isKnowledgeDataChange) {
                rdbChangedData.tableData[key].isTrackedDataChange = val.isTrackedDataChange;
                rdbChangedData.tableData[key].isP2pSyncDataChange = val.isP2pSyncDataChange;
                rdbChangedData.tableData[key].isKnowledgeDataChange = val.isKnowledgeDataChange;
            }
        }
        notifier(rdbChangedData);
    });
    if (status != E_OK) {
        LOG_ERROR("RegisterClientObserver error, status:%{public}d", status);
    }
    RegisterDbHook(dbHandle_);
    config_.SetRegisterInfo(RegisterType::CLIENT_OBSERVER, true);
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
    Suspender suspender(Suspender::SQL_LOG);
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
    return SetEncryptAgo(config.GetCryptoParam());
}

int SqliteConnection::SetEncryptAgo(const RdbStoreConfig::CryptoParam &cryptoParam)
{
    Suspender suspender(Suspender::SQL_LOG);
    if (!cryptoParam.IsValid()) {
        LOG_ERROR("Invalid crypto param: %{public}d, %{public}d, %{public}d, %{public}d, %{public}u",
            cryptoParam.iterNum, cryptoParam.encryptAlgo, cryptoParam.hmacAlgo, cryptoParam.kdfAlgo,
            cryptoParam.cryptoPageSize);
        return E_INVALID_ARGS;
    }

    if (cryptoParam.iterNum != NO_ITER) {
        auto errCode =
            ExecuteSql(std::string(GlobalExpr::CIPHER_ALGO_PREFIX) +
                       SqliteUtils::EncryptAlgoDescription(static_cast<EncryptAlgo>(cryptoParam.encryptAlgo)) +
                       std::string(GlobalExpr::ALGO_SUFFIX));
        if (errCode != E_OK) {
            LOG_ERROR("set cipher algo failed, err = %{public}d", errCode);
            return errCode;
        }

        errCode = ExecuteSql(std::string(GlobalExpr::CIPHER_KDF_ITER) + std::to_string(cryptoParam.iterNum));
        if (errCode != E_OK) {
            LOG_ERROR("set kdf iter number V1 failed, err = %{public}d", errCode);
            return errCode;
        }
    }

    auto errCode = ExecuteSql(std::string(GlobalExpr::CODEC_HMAC_ALGO_PREFIX) +
                              SqliteUtils::HmacAlgoDescription(cryptoParam.hmacAlgo) +
                              std::string(GlobalExpr::ALGO_SUFFIX));
    if (errCode != E_OK) {
        LOG_ERROR("set codec hmac algo failed, err = %{public}d", errCode);
        return errCode;
    }

    errCode = ExecuteSql(std::string(GlobalExpr::CODEC_KDF_ALGO_PREFIX) +
                         SqliteUtils::KdfAlgoDescription(cryptoParam.kdfAlgo) +
                         std::string(GlobalExpr::ALGO_SUFFIX));
    if (errCode != E_OK) {
        LOG_ERROR("set codec kdf algo failed, err = %{public}d", errCode);
        return errCode;
    }

    errCode = ExecuteSql(
        std::string(GlobalExpr::CODEC_PAGE_SIZE_PREFIX) + std::to_string(cryptoParam.cryptoPageSize));
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

int SqliteConnection::ResetKey(const RdbStoreConfig &config)
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

int SqliteConnection::Rekey(const RdbStoreConfig::CryptoParam &cryptoParam)
{
    std::vector<uint8_t> key;
    RdbPassword rdbPwd;
    int errCode = E_OK;
    if (cryptoParam.encryptKey_.empty()) {
        rdbPwd = RdbSecurityManager::GetInstance().GetRdbPassword(
            config_.GetPath(), RdbSecurityManager::PUB_KEY_FILE_NEW_KEY);
        key = std::vector<uint8_t>(rdbPwd.GetData(), rdbPwd.GetData() + rdbPwd.GetSize());
    } else {
        key = cryptoParam.encryptKey_;
    }
    if (key.empty()) {
        LOG_ERROR("key is empty");
        return E_ERROR;
    }
    errCode = sqlite3_rekey(dbHandle_, static_cast<const void *>(key.data()), static_cast<int>(key.size()));
    if (errCode != SQLITE_OK) {
        key.assign(key.size(), 0);
        LOG_ERROR("ReKey failed, err = %{public}d, name = %{public}s", errCode,
            SqliteUtils::Anonymous(config_.GetName()).c_str());
        return SQLiteError::ErrNo(errCode);
    }
    errCode = SetEncryptAgo(cryptoParam);
    if (errCode != E_OK) {
        key.assign(key.size(), 0);
        LOG_ERROR("ReKey failed, err = %{public}d, name = %{public}s", errCode,
            SqliteUtils::Anonymous(config_.GetName()).c_str());
        return errCode;
    }
    if (cryptoParam.encryptKey_.empty()) {
        RdbSecurityManager::GetInstance().ChangeKeyFile(config_.GetPath());
    }
    key.assign(key.size(), 0);
    return E_OK;
}

CodecConfig SqliteConnection::ConvertCryptoParamToCodecConfig(const RdbStoreConfig::CryptoParam &param)
{
    CodecConfig config = CreateCodecConfig();
    if (param.encryptAlgo >= EncryptAlgo::AES_256_GCM && param.encryptAlgo < EncryptAlgo::PLAIN_TEXT) {
        config.pCipher = ENCRYPT_ALGOS[param.encryptAlgo];
    }
    if (param.hmacAlgo >= HmacAlgo::SHA1 && param.hmacAlgo < HmacAlgo::HMAC_BUTT) {
        config.pHmacAlgo = HMAC_ALGOS[param.hmacAlgo];
    }
    if (param.kdfAlgo >= KdfAlgo::KDF_SHA1 && param.kdfAlgo < KdfAlgo::KDF_BUTT) {
        config.pKdfAlgo = KDF_ALGOS[param.kdfAlgo];
    }

    config.pKey = param.encryptKey_.empty() ? nullptr : static_cast<const void *>(param.encryptKey_.data());
    config.nKey = static_cast<int>(param.encryptKey_.size());
    if (param.iterNum == 0) {
        config.kdfIter = DEFAULT_ITER_NUM;
    } else {
        config.kdfIter = static_cast<int>(param.iterNum);
    }
    config.pageSize = static_cast<int>(param.cryptoPageSize);
    return config;
}

int RekeyToPlainText(
    const RdbStoreConfig &config, CodecRekeyConfig &rekeyConfig, const RdbStoreConfig::CryptoParam &cryptoParam)
{
    CodecConfig plainTextCfg = { NULL, NULL, NULL, NULL, 0, 0, cryptoParam.cryptoPageSize };
    errno_t err = memcpy_s(&rekeyConfig.rekeyCfg, sizeof(rekeyConfig.rekeyCfg), &plainTextCfg, sizeof(plainTextCfg));
    if (err != 0) {
        LOG_ERROR("memcpy_s rekeyConfig.rekeyCfg failed, err = %{public}d", err);
        return E_ERROR;
    }

    int errCode = sqlite3_rekey_v3(&rekeyConfig);
    if (errCode != SQLITE_OK) {
        LOG_ERROR("ReKeyex to PlainText failed, err = %{public}d, name = %{public}s", errCode,
            SqliteUtils::Anonymous(config.GetName()).c_str());
        return SQLiteError::ErrNo(errCode);
    }
    RdbSecurityManager::GetInstance().DelAllKeyFiles(config.GetPath());
    config.SetEncryptStatus(false);
    config.SetCryptoParam(cryptoParam);
    return E_OK;
}

int RekeyToGenerateKey(const RdbStoreConfig &config, CodecConfig &rekeyCfg, CodecRekeyConfig &rekeyConfig,
    const RdbStoreConfig::CryptoParam &cryptoParam)
{
    std::vector<uint8_t> key;
    int errCode = E_OK;
    if (config.IsCustomEncryptParam() || !config.IsEncrypt()) {
        auto oldkey = config.GetEncryptKey();
        auto oldEncryptStatus = config.IsEncrypt();
        config.ResetEncryptKey(cryptoParam.encryptKey_);
        config.SetEncryptStatus(true);
        errCode = config.Initialize();
        if (errCode != E_OK) {
            key.assign(key.size(), 0);
            config.ResetEncryptKey(oldkey);
            config.SetEncryptStatus(oldEncryptStatus);
            LOG_ERROR("ReKeyex failed, err = %{public}d, name = %{public}s", errCode,
                SqliteUtils::Anonymous(config.GetName()).c_str());
            return errCode;
        }
    }
    auto rdbPwd =
        RdbSecurityManager::GetInstance().GetRdbPassword(config.GetPath(), RdbSecurityManager::PUB_KEY_FILE_NEW_KEY);
    key = std::vector<uint8_t>(rdbPwd.GetData(), rdbPwd.GetData() + rdbPwd.GetSize());
    rekeyCfg.pKey = static_cast<const void *>(key.data());
    rekeyCfg.nKey = static_cast<int>(key.size());
    errno_t err = memcpy_s(&rekeyConfig.rekeyCfg, sizeof(rekeyConfig.rekeyCfg), &rekeyCfg, sizeof(rekeyCfg));
    if (err != 0) {
        LOG_ERROR("memcpy_s rekeyConfig.rekeyCfg failed, err = %{public}d", err);
        return E_ERROR;
    }
    errCode = sqlite3_rekey_v3(&rekeyConfig);
    if (errCode != SQLITE_OK) {
        key.assign(key.size(), 0);
        return SQLiteError::ErrNo(errCode);
    }
    RdbSecurityManager::GetInstance().ChangeKeyFile(config.GetPath());
    config.SetCryptoParam(cryptoParam);
    config.ResetEncryptKey(key);
    oldkey.assign(oldkey.size(), 0);
    key.assign(key.size(), 0);
    return E_OK;
}

int RekeyToCustomKey(const RdbStoreConfig &config, CodecConfig &rekeyCfg, CodecRekeyConfig &rekeyConfig,
    const RdbStoreConfig::CryptoParam &cryptoParam)
{
    std::vector<uint8_t> key;
    int errCode = E_OK;
    key = cryptoParam.encryptKey_;
    if (key.empty()) {
        LOG_ERROR("key is empty");
        return E_ERROR;
    }
    rekeyCfg.pKey = static_cast<const void *>(key.data());
    rekeyCfg.nKey = static_cast<int>(key.size());
    errno_t err = memcpy_s(&rekeyConfig.rekeyCfg, sizeof(rekeyConfig.rekeyCfg), &rekeyCfg, sizeof(rekeyCfg));
    if (err != 0) {
        LOG_ERROR("memcpy_s rekeyConfig.rekeyCfg failed, err = %{public}d", err);
        return E_ERROR;
    }

    errCode = sqlite3_rekey_v3(&rekeyConfig);
    if (errCode != SQLITE_OK) {
        key.assign(key.size(), 0);
        LOG_ERROR("ReKey failed, err = %{public}d, name = %{public}s", errCode,
            SqliteUtils::Anonymous(config.GetName()).c_str());
        return SQLiteError::ErrNo(errCode);
    }
    config.ResetEncryptKey(cryptoParam.encryptKey_);
    config.SetCryptoParam(cryptoParam);
    RdbSecurityManager::GetInstance().DelAllKeyFiles(config.GetPath());
    key.assign(key.size(), 0);
    return E_OK;
}

int SqliteConnection::RekeyEx(const RdbStoreConfig &config, const RdbStoreConfig::CryptoParam &cryptoParam)
{
    std::vector<uint8_t> key;
    RdbPassword rdbPwd;
    int errCode = E_OK;
    auto path = config.GetPath();
    const char *dbPath = path.c_str();
    auto param = config.GetCryptoParam();
    CodecConfig dbCfg = ConvertCryptoParamToCodecConfig(param);
    CodecConfig rekeyCfg = ConvertCryptoParamToCodecConfig(cryptoParam);
    if (cryptoParam.encryptAlgo != EncryptAlgo::PLAIN_TEXT && cryptoParam.iterNum == 0) {
        cryptoParam.encryptAlgo = EncryptAlgo::AES_256_GCM;
        rekeyCfg.kdfIter = DEFAULT_ITER_NUM;
        rekeyCfg.pCipher = "aes-256-gcm";
    }
    CodecRekeyConfig rekeyConfig;
    rekeyConfig.dbPath = dbPath;
    rekeyConfig.dbCfg = dbCfg;
    rekeyConfig.rekeyCfg = rekeyCfg;
    if (cryptoParam.encryptAlgo == EncryptAlgo::PLAIN_TEXT) {
        return RekeyToPlainText(config, rekeyConfig, cryptoParam);
    }
    if (cryptoParam.encryptKey_.empty()) {
        errCode = RekeyToGenerateKey(config, rekeyCfg, rekeyConfig, cryptoParam);
    } else {
        errCode = RekeyToCustomKey(config, rekeyCfg, rekeyConfig, cryptoParam);
    }
    return errCode;
}

void SqliteConnection::SetDwrEnable(const RdbStoreConfig &config)
{
    if (config.IsEncrypt() || config.IsMemoryRdb()) {
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
    if (config.IsMemoryRdb()) {
        return E_NOT_SUPPORT;
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
        ResetKey(config);
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
    Suspender suspender(Suspender::SQL_LOG);
    errCode = SetEncryptAgo(config);
    if (errCode != E_OK) {
        return errCode;
    }

    if (IsWriter() || config.IsReadOnly()) {
        ValueObject version;
        std::tie(errCode, version) = ExecuteForValue(GlobalExpr::PRAGMA_VERSION);
        if (errCode != E_OK || version.GetType() == ValueObject::TYPE_NULL) {
            return errCode;
        }
        return E_OK;
    }
    return errCode;
}

int SqliteConnection::SetPersistWal(const RdbStoreConfig &config)
{
    if (config.IsMemoryRdb()) {
        return E_OK;
    }
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
    if (isReadOnly_ || config.IsMemoryRdb()) {
        return E_OK;
    }

    auto [errCode, object] = ExecuteForValue("PRAGMA journal_mode");
    if (errCode != E_OK) {
        LOG_ERROR("SetJournalMode fail to get journal mode : %{public}d, errno %{public}d", errCode, errno);
        Reportor::ReportFault(RdbFaultEvent(FT_OPEN, E_DFX_GET_JOURNAL_FAIL, config_.GetBundleName(),
            "PRAGMA journal_mode get fail: " + std::to_string(errCode) + "," + std::to_string(errno)));
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
            Reportor::ReportFault(RdbFaultEvent(FT_OPEN, E_DFX_SET_JOURNAL_FAIL, config_.GetBundleName(),
                "PRAGMA journal_mode set fail: " +  std::to_string(errCode) + "," + std::to_string(errno) + "," +
                config.GetJournalMode()));
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

int SqliteConnection::SetAutoCheckpoint(const RdbStoreConfig &config)
{
    if (isReadOnly_ || config.IsMemoryRdb()) {
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
    Suspender suspender(Suspender::SQL_LOG);
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
    Suspender suspender(Suspender::SQL_LOG);
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

int SqliteConnection::ClearCache(bool isForceClear)
{
    if (dbHandle_ != nullptr && mode_ == JournalMode::MODE_WAL) {
        auto getUsedBytes = [dbHandle = dbHandle_]() -> int {
            int usedBytes = 0;
            int nEntry = 0;
            sqlite3_db_status(dbHandle, SQLITE_DBSTATUS_CACHE_USED, &usedBytes, &nEntry, 0);
            return usedBytes;
        };
        if (isForceClear || getUsedBytes() > config_.GetClearMemorySize()) {
            sqlite3_db_release_memory(dbHandle_);
        }
    }
    if (slaveConnection_) {
        int errCode = slaveConnection_->ClearCache(isForceClear);
        if (errCode != E_OK) {
            LOG_ERROR("slaveConnection clearCache failed:%{public}d", errCode);
        }
    }
    return E_OK;
}

void SqliteConnection::LimitPermission(const RdbStoreConfig &config, const std::string &dbPath) const
{
    if (config.IsMemoryRdb()) {
        return;
    }
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
    return RdbICUManager::GetInstance().ConfigLocale(dbHandle_, localeStr);
}

int32_t SqliteConnection::SetTokenizer(Tokenizer tokenizer)
{
    if (tokenizer != CUSTOM_TOKENIZER) {
        return E_OK;
    }
    int err = sqlite3_db_config(
        dbHandle_, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, SqliteUtils::ENABLE_LOAD_EXTENSION, nullptr);
    if (err != SQLITE_OK) {
        LOG_ERROR("enable failed, err=%{public}d, errno=%{public}d", err, errno);
        return SQLiteError::ErrNo(err);
    }
    err = sqlite3_load_extension(dbHandle_, "libcustomtokenizer.z.so", nullptr, nullptr);
    if (err != SQLITE_OK) {
        LOG_ERROR("load error. err=%{public}d, errno=%{public}d, errmsg:%{public}s", err, errno,
            sqlite3_errmsg(dbHandle_));
    }
    int ret = sqlite3_db_config(
        dbHandle_, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, SqliteUtils::DISABLE_LOAD_EXTENSION, nullptr);
    if (ret != SQLITE_OK) {
        LOG_ERROR("disable failed, err=%{public}d, errno=%{public}d", err, errno);
    }
    return SQLiteError::ErrNo(err == SQLITE_OK ? ret : err);
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

int32_t SqliteConnection::Subscribe(const std::shared_ptr<DistributedDB::StoreObserver> &observer)
{
    if (!isWriter_ || observer == nullptr) {
        return E_OK;
    }
    int32_t errCode = RegisterStoreObserver(dbHandle_, observer);
    if (errCode != E_OK) {
        return errCode;
    }
    RegisterDbHook(dbHandle_);
    config_.SetRegisterInfo(RegisterType::STORE_OBSERVER, true);
    return E_OK;
}

int32_t SqliteConnection::Unsubscribe(const std::shared_ptr<DistributedDB::StoreObserver> &observer)
{
    if (!isWriter_ || observer == nullptr) {
        return E_OK;
    }
    int32_t errCode = UnregisterStoreObserver(dbHandle_, observer);
    if (errCode != 0) {
        return errCode;
    }
    return E_OK;
}

int32_t SqliteConnection::Backup(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey,
    bool isAsync, std::shared_ptr<SlaveStatus> slaveStatus, bool verifyDb)
{
    if (*slaveStatus == SlaveStatus::BACKING_UP) {
        LOG_INFO("backing up, return:%{public}s", SqliteUtils::Anonymous(config_.GetName()).c_str());
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
            InsertReusableReplica(rdbSlaveStoreConfig.GetPath(), conn);
        }
        return ExchangeSlaverToMaster(false, verifyDb, slaveStatus);
    }

    if (backupId_ == TaskExecutor::INVALID_TASK_ID) {
        auto pool = TaskExecutor::GetInstance().GetExecutor();
        if (pool == nullptr) {
            LOG_WARN("task pool err when restore");
            return E_OK;
        }
        backupId_ = pool->Execute([this, slaveStatus]() {
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
    const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey,
    std::shared_ptr<SlaveStatus> slaveStatus)
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
    param.subUser_ = config.GetSubUser();
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

int SqliteConnection::ExchangeSlaverToMaster(bool isRestore, bool verifyDb, std::shared_ptr<SlaveStatus> curStatus)
{
    bool isNeedSetAcl = SqliteUtils::HasAccessAcl(config_.GetPath(), SERVICE_GID) ||
                        SqliteUtils::HasAccessAcl(SqliteUtils::GetSlavePath(config_.GetPath()), SERVICE_GID);
    *curStatus = SlaveStatus::BACKING_UP;
    int err = verifyDb ? ExchangeVerify(isRestore) : E_OK;
    if (err != E_OK) {
        *curStatus = SlaveStatus::UNDEFINED;
        return err;
    }

    err = SqliteNativeBackup(isRestore, curStatus, isNeedSetAcl);
    if (err != E_OK) {
        return err;
    }
    if (!isRestore && IsSupportBinlog(config_) && config_.GetHaMode() != HAMode::SINGLE) {
        LOG_INFO("reset binlog start");
        sqlite3_db_config(dbHandle_, SQLITE_DBCONFIG_ENABLE_BINLOG, nullptr);
        SetBinlog();
        err = sqlite3_clean_binlog(dbHandle_, BinlogFileCleanModeE::BINLOG_FILE_CLEAN_ALL_MODE);
        if (err != SQLITE_OK) {
            sqlite3_db_config(dbHandle_, SQLITE_DBCONFIG_ENABLE_BINLOG, nullptr);
            SqliteUtils::SetSlaveInvalid(config_.GetPath());
        }
        if (isNeedSetAcl) {
            std::string binlogDir = config_.GetPath() + SUFFIX_BINLOG;
            bool setBinlog = SqliteUtils::SetDbDirGid(binlogDir, SERVICE_GID, true);
            if (!setBinlog) {
                LOG_ERROR("SetBinlog fail, bundleName is %{public}s, store is %{public}s.",
                    config_.GetBundleName().c_str(), SqliteUtils::Anonymous(config_.GetName()).c_str());
            }
        }
        LOG_INFO("reset binlog finished, %{public}d", err);
    }
    return E_OK;
}


int SqliteConnection::SqliteBackupStep(bool isRestore, sqlite3_backup *pBackup, std::shared_ptr<SlaveStatus> curStatus)
{
    int sleepTime = BACKUP_PRE_WAIT_TIME;
    if (isRestore) {
        sleepTime = SqliteUtils::IsSlaveRestoring(config_.GetPath()) ? RESTORE_PRE_WAIT_TIME : 0;
    }
    int rc = SQLITE_OK;
    do {
        if (!isRestore && (*curStatus == SlaveStatus::BACKUP_INTERRUPT || *curStatus == SlaveStatus::DB_CLOSING)) {
            rc = E_CANCEL;
            break;
        }
        rc = sqlite3_backup_step(pBackup, BACKUP_PAGES_PRE_STEP);
        LOG_INFO("backup slave process cur/total:%{public}d/%{public}d, rs:%{public}d,isRestore:%{public}d,%{public}d",
            sqlite3_backup_pagecount(pBackup) - sqlite3_backup_remaining(pBackup), sqlite3_backup_pagecount(pBackup),
            rc, isRestore, sleepTime);
        if (sleepTime > 0) {
            sqlite3_sleep(sleepTime);
        }
    } while (sqlite3_backup_pagecount(pBackup) != 0 && (rc == SQLITE_OK || rc == SQLITE_BUSY || rc == SQLITE_LOCKED));
    (void)sqlite3_backup_finish(pBackup);
    return rc;
}

int SqliteConnection::SqliteNativeBackup(bool isRestore, std::shared_ptr<SlaveStatus> curStatus, bool isNeedSetAcl)
{
    sqlite3 *dbFrom = isRestore ? dbHandle_ : slaveConnection_->dbHandle_;
    sqlite3 *dbTo = isRestore ? slaveConnection_->dbHandle_ : dbHandle_;
    sqlite3_backup *pBackup = sqlite3_backup_init(dbFrom, "main", dbTo, "main");
    if (pBackup == nullptr) {
        LOG_WARN("slave backup init failed");
        *curStatus = SlaveStatus::UNDEFINED;
        return E_OK;
    }
    int rc = SqliteBackupStep(isRestore, pBackup, curStatus);
    if (isNeedSetAcl) {
        std::vector<std::string> dbFiles = Connection::GetDbFiles(config_);
        if (!SqliteUtils::SetDbFileGid(config_.GetPath(), dbFiles, SERVICE_GID)) {
            LOG_ERROR("SetDbFile fail when backup, bundleName is %{public}s, store is %{public}s.",
                config_.GetBundleName().c_str(), SqliteUtils::Anonymous(config_.GetName()).c_str());
        }
    }
    if (rc != SQLITE_DONE) {
        LOG_ERROR("backup slave err:%{public}d, isRestore:%{public}d", rc, isRestore);
        if (!isRestore) {
            RdbStoreConfig slaveConfig(slaveConnection_->config_.GetPath());
            if (rc != SQLITE_BUSY && rc != SQLITE_LOCKED) {
                slaveConnection_ = nullptr;
                (void)SqliteConnection::Delete(slaveConfig.GetPath());
            }
            *curStatus = SlaveStatus::BACKUP_INTERRUPT;
            Reportor::ReportCorrupted(Reportor::Create(slaveConfig, SQLiteError::ErrNo(rc), "ErrorType: slaveBackup"));
        }
        return rc == E_CANCEL ? E_CANCEL : SQLiteError::ErrNo(rc);
    }
    rc = isRestore ? TryCheckPoint(true) : slaveConnection_->TryCheckPoint(true);
    if (rc != E_OK && config_.GetHaMode() == HAMode::MANUAL_TRIGGER) {
        if (!isRestore) {
            *curStatus = SlaveStatus::BACKUP_INTERRUPT;
        }
        LOG_WARN("CheckPoint failed err:%{public}d, isRestore:%{public}d", rc, isRestore);
        return E_OK;
    }
    *curStatus = SlaveStatus::BACKUP_FINISHED;
    SqliteUtils::SetSlaveValid(config_.GetPath());
    LOG_INFO("backup slave success, isRestore:%{public}d", isRestore);
    return E_OK;
}

ExchangeStrategy SqliteConnection::GenerateExchangeStrategy(std::shared_ptr<SlaveStatus> status, bool isRelpay)
{
    if (dbHandle_ == nullptr || slaveConnection_ == nullptr || slaveConnection_->dbHandle_ == nullptr ||
        config_.GetHaMode() == HAMode::SINGLE || *status == SlaveStatus::BACKING_UP) {
        return ExchangeStrategy::NOT_HANDLE;
    }
    const std::string querySql = "SELECT COUNT(*) FROM sqlite_master WHERE type='table';";
    const std::string qIndexSql = "SELECT COUNT(*) FROM sqlite_master WHERE type='index';";
    auto [mRet, mObj] = ExecuteForValue(querySql);
    auto [mIdxRet, mIdxObj] = ExecuteForValue(qIndexSql);
    if (mRet == E_SQLITE_CORRUPT || mIdxRet == E_SQLITE_CORRUPT) {
        LOG_WARN("main abnormal, err:%{public}d", mRet);
        return ExchangeStrategy::RESTORE;
    }
    int64_t mCount = static_cast<int64_t>(mObj);
    int64_t mIdxCount = static_cast<int64_t>(mIdxObj);
    // trigger mode only does restore, not backup
    if (config_.GetHaMode() == HAMode::MANUAL_TRIGGER) {
        return mCount == 0 ? ExchangeStrategy::RESTORE : ExchangeStrategy::NOT_HANDLE;
    }
    if (*status == SlaveStatus::DB_CLOSING) {
        return ExchangeStrategy::NOT_HANDLE;
    }
    if (*status == SlaveStatus::BACKUP_INTERRUPT) {
        return ExchangeStrategy::BACKUP;
    }
    if (IsSupportBinlog(config_)) {
        if (isRelpay || (mCount == 0 && !SqliteUtils::IsUseAsyncRestore(config_, config_.GetPath(),
            SqliteUtils::GetSlavePath(config_.GetPath())))) {
            SqliteConnection::ReplayBinlog(config_.GetPath(), slaveConnection_, false);
        } else if (mCount == 0) {
            LOG_INFO("main empty");
            return ExchangeStrategy::RESTORE;
        } else {
            return ExchangeStrategy::PENDING_BACKUP;
        }
    }
    return CompareWithSlave(mCount, mIdxCount);
}

int SqliteConnection::SetKnowledgeSchema(const DistributedRdb::RdbKnowledgeSchema &schema)
{
    DistributedDB::DBStatus status = DistributedDB::DBStatus::OK;
    for (const auto &table : schema.tables) {
        DistributedDB::KnowledgeSourceSchema sourceSchema;
        sourceSchema.tableName = table.tableName;
        for (const auto &item : table.knowledgeFields) {
            sourceSchema.knowledgeColNames.insert(item.columnName);
        }
        sourceSchema.extendColNames = std::set<std::string>(table.referenceFields.begin(),
            table.referenceFields.end());
        status = SetKnowledgeSourceSchema(dbHandle_, sourceSchema);
        if (status != DistributedDB::DBStatus::OK) {
            return E_ERROR;
        }
    }
    return E_OK;
}

int SqliteConnection::CleanDirtyLog(const std::string &table, uint64_t cursor)
{
    if (table.empty()) {
        LOG_ERROR("table is empty");
        return E_INVALID_ARGS;
    }
    auto status = CleanDeletedData(dbHandle_, table, cursor);
    return status == DistributedDB::DBStatus::OK ? E_OK : E_ERROR;
}

int32_t SqliteConnection::Repair(const RdbStoreConfig &config)
{
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
    if (IsSupportBinlog(config)) {
        SqliteConnection::ReplayBinlog(config.GetPath(), conn, false);
    }
    ret = connection->VerifySlaveIntegrity();
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
    std::shared_ptr<SlaveStatus> curStatus = std::make_shared<SlaveStatus>(SlaveStatus::UNDEFINED);
    ret = connection->ExchangeSlaverToMaster(true, false, curStatus);
    if (ret != E_OK) {
        auto slavePath = SqliteUtils::GetSlavePath(config.GetPath());
        LOG_ERROR("repair failed, [%{public}s]->[%{public}s], err:%{public}d",
            SqliteUtils::Anonymous(slavePath).c_str(), SqliteUtils::Anonymous(config.GetName()).c_str(), ret);
    } else {
        LOG_INFO("repair main success:%{public}s", SqliteUtils::Anonymous(config.GetPath()).c_str());
    }
    return ret;
}

int SqliteConnection::ExchangeVerify(bool isRestore)
{
    if (isRestore) {
        SqliteConnection::ReplayBinlog(config_);
        int err = VerifySlaveIntegrity();
        if (err != E_OK) {
            return err;
        }
        if (IsDbVersionBelowSlave()) {
            return E_OK;
        }
        if (SqliteUtils::IsSlaveInvalid(config_.GetPath())) {
            LOG_ERROR("incomplete slave, %{public}s", SqliteUtils::Anonymous(config_.GetName()).c_str());
            return E_SQLITE_CORRUPT;
        }
        return E_OK;
    }
    if (slaveConnection_ == nullptr) {
        return E_ALREADY_CLOSED;
    }
    if (access(config_.GetPath().c_str(), F_OK) != 0) {
        LOG_WARN("main no exist, isR:%{public}d, %{public}s", isRestore,
            SqliteUtils::Anonymous(config_.GetName()).c_str());
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
    const RdbStoreConfig &config, bool isWrite, bool isReusableReplica)
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
        if (err != E_OK) {
            return result;
        }
        conn->slaveConnection_ = slaveConn;
        conn->SetBinlog();
        if (isReusableReplica) {
            InsertReusableReplica(slaveCfg.GetPath(), slaveConn);
        }
        if (!IsSupportBinlog(config)) {
            auto binlogFolder = GetBinlogFolderPath(config.GetPath());
            if (access(binlogFolder.c_str(), F_OK) == 0) {
                SqliteUtils::SetSlaveInvalid(config.GetPath());
                size_t num = SqliteUtils::DeleteFolder(binlogFolder);
                LOG_INFO("binlog files found, %{public}zu deleted", num);
            }
        }
    }
    return result;
}

int SqliteConnection::VerifySlaveIntegrity()
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
    Suspender suspender(Suspender::SQL_LOG);
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
    ssize_t slaveSize = 0;
    if (IsSupportBinlog(config_)) {
        slaveSize = SqliteUtils::GetDecompressedSize(slaveCfg.GetPath());
    }
    if (slaveSize == 0 && bugInfo.find(FILE_SUFFIXES[DB_INDEX].debug_) != bugInfo.end()) {
        slaveSize = bugInfo[FILE_SUFFIXES[DB_INDEX].debug_].size_;
    }
    if (slaveSize > SLAVE_INTEGRITY_CHECK_LIMIT && mCount == 0L) {
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
    Suspender suspender(Suspender::SQL_LOG);
    auto [cRet, cObj] = ExecuteForValue("SELECT COUNT(*) FROM sqlite_master WHERE type='table';");
    auto cVal = std::get_if<int64_t>(&cObj.value);
    if (cRet == E_SQLITE_CORRUPT || (cVal != nullptr && (static_cast<int64_t>(*cVal) == 0L))) {
        LOG_INFO("main empty, %{public}d, %{public}s", cRet, SqliteUtils::Anonymous(config_.GetName()).c_str());
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

void SqliteConnection::BinlogOnErrFunc(void *pCtx, int errNo, char *errMsg, const char *dbPath)
{
    if (dbPath == nullptr) {
        LOG_WARN("path is null");
        return;
    }
    std::string dbPathStr(dbPath);
    LOG_WARN("binlog failed, mark invalid %{public}s", SqliteUtils::Anonymous(dbPathStr).c_str());
    SqliteUtils::SetSlaveInvalid(dbPathStr);
}

int SqliteConnection::BinlogOpenHandle(const std::string &dbPath, sqlite3 *&dbHandle, bool isMemoryRdb)
{
    uint32_t openFileFlags = (SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX);
    if (isMemoryRdb) {
        openFileFlags |= SQLITE_OPEN_URI;
    }
    sqlite3 *db = nullptr;
    int err = sqlite3_open_v2(dbPath.c_str(), &db, static_cast<int>(openFileFlags), nullptr);
    if (err != SQLITE_OK) {
        LOG_ERROR("open binlog handle error. rc=%{public}d, errno=%{public}d, p=%{public}s",
            err, errno, SqliteUtils::Anonymous(dbPath).c_str());
        sqlite3_close_v2(db);
        return E_INVALID_FILE_PATH;
    }
    dbHandle = db;
    return E_OK;
}

void SqliteConnection::BinlogCloseHandle(sqlite3 *dbHandle)
{
    if (dbHandle != nullptr) {
        int errCode = sqlite3_close_v2(dbHandle);
        if (errCode != SQLITE_OK) {
            LOG_ERROR("could not close binlog handle err = %{public}d, errno = %{public}d", errCode, errno);
        }
    }
}

int SqliteConnection::CheckPathExist(const std::string &dbPath)
{
    bool isDbFileExist = access(dbPath.c_str(), F_OK) == 0;
    if (!isDbFileExist) {
        LOG_ERROR("db %{public}s not exist errno is %{public}d",
            SqliteUtils::Anonymous(dbPath).c_str(), errno);
        return E_DB_NOT_EXIST;
    }
    return E_OK;
}

void SqliteConnection::BinlogSetConfig(sqlite3 *dbHandle)
{
    Sqlite3BinlogConfig binLogConfig = {
        .mode = Sqlite3BinlogMode::ROW,
        .fullCallbackThreshold = BINLOG_FILE_NUMS_LIMIT,
        .maxFileSize = BINLOG_FILE_SIZE_LIMIT,
        .xErrorCallback = &BinlogOnErrFunc,
        .xLogFullCallback = nullptr,
        .callbackCtx = nullptr,
    };

    int err = sqlite3_db_config(dbHandle, SQLITE_DBCONFIG_ENABLE_BINLOG, &binLogConfig);
    if (err != SQLITE_OK) {
        LOG_ERROR("set binlog config error. err=%{public}d, errno=%{public}d", err, errno);
    }
}

void SqliteConnection::InsertReusableReplica(const std::string &dbPath, std::weak_ptr<SqliteConnection> slaveConn)
{
    reusableReplicas_.Compute(dbPath, [slaveConn](auto &key, auto &weakPtr) {
        auto sharedPtr = weakPtr.lock();
        if (sharedPtr == nullptr) {
            weakPtr = slaveConn;
        }
        return true;
    });
}

std::shared_ptr<SqliteConnection> SqliteConnection::GetReusableReplica(const std::string &dbPath)
{
    auto [found, weakPtr] = reusableReplicas_.Find(SqliteUtils::GetSlavePath(dbPath));
    if (!found) {
        LOG_WARN("no replica connection for %{public}s", SqliteUtils::Anonymous(dbPath).c_str());
        return nullptr;
    }
    auto slaveConn = weakPtr.lock();
    if (slaveConn == nullptr) {
        LOG_WARN("replica connection expired for %{public}s", SqliteUtils::Anonymous(dbPath).c_str());
    }
    return slaveConn;
}

void SqliteConnection::BinlogOnFullFunc(void *pCtx, unsigned short currentCount, const char *dbPath)
{
    if (dbPath == nullptr) {
        LOG_WARN("path is null");
        return;
    }
    if (SqliteUtils::IsSlaveInvalid(dbPath)) {
        LOG_WARN("replica invalid, skip binlog replay. count:%{public}" PRIu16, currentCount);
        return;
    }
    std::string dbPathStr(dbPath);
    auto lockFile = dbPathStr + BINLOG_LOCK_FILE_SUFFIX;
    if (access(lockFile.c_str(), F_OK) != 0) {
        LOG_WARN("binlog lock path does not exist for %{public}s", SqliteUtils::Anonymous(dbPathStr).c_str());
        return;
    }
    auto readLock = std::make_shared<RdbSecurityManager::KeyFiles>(lockFile);
    if (readLock == nullptr) {
        LOG_WARN("create read lock failed");
        return;
    }
    auto err = readLock->Lock(false);
    if (err != E_OK) {
        LOG_WARN("get lock failed, skip binlog replay for %{public}s", SqliteUtils::Anonymous(dbPathStr).c_str());
        return;
    }
    auto pool = TaskExecutor::GetInstance().GetExecutor();
    if (pool == nullptr) {
        readLock->Unlock();
        LOG_WARN("get pool failed");
        return;
    }
    auto slaveConn = GetReusableReplica(dbPath);
    if (slaveConn == nullptr) {
        readLock->Unlock();
        return;
    }
    auto taskId = pool->Execute([dbPathStr, slaveConn, readLock] {
        LOG_INFO("task start: binlog replay for %{public}s", SqliteUtils::Anonymous(dbPathStr).c_str());
        SqliteConnection::ReplayBinlog(dbPathStr, slaveConn, true);
        readLock->Unlock();
    });
    if (taskId == TaskExecutor::INVALID_TASK_ID) {
        LOG_WARN("start task failed, remove lock for %{public}s", SqliteUtils::Anonymous(dbPathStr).c_str());
        readLock->Unlock();
    }
}

int SqliteConnection::SetBinlog()
{
    if (!IsSupportBinlog(config_)) {
        return E_OK;
    }
    Sqlite3BinlogConfig binLogConfig = {
        .mode = Sqlite3BinlogMode::ROW,
        .fullCallbackThreshold = BINLOG_FILE_NUMS_LIMIT,
        .maxFileSize = BINLOG_FILE_SIZE_LIMIT,
        .xErrorCallback = &BinlogOnErrFunc,
        .xLogFullCallback = &BinlogOnFullFunc,
        .callbackCtx = nullptr,
    };

    LOG_INFO("binlog: open %{public}s", SqliteUtils::Anonymous(config_.GetPath()).c_str());
    int err = sqlite3_db_config(dbHandle_, SQLITE_DBCONFIG_ENABLE_BINLOG, &binLogConfig);
    if (err != SQLITE_OK) {
        LOG_ERROR("set binlog error. err=%{public}d, errno=%{public}d", err, errno);
        return err;
    }
    return E_OK;
}

void SqliteConnection::ReplayBinlog(const std::string &dbPath,
    std::shared_ptr<SqliteConnection> slaveConn, bool isNeedClean)
{
    auto errCode = SqliteConnection::CheckPathExist(dbPath);
    if (errCode != E_OK) {
        LOG_WARN("main db does not exist, %{public}d", errCode);
        return;
    }
    if (slaveConn == nullptr || slaveConn->dbHandle_ == nullptr) {
        LOG_WARN("backup db does not exist, %{public}d", slaveConn == nullptr);
        return;
    }
    if (slaveConn->config_.GetHaMode() == HAMode::MANUAL_TRIGGER &&
        (SqliteUtils::GetFileCount(GetBinlogFolderPath(dbPath)) > BINLOG_FILE_REPLAY_LIMIT)) {
        LOG_WARN("binlog file count over limit: %{public}s", SqliteUtils::Anonymous(dbPath).c_str());
        SqliteUtils::SetSlaveInvalid(dbPath);
        return;
    }
    sqlite3 *dbFrom = nullptr;
    errCode = SqliteConnection::BinlogOpenHandle(dbPath, dbFrom, false);
    if (errCode != E_OK) {
        return;
    }
    SqliteConnection::BinlogSetConfig(dbFrom);
    errCode = SQLiteError::ErrNo(sqlite3_replay_binlog(dbFrom, slaveConn->dbHandle_));
    if (errCode != E_OK) {
        LOG_WARN("async replay err:%{public}d", errCode);
    } else if (isNeedClean) {
        errCode = SQLiteError::ErrNo(sqlite3_clean_binlog(dbFrom, BinlogFileCleanModeE::BINLOG_FILE_CLEAN_READ_MODE));
        LOG_INFO("clean finished, %{public}d, %{public}s", errCode, SqliteUtils::Anonymous(dbPath).c_str());
    }
    SqliteConnection::BinlogCloseHandle(dbFrom);
    return;
}

void SqliteConnection::ReplayBinlog(const RdbStoreConfig &config)
{
    if (!IsSupportBinlog(config)) {
        return;
    }
    if (slaveConnection_ == nullptr) {
        LOG_WARN("back up does not exist");
        return;
    }
    if (SqliteConnection::CheckPathExist(config.GetPath()) != E_OK) {
        LOG_WARN("main db does not exist");
        return;
    }
    int err = SQLiteError::ErrNo(sqlite3_replay_binlog(dbHandle_, slaveConnection_->dbHandle_));
    if (err != E_OK) {
        LOG_WARN("replay err:%{public}d", err);
    }
    return;
}

void SqliteConnection::SetIsSupportBinlog(bool isSupport)
{
    isSupportBinlog_ = isSupport;
}

bool SqliteConnection::IsSupportBinlog(const RdbStoreConfig &config)
{
#if !defined(CROSS_PLATFORM)
    if (sqlite3_is_support_binlog == nullptr) {
        return false;
    }
    if (sqlite3_is_support_binlog(config.GetName().c_str()) != SQLITE_OK) {
        return false;
    }
    return !config.IsEncrypt() && !config.IsMemoryRdb();
#else
    return false;
#endif
}

std::string SqliteConnection::GetBinlogFolderPath(const std::string &dbPath)
{
    std::string suffix(BINLOG_FOLDER_SUFFIX);
    return dbPath + suffix;
}

ExchangeStrategy SqliteConnection::CompareWithSlave(int64_t mCount, int64_t mIdxCount)
{
    const std::string querySql = "SELECT COUNT(*) FROM sqlite_master WHERE type='table';";
    const std::string qIndexSql = "SELECT COUNT(*) FROM sqlite_master WHERE type='index';";
    auto [sRet, sObj] = slaveConnection_->ExecuteForValue(querySql);
    auto [sInxRet, sInxObj] = slaveConnection_->ExecuteForValue(qIndexSql);
    if (sRet == E_SQLITE_CORRUPT || sInxRet == E_SQLITE_CORRUPT) {
        LOG_WARN("slave db abnormal, need backup, err:%{public}d", sRet);
        return ExchangeStrategy::BACKUP;
    }
    int64_t sCount = static_cast<int64_t>(sObj);
    int64_t sIdxCount = static_cast<int64_t>(sInxObj);
    if ((mCount == sCount && mIdxCount == sIdxCount) && !SqliteUtils::IsSlaveInvalid(config_.GetPath())) {
        LOG_INFO("equal, main:%{public}" PRId64 ",slave:%{public}" PRId64, mCount, sCount);
        return ExchangeStrategy::NOT_HANDLE;
    }
    if (mCount == 0) {
        LOG_INFO("main empty, main:%{public}" PRId64 ",slave:%{public}" PRId64, mCount, sCount);
        return ExchangeStrategy::RESTORE;
    }
    LOG_INFO("backup, main:[%{public}" PRId64 ",%{public}" PRId64 "], slave:[%{public}" PRId64 ",%{public}" PRId64 "]",
        mCount, mIdxCount, sCount, sIdxCount);
    return ExchangeStrategy::BACKUP;
}

int SqliteConnection::RegisterAlgo(const std::string &clstAlgoName, ClusterAlgoFunc func)
{
    return E_NOT_SUPPORT;
}

int32_t SqliteConnection::ClientCleanUp()
{
    Clean(false);
    return E_OK;
}

int32_t SqliteConnection::OpenSSLCleanUp()
{
    Clean(true);
    return E_OK;
}
} // namespace NativeRdb
} // namespace OHOS