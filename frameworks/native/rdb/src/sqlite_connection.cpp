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

#include "logger.h"
#include "raw_data_parser.h"
#include "rdb_errno.h"
#include "rdb_security_manager.h"
#include "rdb_sql_statistic.h"
#include "rdb_store_config.h"
#include "relational_store_client.h"
#include "sqlite_errno.h"
#include "sqlite_global_config.h"
#include "sqlite_utils.h"
#include "rdb_fault_hiview_reporter.h"
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
#include "relational/relational_store_sqlite_ext.h"
#include "rdb_manager_impl.h"
#endif
#include "task_executor.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using namespace std::chrono;
using RdbKeyFile = RdbSecurityManager::KeyFileType;

constexpr const char *INTEGRITIES[] = {nullptr, "PRAGMA quick_check", "PRAGMA integrity_check"};
__attribute__((used))
const int32_t SqliteConnection::regCreator_ = Connection::RegisterCreator(DB_SQLITE, SqliteConnection::Create);
__attribute__((used))
const int32_t SqliteConnection::regRepairer_ = Connection::RegisterRepairer(DB_SQLITE, SqliteConnection::Repair);
__attribute__((used))
const int32_t SqliteConnection::regDeleter_ = Connection::RegisterDeleter(DB_SQLITE, SqliteConnection::Delete);

std::pair<int32_t, std::shared_ptr<Connection>> SqliteConnection::Create(const RdbStoreConfig &config, bool isWrite)
{
    std::pair<int32_t, std::shared_ptr<Connection>> result = { E_ERROR, nullptr };
    auto &[errCode, conn] = result;
    std::shared_ptr<SqliteConnection> connection = std::make_shared<SqliteConnection>(config, isWrite);
    if (connection == nullptr) {
        LOG_ERROR("connection is nullptr.");
        return result;
    }

    RdbStoreConfig rdbSlaveStoreConfig = connection->GetSlaveRdbStoreConfig(config);
    errCode = connection->InnerOpen(config);
    if (errCode != E_OK) {
        return result;
    }
    conn = connection;

    if (isWrite) {
        int ret = connection->CreateSlaveConnection(rdbSlaveStoreConfig, isWrite);
        if (ret != E_OK) {
            return { E_OK, conn };
        }
        auto [isExchange, isRestore] = connection->IsExchange(rdbSlaveStoreConfig);
        if (isExchange) {
            LOG_INFO("exchange isRes:%{public}d, %{public}s,", isRestore,
                SqliteUtils::Anonymous(rdbSlaveStoreConfig.GetPath()).c_str());
            if (isRestore) {
                (void)connection->Restore({}, {});
            } else {
                (void)connection->Backup({}, {}, true);
            }
        }
    }
    return result;
}

int32_t SqliteConnection::Delete(const RdbStoreConfig &config)
{
    auto path = config.GetPath();
    SqliteUtils::DeleteFile(path);
    SqliteUtils::DeleteFile(path + "-shm");
    SqliteUtils::DeleteFile(path + "-wal");
    SqliteUtils::DeleteFile(path + "-journal");
    return E_OK;
}

SqliteConnection::SqliteConnection(const RdbStoreConfig &config, bool isWriteConnection)
    : dbHandle_(nullptr), isWriter_(isWriteConnection), isReadOnly_(false), maxVariableNumber_(0), filePath(""),
      config_(config)
{
}

int SqliteConnection::CreateSlaveConnection(const RdbStoreConfig &config, bool isWrite, bool checkSlaveExist)
{
    if (config.GetHaMode() != HAMode::MAIN_REPLICA && config.GetHaMode() != HAMode::MANUAL_TRIGGER) {
        return E_OK;
    }
    bool isSlaveExist = access(config.GetPath().c_str(), F_OK) == 0;
    bool isSlaveLockExist = SqliteUtils::TryAccessSlaveLock(dbHandle_, false, false);
    if (!isSlaveExist) {
        slaveStatus_.store(SlaveStatus::DB_NOT_EXITS);
    }
    if (config.GetHaMode() == HAMode::MANUAL_TRIGGER && ((checkSlaveExist && !isSlaveExist) || isSlaveLockExist)) {
        LOG_INFO("not dual write on manual, slave:%{public}d, lock:%{public}d",
            isSlaveExist, isSlaveLockExist);
        return E_OK;
    }

    slaveConnection_ = std::make_shared<SqliteConnection>(config, isWrite);
    int errCode = slaveConnection_->InnerOpen(config);
    if (errCode != E_OK) {
        if (errCode == E_SQLITE_CORRUPT) {
            LOG_WARN("slave corrupt, rebuild:%{public}s",
                SqliteUtils::Anonymous(config.GetPath()).c_str());
            (void)Delete(config);
            errCode = slaveConnection_->InnerOpen(config);
            if (errCode != E_OK) {
                LOG_ERROR("reopen slave failed:%{public}d", errCode);
                return errCode;
            }
        } else {
            LOG_WARN("open slave failed:%{public}d, %{public}s", errCode,
                SqliteUtils::Anonymous(config.GetPath()).c_str());
        }
    }
    return errCode;
}

RdbStoreConfig SqliteConnection::GetSlaveRdbStoreConfig(const RdbStoreConfig rdbConfig)
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
    rdbStoreConfig.SetIter(rdbConfig.GetIter());
    rdbStoreConfig.SetJournalSize(rdbConfig.GetJournalSize());
    rdbStoreConfig.SetPageSize(rdbConfig.GetPageSize());
    rdbStoreConfig.SetReadConSize(rdbConfig.GetReadConSize());
    rdbStoreConfig.SetReadTime(rdbConfig.GetReadTime());
    rdbStoreConfig.SetDBType(rdbConfig.GetDBType());
    rdbStoreConfig.SetVisitorDir(rdbConfig.GetVisitorDir());
    rdbStoreConfig.SetEncryptKey(rdbConfig.GetEncryptKey());
    rdbStoreConfig.SetNewEncryptKey(rdbConfig.GetNewEncryptKey());
    rdbStoreConfig.SetScalarFunctions(rdbConfig.GetScalarFunctions());

    rdbStoreConfig.SetModuleName(rdbConfig.GetModuleName());
    rdbStoreConfig.SetArea(rdbConfig.GetArea());
    rdbStoreConfig.SetPluginLibs(rdbConfig.GetPluginLibs());
    rdbStoreConfig.SetHaMode(rdbConfig.GetHaMode());
    return rdbStoreConfig;
}

int SqliteConnection::InnerOpen(const RdbStoreConfig &config)
{
    std::string dbPath;
    auto errCode = SqliteGlobalConfig::GetDbPath(config, dbPath);
    if (errCode != E_OK) {
        return errCode;
    }

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    bool isDbFileExist = access(dbPath.c_str(), F_OK) == 0;
    if (!isDbFileExist && (!config.IsCreateNecessary())) {
        LOG_ERROR("db not exist errno is %{public}d", errno);
        return E_DB_NOT_EXIST;
    }
#endif
    isReadOnly_ = !isWriter_ || config.IsReadOnly();
    int openFileFlags = config.IsReadOnly() ? (SQLITE_OPEN_READONLY | SQLITE_OPEN_FULLMUTEX)
                                    : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
    errCode = OpenDatabase(dbPath, openFileFlags);
    if (errCode != E_OK) {
        return errCode;
    }

    maxVariableNumber_ = sqlite3_limit(dbHandle_, SQLITE_LIMIT_VARIABLE_NUMBER, -1);
    errCode = Configure(config, dbPath);
    isConfigured_ = true;
    if (errCode != E_OK) {
        return errCode;
    }

    if (isWriter_) {
        TryCheckPoint();
        ValueObject checkResult{"ok"};
        auto index = static_cast<uint32_t>(config.GetIntegrityCheck());
        if (index < static_cast<uint32_t>(sizeof(INTEGRITIES) / sizeof(INTEGRITIES[0]))) {
            auto sql = INTEGRITIES[index];
            if (sql != nullptr) {
                LOG_INFO("%{public}s : %{public}s, ", sql, config.GetName().c_str());
                std::tie(errCode, checkResult) = ExecuteForValue(sql);
            }
            if (errCode == E_OK && static_cast<std::string>(checkResult) != "ok") {
                LOG_ERROR("%{public}s integrity check result is %{public}s, sql:%{public}s", config.GetName().c_str(),
                    static_cast<std::string>(checkResult).c_str(), sql);
                ReportDbCorruptedEvent(errCode, static_cast<std::string>(checkResult));
            } else {
                LOG_INFO("%{public}s integrity check err:%{public}d, result is %{public}s, sql:%{public}s",
                    config.GetName().c_str(), errCode, static_cast<std::string>(checkResult).c_str(), sql);
            }
        }
        SqliteUtils::ControlDeleteFlag(dbPath, SqliteUtils::SET_FLAG);
    }

    filePath = dbPath;
    return E_OK;
}

void SqliteConnection::ReportDbCorruptedEvent(int errorCode, const std::string &checkResultInfo)
{
    RdbCorruptedEvent eventInfo;
    eventInfo.bundleName = config_.GetBundleName();
    eventInfo.moduleName = config_.GetModuleName();
    eventInfo.storeType = "RDB";
    eventInfo.storeName = config_.GetName();
    eventInfo.securityLevel = static_cast<uint32_t>(config_.GetSecurityLevel());
    eventInfo.pathArea = static_cast<uint32_t>(config_.GetArea());
    eventInfo.encryptStatus = static_cast<uint32_t>(config_.IsEncrypt());
    eventInfo.integrityCheck = static_cast<uint32_t>(config_.GetIntegrityCheck());
    eventInfo.errorCode = errorCode;
    eventInfo.systemErrorNo = errno;
    eventInfo.appendix = checkResultInfo;
    eventInfo.errorOccurTime = time(nullptr);
    std::string dbPath;
    if (SqliteGlobalConfig::GetDbPath(config_, dbPath) == E_OK && access(dbPath.c_str(), F_OK) == 0) {
        eventInfo.dbFileStatRet = stat(dbPath.c_str(), &eventInfo.dbFileStat);
        std::string walPath = dbPath + "-wal";
        eventInfo.walFileStatRet = stat(walPath.c_str(), &eventInfo.walFileStat);
    } else {
        eventInfo.dbFileStatRet = -1;
        eventInfo.walFileStatRet = -1;
    }
    RdbFaultHiViewReporter::ReportRdbCorruptedFault(eventInfo);
}

int32_t SqliteConnection::OpenDatabase(const std::string &dbPath, int openFileFlags)
{
    int errCode = sqlite3_open_v2(dbPath.c_str(), &dbHandle_, openFileFlags, nullptr);
    if (errCode != SQLITE_OK) {
        LOG_ERROR("fail to open database errCode=%{public}d, dbPath=%{public}s, flags=%{public}d, errno=%{public}d",
            errCode, dbPath.c_str(), openFileFlags, errno);
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
    if (config.GetStorageMode() == StorageMode::MODE_MEMORY) {
        return E_OK;
    }

    if (config.GetRoleType() == VISITOR) {
        return E_OK;
    }

    auto errCode = RegDefaultFunctions(dbHandle_);
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

    errCode = SetEncrypt(config);
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
    return LoadExtension(config, dbHandle_);
}

SqliteConnection::~SqliteConnection()
{
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
        statement->slave_ = std::make_shared<SqliteStatement>();
        statement->slave_->config_ = &slaveConnection_->config_;
        errCode = statement->slave_->Prepare(slaveConnection_->dbHandle_, sql);
        if (errCode != E_OK) {
            LOG_WARN("prepare slave stmt failed:%{public}d", errCode);
            return { E_OK, statement };
        }
        statement->slave_->conn_ = slaveConnection_;
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

int SqliteConnection::SetEncryptAgo(int32_t iter)
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
    return E_OK;
}

int SqliteConnection::ReSetKey(const RdbStoreConfig &config)
{
    if (!IsWriter()) {
        return E_OK;
    }
    LOG_INFO("name = %{public}s, iter = %{public}d", config.GetName().c_str(), config.GetIter());
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

std::string SqliteConnection::GetSecManagerName(const RdbStoreConfig &config)
{
    auto name = config.GetBundleName();
    if (name.empty()) {
        LOG_WARN("Bundle name is empty, using path instead.");
        return std::string(config.GetPath()).substr(0, config.GetPath().rfind("/") + 1);
    }
    return name;
}

int SqliteConnection::SetEncrypt(const RdbStoreConfig &config)
{
    if (!config.IsEncrypt()) {
        return E_OK;
    }

    std::vector<uint8_t> key = config.GetEncryptKey();
    std::vector<uint8_t> newKey = config.GetNewEncryptKey();
    auto errCode = SetEncryptKey(key, config.GetIter());
    key.assign(key.size(), 0);
    if (errCode != E_OK) {
        if (!newKey.empty()) {
            LOG_INFO("use new key, iter=%{public}d err=%{public}d errno=%{public}d name=%{public}s",
                config.GetIter(), errCode, errno, config.GetName().c_str());
            errCode = SetEncryptKey(newKey, config.GetIter());
        }
        newKey.assign(newKey.size(), 0);
        if (errCode != E_OK) {
            errCode = SetServiceKey(config, errCode);
            LOG_ERROR("fail, iter=%{public}d err=%{public}d errno=%{public}d name=%{public}s", config.GetIter(),
                errCode, errno, config.GetName().c_str());
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

int SqliteConnection::SetEncryptKey(const std::vector<uint8_t> &key, int32_t iter)
{
    if (key.empty()) {
        return E_INVALID_ARGS;
    }

    auto errCode = sqlite3_key(dbHandle_, static_cast<const void *>(key.data()), static_cast<int>(key.size()));
    if (errCode != SQLITE_OK) {
        return SQLiteError::ErrNo(errCode);
    }

    errCode = SetEncryptAgo(iter);
    if (errCode != E_OK) {
        return errCode;
    }

    if (IsWriter()) {
        ValueObject version;
        std::tie(errCode, version) = ExecuteForValue(GlobalExpr::PRAGMA_VERSION);
        if (errCode != E_OK || version.GetType() == ValueObject::TYPE_NULL) {
            return errCode;
        }
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
    // The number of parameters is 2
    int errCode = sqlite3_create_function_v2(dbHandle, MERGE_ASSETS_FUNC, 2, SQLITE_UTF8 | SQLITE_DETERMINISTIC,
        nullptr, &MergeAssets, nullptr, nullptr, nullptr);
    if (errCode != SQLITE_OK) {
        LOG_ERROR("register function mergeAssets failed, errCode=%{public}d, errno=%{public}d", errCode, errno);
        return errCode;
    }
    // The number of parameters is 2
    errCode = sqlite3_create_function_v2(dbHandle, MERGE_ASSET_FUNC, 2, SQLITE_UTF8 | SQLITE_DETERMINISTIC, nullptr,
        &MergeAsset, nullptr, nullptr, nullptr);
    if (errCode != SQLITE_OK) {
        LOG_ERROR("register function mergeAsset failed, errCode=%{public}d, errno=%{public}d", errCode, errno);
        return errCode;
    }
    return SQLITE_OK;
}

int SqliteConnection::SetJournalMode(const RdbStoreConfig &config)
{
    if (isReadOnly_) {
        return E_OK;
    }

    auto [errCode, object] = ExecuteForValue("PRAGMA journal_mode");
    if (errCode != E_OK) {
        LOG_ERROR("SqliteConnection SetJournalMode fail to get journal mode : %{public}d", errCode);
        return errCode;
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
    if (isReadOnly_ || config.IsAutoCheck() == GlobalExpr::DB_AUTO_CHECK) {
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

std::pair<int32_t, ValueObject> SqliteConnection::ExecuteForValue(const std::string &sql,
    const std::vector<ValueObject> &bindArgs)
{
    auto [errCode, statement] = CreateStatement(sql, nullptr);
    if (statement == nullptr || errCode != E_OK) {
        return { static_cast<int32_t>(errCode), ValueObject() };
    }

    ValueObject object;
    std::tie(errCode, object) = statement->ExecuteForValue(bindArgs);
    if (errCode != E_OK) {
        LOG_ERROR("execute sql failed, errCode:%{public}d, sql:%{public}s, args size:%{public}zu",
            SQLiteError::ErrNo(errCode), sql.c_str(), bindArgs.size());
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

    int err = sqlite3_create_collation_v2(dbHandle_, "LOCALES", SQLITE_UTF8, collator, Collate8Compare,
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
    auto status = DropLogicDeletedData(dbHandle_, table, tmpCursor);
    return status == DistributedDB::DBStatus::OK ? E_OK : E_ERROR;
}

int SqliteConnection::TryCheckPoint()
{
    if (!isWriter_) {
        return E_NOT_SUPPORT;
    }

    std::string walName = sqlite3_filename_wal(sqlite3_db_filename(dbHandle_, "main"));
    int fileSize = SqliteUtils::GetFileSize(walName);
    if (fileSize <= GlobalExpr::DB_WAL_SIZE_LIMIT_MIN) {
        return E_OK;
    }
    int errCode = sqlite3_wal_checkpoint_v2(dbHandle_, nullptr, SQLITE_CHECKPOINT_TRUNCATE, nullptr, nullptr);
    if (errCode != SQLITE_OK) {
        LOG_WARN("sqlite3_wal_checkpoint_v2 failed err %{public}d.", errCode);
        return E_ERROR;
    }

    if (slaveConnection_) {
        int errCode = slaveConnection_->TryCheckPoint();
        if (errCode != E_OK) {
            LOG_ERROR("slaveConnection tryCheckPoint failed:%{public}d", errCode);
        }
    }
    return E_OK;
}

int SqliteConnection::LimitWalSize()
{
    if (!isConfigured_ || !isWriter_) {
        return E_OK;
    }

    std::string walName = sqlite3_filename_wal(sqlite3_db_filename(dbHandle_, "main"));
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

void SqliteConnection::MergeAsset(sqlite3_context *ctx, int argc, sqlite3_value **argv)
{
    // 2 is the number of parameters
    if (ctx == nullptr || argc != 2 || argv == nullptr) {
        LOG_ERROR("Parameter does not meet restrictions.");
        return;
    }
    ValueObject::Asset asset;
    size_t size = 0;
    auto data = static_cast<const uint8_t *>(sqlite3_value_blob(argv[0]));
    if (data != nullptr) {
        int len = sqlite3_value_bytes(argv[0]);
        size = RawDataParser::ParserRawData(data, len, asset);
    }
    ValueObject::Asset newAsset;
    data = static_cast<const uint8_t *>(sqlite3_value_blob(argv[1]));
    if (data != nullptr) {
        int len = sqlite3_value_bytes(argv[1]);
        RawDataParser::ParserRawData(data, len, newAsset);
    }
    if ((size != 0) && (asset.name != newAsset.name)) {
        LOG_ERROR("name change! old:%{public}s, new:%{public}s", SqliteUtils::Anonymous(asset.name).c_str(),
            SqliteUtils::Anonymous(newAsset.name).c_str());
        return;
    }
    MergeAsset(asset, newAsset);
    auto blob = RawDataParser::PackageRawData(asset);
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

int32_t SqliteConnection::UnsubscribeLocalDetail(const std::string &event,
    const std::shared_ptr<RdbStoreObserver> &observer)
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
    bool isAsync)
{
    LOG_INFO("begin backup to slave:%{public}s, isAsync:%{public}d", SqliteUtils::Anonymous(databasePath).c_str(),
        isAsync);
    if (!isAsync) {
        if (config_.GetHaMode() == HAMode::MANUAL_TRIGGER && slaveConnection_ == nullptr) {
            RdbStoreConfig rdbSlaveStoreConfig = GetSlaveRdbStoreConfig(config_);
            int errCode = CreateSlaveConnection(rdbSlaveStoreConfig, true, false);
            if (errCode != E_OK) {
                LOG_ERROR("manual slave conn failed:%{public}d", errCode);
                return errCode;
            }
        }
        return MasterSlaveExchange();
    }
    auto pool = TaskExecutor::GetInstance().GetExecutor();
    if (pool == nullptr) {
        LOG_WARN("task pool err when restore");
        return E_OK;
    }
    pool->Schedule(std::chrono::seconds(0), [this]() {
        int ret = MasterSlaveExchange();
        if (ret != E_OK) {
            LOG_WARN("master backup to slave failed:%{public}d", ret);
        }
    });
    return E_OK;
}

int32_t SqliteConnection::Restore(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey)
{
    LOG_INFO("begin to restore from slave:%{public}s", SqliteUtils::Anonymous(databasePath).c_str());
    return MasterSlaveExchange(true);
};

int SqliteConnection::LoadExtension(const RdbStoreConfig &config, sqlite3 *dbHandle)
{
    if (config.GetPluginLibs().empty() || dbHandle == nullptr) {
        return E_OK;
    }
    if (config.GetPluginLibs().size() > SqliteUtils::MAX_LOAD_EXTENSION_COUNT) {
        LOG_ERROR("failed, size %{public}zu is too large", config.GetPluginLibs().size());
        return E_INVALID_ARGS;
    }
    int err = sqlite3_db_config(dbHandle, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, SqliteUtils::ENABLE_LOAD_EXTENSION,
        nullptr);
    if (err != SQLITE_OK) {
        LOG_ERROR("enable failed, err=%{public}d, errno=%{public}d", err, errno);
        return SQLiteError::ErrNo(err);
    }
    for (auto &path : config.GetPluginLibs()) {
        if (path.empty()) {
            continue;
        }
        if (access(path.c_str(), F_OK) != 0) {
            LOG_ERROR("no file, errno:%{public}d %{public}s", errno, path.c_str());
            return E_INVALID_FILE_PATH;
        }
        err = sqlite3_load_extension(dbHandle, path.c_str(), nullptr, nullptr);
        if (err != SQLITE_OK) {
            LOG_ERROR("load error. err=%{public}d, errno=%{public}d, errmsg:%{public}s, lib=%{public}s",
                err, errno, sqlite3_errmsg(dbHandle), path.c_str());
            break;
        }
    }
    int ret = sqlite3_db_config(dbHandle, SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, SqliteUtils::DISABLE_LOAD_EXTENSION,
        nullptr);
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
    param.password_ = {};
    std::vector<uint8_t> key;
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    auto [svcErr, service] = DistributedRdb::RdbManagerImpl::GetInstance().GetRdbService(param);
    if (svcErr != E_OK) {
        return errCode;
    }
    svcErr = service->GetPassword(param, key);
    if (svcErr != RDB_OK) {
        return errCode;
    }
#endif

    errCode = SetEncryptKey(key, config.GetIter());
    if (errCode == E_OK) {
        config.RestoreEncryptKey(key);
    }
    key.assign(key.size(), 0);
    return errCode;
}

int SqliteConnection::MasterSlaveExchange(bool isRestore)
{
    auto [isReturn, err] = ExchangeVerify(isRestore);
    if (isReturn) {
        return err;
    }

    sqlite3 *dbFrom = isRestore ? dbHandle_ : slaveConnection_->dbHandle_;
    sqlite3 *dbTo = isRestore ? slaveConnection_->dbHandle_ : dbHandle_;
    sqlite3_backup *pBackup = sqlite3_backup_init(dbFrom, "main", dbTo, "main");
    if (pBackup == nullptr) {
        LOG_WARN("slave backup init failed");
        slaveStatus_.store(SlaveStatus::UNDEFINED);
        return E_OK;
    }
    int rc = SQLITE_OK;
    do {
        if (!isRestore && slaveStatus_.load() == SlaveStatus::BACKUP_INTERRUPT) {
            LOG_INFO("backup slave was interrupt!");
            (void)sqlite3_backup_finish(pBackup);
            (void)SqliteConnection::Delete(slaveConnection_->config_);
            return E_OK;
        }
        rc = sqlite3_backup_step(pBackup, BACKUP_PAGES_PRE_STEP);
        LOG_INFO("backup slave process cur/total:%{public}d/%{public}d, isRestore:%{public}d",
            sqlite3_backup_pagecount(pBackup) - sqlite3_backup_remaining(pBackup), sqlite3_backup_pagecount(pBackup),
            isRestore);
    } while (rc == SQLITE_OK || rc == SQLITE_BUSY || rc == SQLITE_LOCKED);
    (void)sqlite3_backup_finish(pBackup);
    if (rc != SQLITE_DONE) {
        slaveStatus_.store(SlaveStatus::BACKUP_INTERRUPT);
        LOG_WARN("backup slave err:%{public}d, isRestore:%{public}d", rc, isRestore);
        return SQLiteError::ErrNo(rc);
    } else {
        slaveStatus_.store(SlaveStatus::BACKUP_FINISHED);
        if (!SqliteUtils::TryAccessSlaveLock(dbHandle_, true, false)) {
            LOG_WARN("try remove slave lock failed! isRestore:%{public}d", isRestore);
        }
        LOG_INFO("backup slave success, isRestore:%{public}d", isRestore);
    }
    return E_OK;
}

std::pair<bool, bool> SqliteConnection::IsExchange(const RdbStoreConfig &config)
{
    std::pair<bool, bool> res = { false, false };
    auto &[isExchanged, isRestore] = res;
    if (dbHandle_ == nullptr || slaveConnection_ == nullptr || slaveConnection_->dbHandle_ == nullptr) {
        return res;
    }
    if (config.GetHaMode() != HAMode::MAIN_REPLICA) {
        return res;
    }
    SlaveStatus curSlaveStatus = slaveStatus_.load();
    if (curSlaveStatus == SlaveStatus::BACKING_UP) {
        return res;
    }
    if (curSlaveStatus == SlaveStatus::DB_NOT_EXITS || curSlaveStatus == SlaveStatus::BACKUP_INTERRUPT) {
        isExchanged = true;
        return res;
    }
    static const std::string querySql = "SELECT COUNT(*) FROM sqlite_master WHERE type='table';";
    auto [mRet, mObj] = ExecuteForValue(querySql);
    if (mRet != E_OK) {
        return res;
    }
    auto [sRet, sObj] = slaveConnection_->ExecuteForValue(querySql);
    if (sRet != E_OK) {
        LOG_WARN("slave db abnormal, need backup, err:%{public}d", sRet);
        isExchanged = true;
        return res;
    }
    int64_t mCount = static_cast<int64_t>(mObj);
    int64_t sCount = static_cast<int64_t>(sObj);
    if (mCount != sCount) {
        isExchanged = true;
        if (mCount == 0) {
            isRestore = true;
            LOG_INFO("main empty, main:%{public}" PRId64 ",slave:%{public}" PRId64, mCount, sCount);
        } else {
            LOG_INFO("not equal, main:%{public}" PRId64 ",slave:%{public}" PRId64, mCount, sCount);
        }
    }
    return res;
}

int32_t SqliteConnection::InterruptBackup()
{
    if (slaveStatus_.load() == SlaveStatus::BACKING_UP) {
        slaveStatus_.store(SlaveStatus::BACKUP_INTERRUPT);
        return E_OK;
    }
    return E_NOT_SUPPORT;
}

int32_t SqliteConnection::GetBackupStatus() const
{
    return slaveStatus_.load();
}

int32_t SqliteConnection::Repair(const RdbStoreConfig &config)
{
    if (config.GetHaMode() != MAIN_REPLICA) {
        return E_NOT_SUPPORT;
    }
    std::shared_ptr<SqliteConnection> connection = std::make_shared<SqliteConnection>(config, true);
    if (connection == nullptr) {
        return E_NOT_SUPPORT;
    }
    RdbStoreConfig rdbSlaveStoreConfig = connection->GetSlaveRdbStoreConfig(config);
    int ret = connection->CreateSlaveConnection(rdbSlaveStoreConfig, true);
    if (ret != E_OK) {
        return ret;
    }
    if (!connection->IsRepairable()) {
        return E_NOT_SUPPORT;
    }
    LOG_WARN("begin repair main:%{public}s", SqliteUtils::Anonymous(config.GetPath()).c_str());
    (void)SqliteConnection::Delete(config);
    ret = connection->InnerOpen(config);
    if (ret != E_OK) {
        LOG_ERROR("reopen db failed, err:%{public}d", ret);
        return ret;
    }
    ret = connection->MasterSlaveExchange(true);
    if (ret != E_OK) {
        LOG_ERROR("repair failed, [%{public}s]->[%{public}s], err:%{public}d", rdbSlaveStoreConfig.GetName().c_str(),
            config.GetName().c_str(), ret);
        return ret;
    }
    LOG_INFO("repair main success:%{public}s", SqliteUtils::Anonymous(config.GetPath()).c_str());
    connection->slaveConnection_ = nullptr;
    connection = nullptr;
    return E_OK;
}

bool SqliteConnection::IsRepairable()
{
    if (slaveConnection_ == nullptr || slaveConnection_->dbHandle_ == nullptr) {
        return false;
    }
    static const std::string querySql = "SELECT COUNT(*) FROM sqlite_master WHERE type='table';";
    auto [qRet, qObj] = slaveConnection_->ExecuteForValue(querySql);
    if (qRet != E_OK || (static_cast<int64_t>(qObj) == 0L)) {
        LOG_INFO("cancel repair, ret:%{public}d", qRet);
        return false;
    }
    auto [cRet, cObj] = slaveConnection_->ExecuteForValue(INTEGRITIES[1]); // 1 is quick check
    if (cRet != E_OK || (static_cast<std::string>(cObj) != "ok")) {
        LOG_ERROR("cancel repair, ret:%{public}s, cRet:%{public}d", static_cast<std::string>(cObj).c_str(), cRet);
        return false;
    }
    return true;
}

std::pair<bool, int> SqliteConnection::ExchangeVerify(bool isRestore)
{
    if (dbHandle_ == nullptr || slaveConnection_ == nullptr || slaveConnection_->dbHandle_ == nullptr) {
        LOG_WARN("slave conn invalid");
        return { true, E_OK };
    }
    if (!SqliteUtils::TryAccessSlaveLock(dbHandle_, false, true)) {
        LOG_WARN("try create slave lock failed! isRestore:%{public}d", isRestore);
    }
    slaveStatus_.store(SlaveStatus::BACKING_UP);
    if (isRestore) {
        auto [cRet, cObj] = slaveConnection_->ExecuteForValue(INTEGRITIES[2]); // 2 is integrity_check
        if (cRet != E_OK || (static_cast<std::string>(cObj) != "ok")) {
            LOG_ERROR("slave may corrupt, cancel backup, ret:%{public}s, cRet:%{public}d",
                static_cast<std::string>(cObj).c_str(), cRet);
            slaveStatus_.store(SlaveStatus::DB_NOT_EXITS);
            return { true, E_SQLITE_CORRUPT };
        }
    }
    return { false, E_OK };
}
} // namespace NativeRdb
} // namespace OHOS
