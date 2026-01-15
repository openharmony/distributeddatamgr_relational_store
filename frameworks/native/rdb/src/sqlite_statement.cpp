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
#define LOG_TAG "SqliteStatement"
#include "sqlite_statement.h"

#include <cstdint>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>

#include "cache_block.h"
#include "connection_pool.h"
#include "corrupted_handle_manager.h"
#include "logger.h"
#include "raw_data_parser.h"
#include "rdb_errno.h"
#include "rdb_fault_hiview_reporter.h"
#include "rdb_perfStat.h"
#include "rdb_sql_log.h"
#include "rdb_sql_statistic.h"
#include "rdb_types.h"
#include "relational_store_client.h"
#include "remote_result_set.h"
#include "share_block.h"
#include "shared_block_serializer_info.h"
#include "sqlite3.h"
#include "sqlite3ext.h"
#include "sqlite_connection.h"
#include "sqlite_errno.h"
#include "sqlite_global_config.h"
#include "sqlite_utils.h"
#include "string_utils.h"
namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using namespace std::chrono;
using SqlStatistic = DistributedRdb::SqlStatistic;
using PerfStat = DistributedRdb::PerfStat;
using Reportor = RdbFaultHiViewReporter;
// Setting Data Precision
constexpr SqliteStatement::Action SqliteStatement::ACTIONS[ValueObject::TYPE_MAX];
static constexpr int ERR_MSG_SIZE = 2;
static constexpr const char *ERR_MSG[] = {
    "no such table:",
    "no such column:",
    "has no column named"
};

SqliteStatement::SqliteStatement(const RdbStoreConfig *config)
    : readOnly_(false), columnCount_(0), numParameters_(0), stmt_(nullptr), sql_(""), config_(config)
{
    seqId_ = PerfStat::GenerateId();
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_TOTAL_REF, seqId_);
    PerfStat perfStat((config_ != nullptr) ? config_->GetPath() : "", "", SqlStatistic::Step::STEP_TOTAL_REF, seqId_);
}

SqliteStatement::~SqliteStatement()
{
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_TOTAL_RES, seqId_);
    PerfStat perfStat((config_ != nullptr) ? config_->GetPath() : "", "", PerfStat::Step::STEP_TOTAL_RES, seqId_);
    Finalize();
    slave_ = nullptr;
    conn_ = nullptr;
    config_ = nullptr;
}

void SqliteStatement::TableReport(const std::string &errMsg, const std::string &bundleName, ErrMsgState state)
{
    std::string custLog;
    if (!state.isCreated) {
        custLog = "table is not created " + errMsg;
        Reportor::ReportFault(RdbFaultEvent(RdbFaultType::FT_CURD, E_DFX_IS_NOT_CREATE, bundleName, custLog));
    } else if (state.isDeleted) {
        custLog = "table is deleted " + errMsg;
        Reportor::ReportFault(RdbFaultEvent(RdbFaultType::FT_CURD, E_DFX_IS_DELETE, bundleName, custLog));
    } else if (state.isRenamed) {
        custLog = "table is renamed " + errMsg;
        Reportor::ReportFault(RdbFaultEvent(RdbFaultType::FT_CURD, E_DFX_IS_RENAME, bundleName, custLog));
    } else {
        custLog = errMsg;
        Reportor::ReportFault(RdbFaultEvent(RdbFaultType::FT_CURD, E_DFX_IS_NOT_EXIST, bundleName, custLog));
    }
}

void SqliteStatement::ColumnReport(const std::string &errMsg, const std::string &bundleName, ErrMsgState state)
{
    std::string custLog;
    if (!state.isCreated) {
        custLog = "column is not created " + errMsg;
        Reportor::ReportFault(RdbFaultEvent(RdbFaultType::FT_CURD, E_DFX_IS_NOT_CREATE, bundleName, custLog));
    } else if (state.isDeleted) {
        custLog = "column is deleted " + errMsg;
        Reportor::ReportFault(RdbFaultEvent(RdbFaultType::FT_CURD, E_DFX_IS_DELETE, bundleName, custLog));
    } else if (state.isRenamed) {
        custLog = "column is renamed " + errMsg;
        Reportor::ReportFault(RdbFaultEvent(RdbFaultType::FT_CURD, E_DFX_IS_RENAME, bundleName, custLog));
    } else {
        custLog = errMsg;
        Reportor::ReportFault(RdbFaultEvent(RdbFaultType::FT_CURD, E_DFX_IS_NOT_EXIST, bundleName, custLog));
    }
}

void SqliteStatement::HandleErrMsg(const std::string &errMsg, const std::string &dbPath, const std::string &bundleName)
{
    for (auto err: ERR_MSG) {
        if (errMsg.find(err) == std::string::npos) {
            continue;
        }
        if (err == ERR_MSG[0]) {
            std::string tableName = SqliteUtils::GetErrInfoFromMsg(errMsg, err);
            ErrMsgState state = SqliteUtils::CompareTableFileContent(dbPath, bundleName, tableName);
            TableReport(errMsg, bundleName, state);
        }
        if (err == ERR_MSG[1] || err == ERR_MSG[ERR_MSG_SIZE]) {
            std::string columnName = SqliteUtils::GetErrInfoFromMsg(errMsg, err);
            ErrMsgState state = SqliteUtils::CompareColumnFileContent(dbPath, bundleName, columnName);
            ColumnReport(errMsg, bundleName, state);
        }
    }
}

void SqliteStatement::TryNotifyErrorLog(const int &errCode, sqlite3 *dbHandle, const std::string &sql)
{
    if (errCode == SQLITE_ROW || errCode == SQLITE_DONE || errCode == SQLITE_OK) {
        return ;
    }
    std::string errMsg(sqlite3_errmsg(dbHandle));
    DistributedRdb::SqlErrorObserver::ExceptionMessage exceMessage;
    exceMessage.code = errCode;
    exceMessage.message = std::move(errMsg);
    exceMessage.sql = sql;
    NativeRdb::SqlLog::Notify(config_->GetPath(), exceMessage);
}

int SqliteStatement::Prepare(sqlite3 *dbHandle, const std::string &newSql)
{
    if (sql_.compare(newSql) == 0) {
        return E_OK;
    }
    // prepare the new sqlite3_stmt
    sqlite3_stmt *stmt = nullptr;
    SqlStatistic sqlStatistic(newSql, SqlStatistic::Step::STEP_PREPARE, seqId_);
    PerfStat perfStat((config_ != nullptr) ? config_->GetPath() : "", newSql, PerfStat::Step::STEP_PREPARE, seqId_);
    int errCode = sqlite3_prepare_v2(dbHandle, newSql.c_str(), newSql.length(), &stmt, nullptr);
    if (errCode != SQLITE_OK) {
        std::string errMsg(sqlite3_errmsg(dbHandle));
        TryNotifyErrorLog(errCode, dbHandle, newSql);
        if (errMsg.size() != 0) {
            HandleErrMsg(errMsg, config_->GetPath(), config_->GetBundleName());
        }
        if (stmt != nullptr) {
            sqlite3_finalize(stmt);
        }
        if (errCode == SQLITE_NOTADB) {
            ReadFile2Buffer();
        }
        int ret = SQLiteError::ErrNo(errCode);
        if (config_ != nullptr &&
            (errCode == SQLITE_CORRUPT || (errCode == SQLITE_NOTADB && config_->GetIter() != 0))) {
            Reportor::ReportCorruptedOnce(Reportor::Create(*config_, ret,
                (errCode == SQLITE_CORRUPT ? SqliteGlobalConfig::GetLastCorruptionMsg() : "SqliteStatement::Prepare")));
            CorruptedHandleManager::GetInstance().HandleCorrupt(*config_);
        }
        if (config_ != nullptr) {
            Reportor::ReportFault(RdbFaultDbFileEvent(RdbFaultType::FT_CURD,
                (errCode == SQLITE_NOTADB ? E_SQLITE_NOT_DB : ret), *config_, "sqlite3_prepare_v2", true));
        }
        PrintInfoForDbError(ret, newSql);
        return ret;
    }
    InnerFinalize(); // finalize the old
    sql_ = newSql;
    stmt_ = stmt;
    readOnly_ = (sqlite3_stmt_readonly(stmt_) != 0);
    columnCount_ = sqlite3_column_count(stmt_);
    types_ = std::vector<int32_t>(columnCount_, COLUMN_TYPE_INVALID);
    numParameters_ = sqlite3_bind_parameter_count(stmt_);
    return E_OK;
}

void SqliteStatement::PrintInfoForDbError(int errCode, const std::string &sql)
{
    if (config_ == nullptr) {
        return;
    }

    if (errCode == E_SQLITE_ERROR && sql == std::string(GlobalExpr::PRAGMA_VERSION) + "=?") {
        return;
    }

    if (errCode == E_SQLITE_ERROR || errCode == E_SQLITE_BUSY || errCode == E_SQLITE_LOCKED ||
        errCode == E_SQLITE_IOERR || errCode == E_SQLITE_CANTOPEN) {
        LOG_ERROR("DbError errCode:%{public}d errno:%{public}d DbName: %{public}s ", errCode, errno,
            SqliteUtils::Anonymous(config_->GetName()).c_str());
    }
}

void SqliteStatement::ReadFile2Buffer()
{
    if (config_ == nullptr) {
        return;
    }
    std::string fileName;
    if (SqliteGlobalConfig::GetDbPath(*config_, fileName) != E_OK || access(fileName.c_str(), F_OK) != 0) {
        return;
    }
    uint64_t buffer[BUFFER_LEN] = { 0x0 };
    FILE *file = fopen(fileName.c_str(), "r");
    if (file == nullptr) {
        LOG_ERROR(
            "Open db file failed: %{public}s, errno is %{public}d", SqliteUtils::Anonymous(fileName).c_str(), errno);
        return;
    }
    size_t readSize = fread(buffer, sizeof(uint64_t), BUFFER_LEN, file);
    if (readSize != BUFFER_LEN) {
        LOG_ERROR("read db file size: %{public}zu, errno is %{public}d", readSize, errno);
        (void)fclose(file);
        return;
    }
    constexpr int bufferSize = 4;
    for (uint32_t i = 0; i < BUFFER_LEN; i += bufferSize) {
        LOG_WARN("line%{public}d: %{public}016" PRIx64 "%{public}016" PRIx64 "%{public}016" PRIx64
                 "%{public}016" PRIx64, i >> 2, buffer[i], buffer[i + 1], buffer[i + 2], buffer[i + 3]);
    }
    (void)fclose(file);
}

int SqliteStatement::BindArgs(const std::vector<ValueObject> &bindArgs)
{
    std::vector<std::reference_wrapper<ValueObject>> refBindArgs;
    for (auto &object : bindArgs) {
        refBindArgs.emplace_back(std::ref(const_cast<ValueObject &>(object)));
    }
    return BindArgs(refBindArgs);
}

int SqliteStatement::BindArgs(const std::vector<std::reference_wrapper<ValueObject>> &bindArgs)
{
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_PREPARE, seqId_);
    PerfStat perfStat((config_ != nullptr) ? config_->GetPath() : "", "", PerfStat::Step::STEP_PREPARE, seqId_);
    if (bound_) {
        sqlite3_reset(stmt_);
        sqlite3_clear_bindings(stmt_);
    }
    bound_ = true;
    int index = 1;
    for (auto &arg : bindArgs) {
        auto action = ACTIONS[arg.get().value.index()];
        if (action == nullptr) {
            LOG_ERROR("not support the type %{public}zu", arg.get().value.index());
            return E_INVALID_ARGS;
        }
        auto errCode = action(stmt_, index, arg.get().value);
        if (errCode != SQLITE_OK) {
            LOG_ERROR("Bind has error: %{public}d, sql: %{public}s, errno %{public}d",
                errCode, SqliteUtils::SqlAnonymous(sql_).c_str(), errno);
            return SQLiteError::ErrNo(errCode);
        }
        index++;
    }

    return E_OK;
}

int SqliteStatement::IsValid(int index) const
{
    if (stmt_ == nullptr) {
        LOG_ERROR("statement already close.");
        return E_ALREADY_CLOSED;
    }

    if (index >= columnCount_ || index < 0) {
        LOG_ERROR("index (%{public}d) is out of range [0, %{public}d]", index, columnCount_ - 1);
        return E_COLUMN_OUT_RANGE;
    }
    return E_OK;
}

int SqliteStatement::Prepare(const std::string &sql)
{
    if (stmt_ == nullptr) {
        return E_ERROR;
    }
    auto db = sqlite3_db_handle(stmt_);
    int errCode = Prepare(db, sql);
    if (errCode != E_OK) {
        return errCode;
    }

    if (slave_) {
        int errCode = slave_->Prepare(sql);
        if (errCode != E_OK) {
            LOG_WARN("slave prepare Error:%{public}d", errCode);
            SqliteUtils::SetSlaveInvalid(config_->GetPath());
        }
    }
    return E_OK;
}

int SqliteStatement::Bind(const std::vector<ValueObject> &args)
{
    int count = static_cast<int>(args.size());
    std::vector<ValueObject> abindArgs;

    if (count == 0) {
        return E_OK;
    }
    // Obtains the bound parameter set.
    if ((numParameters_ != 0) && (count <= numParameters_)) {
        for (const auto &i : args) {
            abindArgs.push_back(i);
        }

        for (int i = count; i < numParameters_; i++) { // TD: when count <> numParameters
            ValueObject val;
            abindArgs.push_back(val);
        }
    }

    if (count > numParameters_) {
        LOG_ERROR("bind args count(%{public}d) > numParameters(%{public}d), sql: %{public}s", count, numParameters_,
            SqliteUtils::SqlAnonymous(sql_).c_str());
        return E_INVALID_BIND_ARGS_COUNT;
    }

    int errCode = BindArgs(abindArgs);
    if (errCode != E_OK) {
        return errCode;
    }

    if (slave_) {
        int errCode = slave_->Bind(args);
        if (errCode != E_OK) {
            LOG_ERROR("slave bind error:%{public}d", errCode);
            SqliteUtils::SetSlaveInvalid(config_->GetPath());
        }
    }
    return E_OK;
}

std::pair<int32_t, int32_t> SqliteStatement::Count()
{
    SharedBlockInfo info(nullptr);
    info.isCountAllRows = true;
    info.isFull = true;
    info.totalRows = -1;
    auto errCode = FillBlockInfo(&info);
    if (errCode != E_OK) {
        return { errCode, INVALID_COUNT };
    }
    return { errCode, info.totalRows };
}

int SqliteStatement::Step()
{
    int ret = InnerStep();
    if (ret != E_OK) {
        return ret;
    }
    if (slave_) {
        ret = slave_->Step();
        if (ret != E_OK) {
            LOG_WARN("slave step error:%{public}d", ret);
        }
    }
    return E_OK;
}

int SqliteStatement::InnerStep()
{
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_EXECUTE, seqId_);
    PerfStat perfStat((config_ != nullptr) ? config_->GetPath() : "", "", PerfStat::Step::STEP_EXECUTE, seqId_);
    auto errCode = sqlite3_step(stmt_);
    auto db = sqlite3_db_handle(stmt_);
    TryNotifyErrorLog(errCode, db, sql_);
    int ret = SQLiteError::ErrNo(errCode);
    if (config_ != nullptr && (errCode == SQLITE_CORRUPT || (errCode == SQLITE_NOTADB && config_->GetIter() != 0))) {
        Reportor::ReportCorruptedOnce(Reportor::Create(*config_, ret,
            (errCode == SQLITE_CORRUPT ? SqliteGlobalConfig::GetLastCorruptionMsg() : "SqliteStatement::InnerStep")));
        CorruptedHandleManager::GetInstance().HandleCorrupt(*config_);
    }
    if (config_ != nullptr && ret != E_OK && !config_->GetBundleName().empty()) {
        Reportor::ReportFault(RdbFaultDbFileEvent(RdbFaultType::FT_CURD, ret, *config_, "sqlite3_step", true));
    }
    PrintInfoForDbError(ret, sql_);
    return ret;
}

int SqliteStatement::Reset()
{
    if (stmt_ == nullptr) {
        return E_OK;
    }

    int errCode = sqlite3_reset(stmt_);
    if (errCode != SQLITE_OK) {
        LOG_ERROR("reset ret is %{public}d, errno is %{public}d", errCode, errno);
        return SQLiteError::ErrNo(errCode);
    }
    if (slave_) {
        errCode = slave_->Reset();
        if (errCode != E_OK) {
            LOG_WARN("slave reset error:%{public}d", errCode);
        }
    }
    return E_OK;
}

int SqliteStatement::Finalize()
{
    int errCode = InnerFinalize();
    if (errCode != E_OK) {
        return errCode;
    }

    if (slave_) {
        errCode = slave_->Finalize();
        if (errCode != E_OK) {
            LOG_WARN("slave finalize error:%{public}d", errCode);
        }
    }
    return E_OK;
}

int SqliteStatement::Execute(const std::vector<ValueObject> &args)
{
    std::vector<std::reference_wrapper<ValueObject>> refArgs;
    for (auto &object : args) {
        refArgs.emplace_back(std::ref(const_cast<ValueObject &>(object)));
    }
    return Execute(refArgs);
}

int32_t SqliteStatement::Execute(const std::vector<std::reference_wrapper<ValueObject>> &args)
{
    auto errCode = CheckEnvironment(static_cast<int>(args.size()));
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = BindArgs(args);
    if (errCode != E_OK) {
        return errCode;
    }
    errCode = InnerStep();
    if (errCode != E_NO_MORE_ROWS && errCode != E_OK) {
        LOG_ERROR("sqlite3_step failed %{public}d, sql is %{public}s, errno %{public}d",
            errCode, SqliteUtils::SqlAnonymous(sql_).c_str(), errno);
        auto db = sqlite3_db_handle(stmt_);
        // errno: 28 No space left on device
        return (errCode == E_SQLITE_IOERR && sqlite3_system_errno(db) == 28) ? E_SQLITE_IOERR_FULL : errCode;
    }

    if (slave_) {
        int code = slave_->Execute(args);
        if (code != E_OK) {
            LOG_ERROR("slave execute errCode:%{public}d, sql is %{public}s, errno %{public}d code %{public}d", errCode,
                SqliteUtils::SqlAnonymous(sql_).c_str(), errno, code);
            SqliteUtils::SetSlaveInvalid(config_->GetPath());
        }
    }
    return E_OK;
}

std::pair<int, ValueObject> SqliteStatement::ExecuteForValue(const std::vector<ValueObject> &args)
{
    auto errCode = Execute(args);
    if (errCode == E_OK) {
        return GetColumn(0);
    }
    return { errCode, ValueObject() };
}

std::pair<int, std::vector<ValuesBucket>> SqliteStatement::ExecuteForRows(
    const std::vector<ValueObject> &args, int32_t maxCount)
{
    std::vector<std::reference_wrapper<ValueObject>> refArgs;
    for (auto &object : args) {
        refArgs.emplace_back(std::ref(const_cast<ValueObject &>(object)));
    }
    return ExecuteForRows(refArgs, maxCount);
}

std::pair<int, std::vector<ValuesBucket>> SqliteStatement::ExecuteForRows(
    const std::vector<std::reference_wrapper<ValueObject>> &args, int32_t maxCount)
{
    if (columnCount_ <= 0) {
        return { Execute(args), {} };
    }
    std::pair<int, std::vector<ValuesBucket>> ret;
    auto &[errCode, rows] = ret;
    errCode = CheckEnvironment(static_cast<int>(args.size()));
    if (errCode != E_OK) {
        return ret;
    }
    errCode = BindArgs(args);
    if (errCode != E_OK) {
        return ret;
    }

    ret = GetRows(maxCount);
    if (errCode != E_NO_MORE_ROWS && errCode != E_OK) {
        LOG_ERROR("sqlite3_step failed %{public}d, sql is %{public}s, errno %{public}d", errCode,
            SqliteUtils::SqlAnonymous(sql_).c_str(), errno);
        auto db = sqlite3_db_handle(stmt_);
        // errno: 28 No space left on device
        errCode = (errCode == E_SQLITE_IOERR && sqlite3_system_errno(db) == 28) ? E_SQLITE_IOERR_FULL : errCode;
        return ret;
    }

    if (slave_) {
        int code = slave_->Execute(args);
        if (code != E_OK) {
            LOG_ERROR("slave execute errCode:%{public}d, sql is %{public}s, errno %{public}d code %{public}d", errCode,
                SqliteUtils::SqlAnonymous(sql_).c_str(), errno, code);
            SqliteUtils::SetSlaveInvalid(config_->GetPath());
        }
    }
    return {E_OK, rows};
}

int SqliteStatement::Changes() const
{
    if (stmt_ == nullptr) {
        return -1;
    }
    auto db = sqlite3_db_handle(stmt_);
    return sqlite3_changes(db);
}

int64_t SqliteStatement::LastInsertRowId() const
{
    if (stmt_ == nullptr) {
        return -1;
    }
    auto db = sqlite3_db_handle(stmt_);
    return sqlite3_last_insert_rowid(db);
}

int32_t SqliteStatement::GetColumnCount() const
{
    return columnCount_;
}

std::pair<int32_t, std::string> SqliteStatement::GetColumnName(int index) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        return { ret, "" };
    }

    const char *name = sqlite3_column_name(stmt_, index);
    if (name == nullptr) {
        LOG_ERROR("column_name is null.");
        return { E_ERROR, "" };
    }
    return { E_OK, std::string(name) };
}

static int32_t Convert2ColumnType(int32_t type)
{
    switch (type) {
        case SQLITE_INTEGER:
            return int32_t(ColumnType::TYPE_INTEGER);
        case SQLITE_FLOAT:
            return int32_t(ColumnType::TYPE_FLOAT);
        case SQLITE_BLOB:
            return int32_t(ColumnType::TYPE_BLOB);
        case SQLITE_TEXT:
            return int32_t(ColumnType::TYPE_STRING);
        default:
            break;
    }
    return int32_t(ColumnType::TYPE_NULL);
}

std::pair<int32_t, int32_t> SqliteStatement::GetColumnType(int index) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        return { ret, int32_t(ColumnType::TYPE_NULL) };
    }

    int type = sqlite3_column_type(stmt_, index);
    if (type != SQLITE_BLOB) {
        return { E_OK, Convert2ColumnType(type) };
    }

    if (types_[index] != COLUMN_TYPE_INVALID) {
        return { E_OK, types_[index] };
    }

    const char *decl = sqlite3_column_decltype(stmt_, index);
    if (decl == nullptr) {
        LOG_ERROR("invalid type %{public}d, errno %{public}d.", type, errno);
        return { E_ERROR, int32_t(ColumnType::TYPE_NULL) };
    }

    auto declType = StringUtils::TruncateAfterFirstParen(SqliteUtils::StrToUpper(decl));
    if (declType == ValueObject::DeclType<ValueObject::Asset>()) {
        types_[index] = int32_t(ColumnType::TYPE_ASSET);
    } else if (declType == ValueObject::DeclType<ValueObject::Assets>()) {
        types_[index] = int32_t(ColumnType::TYPE_ASSETS);
    } else if (declType == ValueObject::DeclType<ValueObject::FloatVector>()) {
        types_[index] = int32_t(ColumnType::TYPE_FLOAT32_ARRAY);
    } else if (declType == ValueObject::DeclType<ValueObject::BigInt>()) {
        types_[index] = int32_t(ColumnType::TYPE_BIGINT);
    } else {
        types_[index] = int32_t(ColumnType::TYPE_BLOB);
    }

    return { E_OK, types_[index] };
}

std::pair<int32_t, size_t> SqliteStatement::GetSize(int index) const
{
    auto [errCode, type] = GetColumnType(index);
    if (errCode != E_OK) {
        return { errCode, 0 };
    }

    if (type == static_cast<int32_t>(ColumnType::TYPE_BLOB) || type == static_cast<int32_t>(ColumnType::TYPE_NULL)) {
        auto size = static_cast<size_t>(sqlite3_column_bytes(stmt_, index));
        return { E_OK, size };
    } else if (type == static_cast<int32_t>(ColumnType::TYPE_STRING)) {
        // Add 1 to size for the string terminator (null character).
        auto size = static_cast<size_t>(sqlite3_column_bytes(stmt_, index) + 1);
        return { E_OK, size };
    }
    return { E_INVALID_COLUMN_TYPE, 0 };
}

std::pair<int32_t, ValueObject> SqliteStatement::GetColumn(int index) const
{
    auto [errCode, type] = GetColumnType(index);
    if (errCode != E_OK) {
        return { errCode, ValueObject() };
    }

    switch (static_cast<ColumnType>(type)) {
        case ColumnType::TYPE_FLOAT:
            return { E_OK, ValueObject(sqlite3_column_double(stmt_, index)) };
        case ColumnType::TYPE_INTEGER:
            return { E_OK, ValueObject(static_cast<int64_t>(sqlite3_column_int64(stmt_, index))) };
        case ColumnType::TYPE_STRING: {
            int size = sqlite3_column_bytes(stmt_, index);
            auto text = reinterpret_cast<const char *>(sqlite3_column_text(stmt_, index));
            return { E_OK, ValueObject(text == nullptr ? std::string("") : std::string(text, size)) };
        }
        case ColumnType::TYPE_NULL:
            return { E_OK, ValueObject() };
        default:
            break;
    }
    return { E_OK, GetValueFromBlob(index, type) };
}

std::pair<int32_t, std::vector<ValuesBucket>> SqliteStatement::GetRows(int32_t maxCount)
{
    auto colCount = GetColumnCount();
    if (colCount <= 0) {
        return { E_OK, {} };
    }
    std::vector<std::string> colNames;
    colNames.reserve(colCount);
    for (int i = 0; i < colCount; i++) {
        auto [code, colName] = GetColumnName(i);
        if (code != E_OK) {
            LOG_ERROR("GetColumnName ret %{public}d", code);
            return { code, {} };
        }
        colNames.push_back(std::move(colName));
    }
    AppDataFwk::CacheBlock block(maxCount, colNames);
    SharedBlockInfo info(&block);
    info.isCountAllRows = true;
    info.totalRows = -1;
    auto res = FillBlockInfo(&info, 0);
    if (res != E_OK) {
        LOG_ERROR("FillBlockInfo ret %{public}d", res);
        return { res, {} };
    }
    if (block.HasException()) {
        LOG_ERROR("HasException ret");
        return { E_ERROR, {} };
    }
    return { E_OK, block.StealRows() };
}

ValueObject SqliteStatement::GetValueFromBlob(int32_t index, int32_t type) const
{
    int size = sqlite3_column_bytes(stmt_, index);
    auto blob = static_cast<const uint8_t *>(sqlite3_column_blob(stmt_, index));
    if (blob == nullptr || size <= 0) {
        return ValueObject();
    }
    switch (static_cast<ColumnType>(type)) {
        case ColumnType::TYPE_ASSET: {
            Asset asset;
            RawDataParser::ParserRawData(blob, size, asset);
            return ValueObject(std::move(asset));
        }
        case ColumnType::TYPE_ASSETS: {
            Assets assets;
            RawDataParser::ParserRawData(blob, size, assets);
            return ValueObject(std::move(assets));
        }
        case ColumnType::TYPE_FLOAT32_ARRAY: {
            Floats floats;
            RawDataParser::ParserRawData(blob, size, floats);
            return ValueObject(std::move(floats));
        }
        case ColumnType::TYPE_BIGINT: {
            BigInt bigint;
            RawDataParser::ParserRawData(blob, size, bigint);
            return ValueObject(std::move(bigint));
        }
        default:
            break;
    }
    return ValueObject(std::vector<uint8_t>(blob, blob + size));
}

bool SqliteStatement::ReadOnly() const
{
    return readOnly_;
}

bool SqliteStatement::SupportBlockInfo() const
{
    auto db = sqlite3_db_handle(stmt_);
    return (sqlite3_db_config(db, SQLITE_USE_SHAREDBLOCK) == SQLITE_OK);
}

int32_t SqliteStatement::FillBlockInfo(SharedBlockInfo *info, int retryTime) const
{
    SqlStatistic sqlStatistic("", SqlStatistic::Step::STEP_EXECUTE, seqId_);
    PerfStat perfStat((config_ != nullptr) ? config_->GetPath() : "", "", PerfStat::Step::STEP_EXECUTE, seqId_);
    if (info == nullptr) {
        return E_INVALID_ARGS;
    }
    int32_t errCode = E_OK;
    if (SupportBlockInfo()) {
        errCode = FillSharedBlockOpt(info, stmt_, retryTime);
    } else {
        errCode = FillSharedBlock(info, stmt_, retryTime);
    }
    if (errCode != E_OK) {
        if (config_ != nullptr) {
            Reportor::ReportFault(RdbFaultDbFileEvent(RdbFaultType::FT_CURD, errCode, *config_,
                "FillBlockInfo", true));
        }
        auto ret = (config_ != nullptr && errCode == E_SQLITE_CORRUPT);
        if (ret) {
            Reportor::ReportCorruptedOnce(Reportor::Create(*config_, errCode,
                "FillBlockInfo: " + SqliteGlobalConfig::GetLastCorruptionMsg()));
            CorruptedHandleManager::GetInstance().HandleCorrupt(*config_);
        }
        return errCode;
    }
    if (!ResetStatement(info, stmt_)) {
        LOG_ERROR("ResetStatement Failed.");
        return E_ERROR;
    }
    return E_OK;
}

int32_t SqliteStatement::BindNil(sqlite3_stmt *stat, int index, const ValueObject::Type &arg)
{
    return sqlite3_bind_null(stat, index);
}

int32_t SqliteStatement::BindInteger(sqlite3_stmt *stat, int index, const ValueObject::Type &arg)
{
    auto val = std::get_if<int64_t>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    return sqlite3_bind_int64(stat, index, *val);
}

int32_t SqliteStatement::BindDouble(sqlite3_stmt *stat, int index, const ValueObject::Type &arg)
{
    auto val = std::get_if<double>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    return sqlite3_bind_double(stat, index, *val);
}

int32_t SqliteStatement::BindText(sqlite3_stmt *stat, int index, const ValueObject::Type &arg)
{
    auto val = std::get_if<std::string>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    return sqlite3_bind_text(stat, index, val->c_str(), val->length(), SQLITE_TRANSIENT);
}

int32_t SqliteStatement::BindBool(sqlite3_stmt *stat, int index, const ValueObject::Type &arg)
{
    auto val = std::get_if<bool>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    return sqlite3_bind_int64(stat, index, *val ? 1 : 0);
}

int32_t SqliteStatement::BindBlob(sqlite3_stmt *stat, int index, const ValueObject::Type &arg)
{
    auto val = std::get_if<std::vector<uint8_t>>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }

    if (val->empty()) {
        return sqlite3_bind_zeroblob(stat, index, 0);
    }
    return sqlite3_bind_blob(stat, index, static_cast<const void *>((*val).data()), (*val).size(), SQLITE_TRANSIENT);
}

int32_t SqliteStatement::BindAsset(sqlite3_stmt *stat, int index, const ValueObject::Type &arg)
{
    auto val = std::get_if<Asset>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    auto rawData = RawDataParser::PackageRawData(*val);
    return sqlite3_bind_blob(stat, index, static_cast<const void *>(rawData.data()), rawData.size(), SQLITE_TRANSIENT);
}

int32_t SqliteStatement::BindAssets(sqlite3_stmt *stat, int index, const ValueObject::Type &arg)
{
    auto val = std::get_if<Assets>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    auto rawData = RawDataParser::PackageRawData(*val);
    return sqlite3_bind_blob(stat, index, static_cast<const void *>(rawData.data()), rawData.size(), SQLITE_TRANSIENT);
}

int32_t SqliteStatement::BindFloats(sqlite3_stmt *stat, int index, const ValueObject::Type &object)
{
    auto val = std::get_if<Floats>(&object);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    auto rawData = RawDataParser::PackageRawData(*val);
    return sqlite3_bind_blob(stat, index, static_cast<const void *>(rawData.data()), rawData.size(), SQLITE_TRANSIENT);
}

int32_t SqliteStatement::BindBigInt(sqlite3_stmt *stat, int index, const ValueObject::Type &arg)
{
    auto val = std::get_if<BigInt>(&arg);
    if (val == nullptr) {
        return SQLITE_MISMATCH;
    }
    auto rawData = RawDataParser::PackageRawData(*val);
    return sqlite3_bind_blob(stat, index, static_cast<const void *>(rawData.data()), rawData.size(), SQLITE_TRANSIENT);
}

int SqliteStatement::ModifyLockStatus(
    const std::string &table, const std::vector<std::vector<uint8_t>> &hashKeys, bool isLock)
{
    ::DistributedDB::DBStatus ret;
    auto db = sqlite3_db_handle(stmt_);
    if (db == nullptr) {
        return E_ERROR;
    }
    if (isLock) {
        ret = Lock(table, hashKeys, db);
    } else {
        ret = UnLock(table, hashKeys, db);
    }
    if (ret == ::DistributedDB::DBStatus::OK) {
        return E_OK;
    }
    if (ret == ::DistributedDB::DBStatus::WAIT_COMPENSATED_SYNC) {
        return E_WAIT_COMPENSATED_SYNC;
    }
    if (ret == ::DistributedDB::DBStatus::NOT_FOUND) {
        return E_NO_ROW_IN_QUERY;
    }
    LOG_ERROR("Lock/Unlock failed, err is %{public}d.", ret);
    return E_ERROR;
}

int SqliteStatement::InnerFinalize()
{
    if (stmt_ == nullptr) {
        return E_OK;
    }

    auto db = sqlite3_db_handle(stmt_);
    int errCode = sqlite3_finalize(stmt_);
    TryNotifyErrorLog(errCode, db, sql_);
    stmt_ = nullptr;
    sql_ = "";
    readOnly_ = false;
    columnCount_ = -1;
    numParameters_ = 0;
    types_ = std::vector<int32_t>();
    if (errCode != SQLITE_OK) {
        LOG_ERROR("finalize ret is %{public}d, errno is %{public}d", errCode, errno);
        return SQLiteError::ErrNo(errCode);
    }
    return E_OK;
}

int SqliteStatement::CheckEnvironment(int paramCount) const
{
    if (paramCount != numParameters_) {
        LOG_ERROR("bind args count(%{public}d) > numParameters(%{public}d), sql is %{public}s", paramCount,
            numParameters_, SqliteUtils::SqlAnonymous(sql_).c_str());
        return E_INVALID_BIND_ARGS_COUNT;
    }

    if (conn_ != nullptr) {
        if (!conn_->IsWriter() && !ReadOnly()) {
            return E_EXECUTE_WRITE_IN_READ_CONNECTION;
        }
        auto errCode = E_OK;
        int sqlType = SqliteUtils::GetSqlStatementType(sql_);
        if (sqlType != SqliteUtils::STATEMENT_COMMIT && sqlType != SqliteUtils::STATEMENT_ROLLBACK) {
            errCode = conn_->LimitWalSize();
        }
        if (errCode != E_OK) {
            return errCode;
        }
    }
    return E_OK;
}
} // namespace NativeRdb
} // namespace OHOS
