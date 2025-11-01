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
#define LOG_TAG "RdStatement"
#include "rd_statement.h"

#include <chrono>
#include <cinttypes>
#include <iomanip>
#include <sstream>

#include "corrupted_handle_manager.h"
#include "logger.h"
#include "raw_data_parser.h"
#include "rd_connection.h"
#include "rd_utils.h"
#include "rdb_errno.h"
#include "rdb_fault_hiview_reporter.h"
#include "sqlite_global_config.h"
#include "sqlite_utils.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;
using Reportor = RdbFaultHiViewReporter;
RdStatement::RdStatement()
{
}

RdStatement::~RdStatement()
{
    Finalize();
}

constexpr size_t PRAGMA_VERSION_SQL_LEN = __builtin_strlen(GlobalExpr::PRAGMA_VERSION);

static bool TryEatSymbol(const std::string &str, char symbol, size_t &curIdx)
{
    size_t idx = curIdx;
    while (idx < str.length()) {
        if (str[idx] == ' ') {
            idx++;
            continue;
        }
        if (str[idx] == symbol) {
            curIdx = idx + 1;
            return true;
        }
        break;
    }
    return false;
}

static int TryEatNumber(const std::string &str, int &outNumber, size_t &curIdx)
{
    size_t idx = curIdx;
    uint32_t numSpace = 0;
    bool hasMeetDigit = false;
    while (idx < str.length()) {
        if (str[idx] == ' ' && !hasMeetDigit) {
            idx++;
            numSpace++;
            continue;
        }
        if (isdigit(str[idx]) != 0) {
            idx++;
            hasMeetDigit = true;
            continue;
        }
        // Indicates that meet first not-digit-char
        break;
    }
    if (!hasMeetDigit) {
        return false;
    }
    outNumber = atoi(str.substr(curIdx).c_str());
    curIdx = idx;
    return true;
}

static int EndWithNull(const std::string &str, size_t curIdx)
{
    size_t idx = curIdx;
    while (idx < str.length()) {
        if (str[idx] == ' ') {
            idx++;
            continue;
        }
        return false;
    }
    return true;
}

int RdStatement::Prepare(GRD_DB *db, const std::string &newSql)
{
    if (newSql.find(GlobalExpr::PRAGMA_VERSION) == 0) {
        // Indicates that sql is start with pragma version
        if (newSql.length() == PRAGMA_VERSION_SQL_LEN) {
            // Indicates that sql is to get version
            sql_ = newSql;
            readOnly_ = true;
            return E_OK;
        }
        size_t curIdx = PRAGMA_VERSION_SQL_LEN;
        int version = 0;
        if ((!TryEatSymbol(newSql, '=', curIdx)) || (!TryEatNumber(newSql, version, curIdx)) ||
            (!EndWithNull(newSql, curIdx) && !TryEatSymbol(newSql, ';', curIdx))) {
            return E_INCORRECT_SQL;
        }

        readOnly_ = false;
        sql_ = newSql;
        return setPragmas_["user_version"](version);
    }
    if (sql_.compare(newSql) == 0) {
        return E_OK;
    }
    GRD_SqlStmt *tmpStmt = nullptr;
    int ret = RdUtils::RdSqlPrepare(db, newSql.c_str(), newSql.length(), &tmpStmt, nullptr);
    if (ret != E_OK) {
        if (ret == E_SQLITE_CORRUPT && config_ != nullptr) {
            Reportor::ReportCorruptedOnce(Reportor::Create(*config_, ret));
            CorruptedHandleManager::GetInstance().HandleCorrupt(*config_);
        }
        if (tmpStmt != nullptr) {
            (void)RdUtils::RdSqlFinalize(tmpStmt);
        }
        LOG_ERROR("Prepare sql for stmt ret is %{public}d", ret);
        return ret;
    }
    Finalize(); // Finalize original stmt
    sql_ = newSql;
    stmtHandle_ = tmpStmt;
    columnCount_ = RdUtils::RdSqlColCnt(tmpStmt);
    readOnly_ = SqliteUtils::GetSqlStatementType(newSql) == SqliteUtils::STATEMENT_SELECT;
    return E_OK;
}

int RdStatement::Finalize()
{
    if (stmtHandle_ == nullptr) {
        return E_OK;
    }
    int ret = RdUtils::RdSqlFinalize(stmtHandle_);
    if (ret != E_OK) {
        LOG_ERROR("Finalize ret is %{public}d", ret);
        return ret;
    }
    stmtHandle_ = nullptr;
    sql_ = "";
    columnCount_ = 0;
    readOnly_ = false;
    config_ = nullptr;
    return E_OK;
}

int RdStatement::InnerBindBlobTypeArgs(const ValueObject &arg, uint32_t index) const
{
    int ret = E_OK;
    switch (arg.GetType()) {
        case ValueObjectType::TYPE_BLOB: {
            std::vector<uint8_t> blob;
            arg.GetBlob(blob);
            ret = RdUtils::RdSqlBindBlob(
                stmtHandle_, index, static_cast<const void *>(blob.data()), blob.size(), nullptr);
            break;
        }
        case ValueObjectType::TYPE_BOOL: {
            bool boolVal = false;
            arg.GetBool(boolVal);
            ret = RdUtils::RdSqlBindInt64(stmtHandle_, index, boolVal ? 1 : 0);
            break;
        }
        case ValueObjectType::TYPE_ASSET: {
            ValueObject::Asset asset;
            arg.GetAsset(asset);
            auto rawData = RawDataParser::PackageRawData(asset);
            ret = RdUtils::RdSqlBindBlob(
                stmtHandle_, index, static_cast<const void *>(rawData.data()), rawData.size(), nullptr);
            break;
        }
        case ValueObjectType::TYPE_ASSETS: {
            ValueObject::Assets assets;
            arg.GetAssets(assets);
            auto rawData = RawDataParser::PackageRawData(assets);
            ret = RdUtils::RdSqlBindBlob(
                stmtHandle_, index, static_cast<const void *>(rawData.data()), rawData.size(), nullptr);
            break;
        }
        case ValueObjectType::TYPE_VECS: {
            ValueObject::FloatVector vectors;
            arg.GetVecs(vectors);
            ret = RdUtils::RdSqlBindFloatVector(
                stmtHandle_, index, static_cast<float *>(vectors.data()), vectors.size(), nullptr);
            break;
        }
        default: {
            std::string str;
            arg.GetString(str);
            ret = RdUtils::RdSqlBindText(stmtHandle_, index, str.c_str(), str.length(), nullptr);
            break;
        }
    }
    return ret;
}

int RdStatement::PreGetColCount()
{
    if (!isStepInPrepare_ && readOnly_) {
        isStepInPrepare_ = true;
        int ret = Step();
        if (ret != E_OK && ret != E_NO_MORE_ROWS) {
            isStepInPrepare_ = false;
            return ret;
        }
        GetProperties();
        if (ret == E_NO_MORE_ROWS) {
            Reset();
        }
    }
    return E_OK;
}

int RdStatement::IsValid(int index) const
{
    if (stmtHandle_ == nullptr) {
        LOG_ERROR("Statement already close.");
        return E_ALREADY_CLOSED;
    }
    if (index < 0 || index >= columnCount_) {
        LOG_ERROR("Index (%{public}d) >= columnCount (%{public}d)", index, columnCount_);
        return E_COLUMN_OUT_RANGE;
    }
    return E_OK;
}

int32_t RdStatement::Prepare(const std::string &sql)
{
    if (dbHandle_ == nullptr) {
        return E_ERROR;
    }
    return Prepare(dbHandle_, sql);
}

int32_t RdStatement::Bind(const std::vector<ValueObject> &args)
{
    std::vector<std::reference_wrapper<ValueObject>> refArgs;
    for (auto &object : args) {
        refArgs.emplace_back(std::ref(const_cast<ValueObject &>(object)));
    }
    return Bind(refArgs);
}

int32_t RdStatement::Bind(const std::vector<std::reference_wrapper<ValueObject>> &args)
{
    uint32_t index = 1;
    int ret = E_OK;
    for (auto &arg : args) {
        switch (arg.get().GetType()) {
            case ValueObjectType::TYPE_NULL: {
                ret = RdUtils::RdSqlBindNull(stmtHandle_, index);
                break;
            }
            case ValueObjectType::TYPE_INT: {
                int64_t value = 0;
                arg.get().GetLong(value);
                ret = RdUtils::RdSqlBindInt64(stmtHandle_, index, value);
                break;
            }
            case ValueObjectType::TYPE_DOUBLE: {
                double doubleVal = 0;
                arg.get().GetDouble(doubleVal);
                ret = RdUtils::RdSqlBindDouble(stmtHandle_, index, doubleVal);
                break;
            }
            default: {
                ret = InnerBindBlobTypeArgs(arg, index);
                break;
            }
        }
        if (ret != E_OK) {
            LOG_ERROR("Bind ret is %{public}d", ret);
            return ret;
        }
        index++;
    }
    return PreGetColCount();
}

std::pair<int32_t, int32_t> RdStatement::Count()
{
    return { E_NOT_SUPPORT, INVALID_COUNT };
}

int32_t RdStatement::Step()
{
    if (stmtHandle_ == nullptr) {
        return E_OK;
    }
    if (isStepInPrepare_ && stepCnt_ == 1) {
        stepCnt_++;
        return E_OK;
    }
    int ret = RdUtils::RdSqlStep(stmtHandle_);
    if (ret == E_SQLITE_CORRUPT && config_ != nullptr) {
        Reportor::ReportCorruptedOnce(Reportor::Create(*config_, ret));
        CorruptedHandleManager::GetInstance().HandleCorrupt(*config_);
    }
    stepCnt_++;
    return ret;
}

int32_t RdStatement::Reset()
{
    if (stmtHandle_ == nullptr) {
        return E_OK;
    }
    stepCnt_ = 0;
    isStepInPrepare_ = false;
    return RdUtils::RdSqlReset(stmtHandle_);
}

int32_t RdStatement::Execute(const std::vector<ValueObject> &args)
{
    std::vector<std::reference_wrapper<ValueObject>> refArgs;
    for (auto &object : args) {
        refArgs.emplace_back(std::ref(const_cast<ValueObject &>(object)));
    }
    return Execute(refArgs);
}

int32_t RdStatement::Execute(const std::vector<std::reference_wrapper<ValueObject>> &args)
{
    if (!readOnly_ && strcmp(sql_.c_str(), GlobalExpr::PRAGMA_VERSION) == 0) {
        // It has already set version in prepare procedure
        // Current modification is only temporary for unification between rd and sqlite,
        // rd kernal will support pragma in later version
        return E_OK;
    }
    int ret = Bind(args);
    if (ret != E_OK) {
        LOG_ERROR("RdConnection unable to prepare and bind stmt : err %{public}d", ret);
        return ret;
    }
    ret = Step();
    if (ret != E_OK && ret != E_NO_MORE_ROWS) {
        LOG_ERROR("RdConnection Execute : err %{public}d", ret);
    }
    return ret;
}

std::pair<int, ValueObject> RdStatement::ExecuteForValue(const std::vector<ValueObject> &args)
{
    int ret = E_OK;
    if (readOnly_ && strcmp(sql_.c_str(), GlobalExpr::PRAGMA_VERSION) == 0) {
        int version = 0;
        ret = getPragmas_["user_version"](version);
        if (ret != E_OK) {
            LOG_ERROR("RdConnection unable to GetVersion : err %{public}d", ret);
            return { ret, ValueObject() };
        }
        return { ret, ValueObject(version) };
    }
    ret = Bind(args);
    if (ret != E_OK) {
        LOG_ERROR("RdConnection unable to prepare and bind stmt : err %{public}d", ret);
        return { ret, ValueObject() };
    }
    ret = Step();
    if (ret != E_OK && ret != E_NO_MORE_ROWS) {
        LOG_ERROR("RdConnection Execute : err %{public}d", ret);
        return { ret, ValueObject() };
    }
    return GetColumn(0);
}

int32_t RdStatement::Changes() const
{
    return 0;
}

int64_t RdStatement::LastInsertRowId() const
{
    return 0;
}

int32_t RdStatement::GetColumnCount() const
{
    return columnCount_;
}

std::pair<int32_t, std::string> RdStatement::GetColumnName(int32_t index) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        return { ret, "" };
    }
    const char *name = RdUtils::RdSqlColName(stmtHandle_, index);
    if (name == nullptr) {
        LOG_ERROR("column_name is null.");
        return { E_ERROR, "" };
    }
    return { E_OK, name };
}

std::pair<int32_t, int32_t> RdStatement::GetColumnType(int32_t index) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        return { ret, static_cast<int32_t>(ColumnType::TYPE_NULL) };
    }
    ColumnType type = RdUtils::RdSqlColType(stmtHandle_, index);
    switch (type) {
        case ColumnType::TYPE_INTEGER:
        case ColumnType::TYPE_FLOAT:
        case ColumnType::TYPE_NULL:
        case ColumnType::TYPE_STRING:
        case ColumnType::TYPE_BLOB:
        case ColumnType::TYPE_FLOAT32_ARRAY:
            break;
        default:
            LOG_ERROR("Invalid type %{public}d.", type);
            return { E_ERROR, static_cast<int32_t>(ColumnType::TYPE_NULL) };
    }
    return { ret, static_cast<int32_t>(type) };
}

std::pair<int32_t, size_t> RdStatement::GetSize(int32_t index) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        return { ret, 0 };
    }
    ColumnType type = RdUtils::RdSqlColType(stmtHandle_, index);
    if (type == ColumnType::TYPE_BLOB || type == ColumnType::TYPE_STRING || type == ColumnType::TYPE_NULL ||
        type == ColumnType::TYPE_FLOAT32_ARRAY) {
        return { E_OK, static_cast<size_t>(RdUtils::RdSqlColBytes(stmtHandle_, index)) };
    }
    return { E_INVALID_COLUMN_TYPE, 0 };
}

std::pair<int32_t, ValueObject> RdStatement::GetColumn(int32_t index) const
{
    ValueObject object;
    int ret = IsValid(index);
    if (ret != E_OK) {
        return { ret, object };
    }

    ColumnType type = RdUtils::RdSqlColType(stmtHandle_, index);
    switch (type) {
        case ColumnType::TYPE_FLOAT:
            object = RdUtils::RdSqlColDouble(stmtHandle_, index);
            break;
        case ColumnType::TYPE_INTEGER:
            object = static_cast<int64_t>(RdUtils::RdSqlColInt64(stmtHandle_, index));
            break;
        case ColumnType::TYPE_STRING:
            object = reinterpret_cast<const char *>(RdUtils::RdSqlColText(stmtHandle_, index));
            break;
        case ColumnType::TYPE_NULL:
            break;
        case ColumnType::TYPE_FLOAT32_ARRAY: {
            uint32_t dim = 0;
            auto vectors = reinterpret_cast<const float *>(RdUtils::RdSqlColumnFloatVector(stmtHandle_, index, &dim));
            std::vector<float> vecData;
            if (dim > 0 || vectors != nullptr) {
                vecData.resize(dim);
                vecData.assign(vectors, vectors + dim);
            }
            object = std::move(vecData);
            break;
        }
        case ColumnType::TYPE_BLOB: {
            int size = RdUtils::RdSqlColBytes(stmtHandle_, index);
            auto blob = static_cast<const uint8_t *>(RdUtils::RdSqlColBlob(stmtHandle_, index));
            std::vector<uint8_t> rawData;
            if (size > 0 || blob != nullptr) {
                rawData.resize(size);
                rawData.assign(blob, blob + size);
            }
            object = std::move(rawData);
            break;
        }
        default:
            break;
    }
    return { ret, std::move(object) };
}

bool RdStatement::ReadOnly() const
{
    return readOnly_;
}

bool RdStatement::SupportBlockInfo() const
{
    return false;
}

int32_t RdStatement::FillBlockInfo(SharedBlockInfo *info) const
{
    return E_NOT_SUPPORT;
}

void RdStatement::GetProperties()
{
    columnCount_ = RdUtils::RdSqlColCnt(stmtHandle_);
}

std::pair<int32_t, std::vector<ValuesBucket>> RdStatement::GetRows(uint32_t maxCount)
{
    return { E_NOT_SUPPORT, {} };
}
} // namespace NativeRdb
} // namespace OHOS
