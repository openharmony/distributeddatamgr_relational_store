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
#define LOG_TAG "RdSharedResultSet"
#include "rd_statement.h"

#include <iomanip>
#include <sstream>
#include <chrono>
#include <cinttypes>
#include "logger.h"
#include "raw_data_parser.h"
#include "rdb_errno.h"
#include "rd_utils.h"
#include "rdb_connection.h"

namespace OHOS {
namespace NativeRdb {
using namespace OHOS::Rdb;

std::shared_ptr<RdStatement> RdStatement::CreateStatement(
    std::shared_ptr<RdConnection> connection, const std::string &sql)
{
    (void)connection;
    (void)sql;
    return std::make_shared<RdStatement>();
}

RdStatement::RdStatement()
{
}

RdStatement::~RdStatement()
{
    Finalize();
}

int RdStatement::Prepare(GRD_DB *db, const std::string &newSql)
{
    if (sql_.compare(newSql) == 0) {
        return E_OK;
    }
    GRD_SqlStmt *tmpStmt = nullptr;
    int ret = RdUtils::RdSqlPrepare(db, newSql.c_str(), newSql.length(), &tmpStmt, nullptr);
    if (ret != E_OK) {
        if (tmpStmt != nullptr) {
            (void)RdUtils::RdSqlFinalize(tmpStmt);
        }
        LOG_ERROR("Prepare sql for stmt ret is %{public}d", ret);
        return ret;
    }
    Finalize(); // Finalize original stmt
    sql_ = newSql;
    stmtHandle_ = tmpStmt;
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
    return E_OK;
}

int RdStatement::BindArguments(const std::vector<ValueObject> &bindArgs) const
{
    if (bindArgs.empty()) {
        return E_OK;
    }
    return InnerBindArguments(bindArgs);
}

int RdStatement::InnerBindBlobTypeArgs(const ValueObject &arg, uint32_t index) const
{
    int ret = E_OK;
    switch (arg.GetType()) {
        case ValueObjectType::TYPE_BLOB: {
            std::vector<uint8_t> blob;
            arg.GetBlob(blob);
            ret = RdUtils::RdSqlBindBlob(stmtHandle_, index, static_cast<const void *>(blob.data()), blob.size(),
                nullptr);
            break;
        }
        case ValueObjectType::TYPE_BOOL: {
            bool boolVal = false;
            arg.GetBool(boolVal);
            ret = RdUtils::RdSqlBindInt64(stmtHandle_, index, boolVal ? 1 : 0);
            break;
        }
        case ValueObjectType::TYPE_ASSET: {
            Asset asset;
            arg.GetAsset(asset);
            auto rawData = RawDataParser::PackageRawData(asset);
            ret = RdUtils::RdSqlBindBlob(stmtHandle_, index, static_cast<const void *>(rawData.data()),
                rawData.size(), nullptr);
            break;
        }
        case ValueObjectType::TYPE_ASSETS: {
            Assets assets;
            arg.GetAssets(assets);
            auto rawData = RawDataParser::PackageRawData(assets);
            ret = RdUtils::RdSqlBindBlob(stmtHandle_, index, static_cast<const void *>(rawData.data()),
                rawData.size(), nullptr);
            break;
        }
        case ValueObjectType::TYPE_VECS: {
            FloatVector vectors;
            arg.GetVecs(vectors);
            ret = RdUtils::RdSqlBindFloatVector(stmtHandle_, index,
                static_cast<float *>(vectors.data()), vectors.size(), nullptr);
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

int RdStatement::InnerBindArguments(const std::vector<ValueObject> &bindArgs) const
{
    uint32_t index = 1;
    int ret = E_OK;
    for (auto arg : bindArgs) {
        switch (arg.GetType()) {
            case ValueObjectType::TYPE_NULL: {
                ret = RdUtils::RdSqlBindNull(stmtHandle_, index);
                break;
            }
            case ValueObjectType::TYPE_INT: {
                int64_t value = 0;
                arg.GetLong(value);
                ret = RdUtils::RdSqlBindInt64(stmtHandle_, index, value);
                break;
            }
            case ValueObjectType::TYPE_DOUBLE: {
                double doubleVal = 0;
                arg.GetDouble(doubleVal);
                ret = RdUtils::RdSqlBindDouble(stmtHandle_, index, doubleVal);
                break;
            }
            default: {
                ret = InnerBindBlobTypeArgs(arg, index);
                break;
            }
        }
        if (ret != E_OK) {
            LOG_ERROR("bind ret is %{public}d", ret);
            return ret;
        }
        index++;
    }
    return E_OK;
}

int RdStatement::ResetStatementAndClearBindings() const
{
    if (stmtHandle_ == nullptr) {
        return E_OK;
    }
    int ret = RdUtils::RdSqlReset(stmtHandle_);
    if (ret != E_OK) {
        LOG_ERROR("reset ret is %{public}d", ret);
    }
    return ret;
}

int RdStatement::Step() const
{
    return RdUtils::RdSqlStep(stmtHandle_);
}

int RdStatement::GetColumnCount(int &count) const
{
    if (stmtHandle_ == nullptr) {
        LOG_ERROR("statement already close.");
        return E_ALREADY_CLOSED;
    }
    count = RdUtils::RdSqlColCnt(stmtHandle_);
    return E_OK;
}

int RdStatement::GetColumnName(int index, std::string &columnName) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        return ret;
    }
    const char *name = RdUtils::RdSqlColName(stmtHandle_, index);
    if (name == nullptr) {
        LOG_ERROR("column_name is null.");
        return E_ERROR;
    }
    columnName = std::string(name);
    return E_OK;
}

int RdStatement::GetColumnType(int index, int &columnType) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        return ret;
    }
    ColumnType type = RdUtils::RdSqlColType(stmtHandle_, index);
    switch (type) {
        case ColumnType::TYPE_INTEGER:
        case ColumnType::TYPE_FLOAT:
        case ColumnType::TYPE_NULL:
        case ColumnType::TYPE_STRING:
            columnType = static_cast<int>(type);
            return E_OK;
        case ColumnType::TYPE_BLOB: {
            // Attention! Grd can not distinguish assets type and blob type
            columnType = static_cast<int>(type);
            return E_OK;
        }
        case ColumnType::TYPE_FLOAT32_ARRAY: {
            columnType = static_cast<int>(type);
            return E_OK;
        }
        default:
            LOG_ERROR("invalid type %{public}d.", type);
            return E_ERROR;
    }
}

int RdStatement::GetFloat32Array(int index, std::vector<float> &vecs) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        // It has already logged inside
        return ret;
    }
    ColumnType type = RdUtils::RdSqlColType(stmtHandle_, index);
    if (type != ColumnType::TYPE_FLOAT32_ARRAY) {
        LOG_ERROR("invalid type %{public}d.", static_cast<int>(type));
        return E_INVALID_COLUMN_TYPE;
    }
    uint32_t dim = 0;
    const float *vec = RdUtils::RdSqlColumnFloatVector(stmtHandle_, index, &dim);
    if (dim == 0 || vec == nullptr) {
        vecs.resize(0);
    } else {
        vecs.resize(dim);
        vecs.assign(vec, vec + dim);
    }
    return E_OK;
}

int RdStatement::GetColumnBlob(int index, std::vector<uint8_t> &value) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        // It has already logged inside
        return ret;
    }
    ColumnType type = RdUtils::RdSqlColType(stmtHandle_, index);
    if (type != ColumnType::TYPE_BLOB && type != ColumnType::TYPE_STRING && type != ColumnType::TYPE_NULL) {
        LOG_ERROR("invalid type %{public}d.", type);
        return E_INVALID_COLUMN_TYPE;
    }
    int size = RdUtils::RdSqlColBytes(stmtHandle_, index);
    const uint8_t *blob = RdUtils::RdSqlColBlob(stmtHandle_, index);
    if (size == 0 || blob == nullptr) {
        value.resize(0);
    } else {
        value.resize(size);
        value.assign(blob, blob + size);
    }
    return E_OK;
}

int RdStatement::GetColumnString(int index, std::string &value) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        return ret;
    }
    ColumnType type = RdUtils::RdSqlColType(stmtHandle_, index);
    switch (type) {
        case ColumnType::TYPE_STRING: {
            auto val = reinterpret_cast<const char *>(RdUtils::RdSqlColText(stmtHandle_, index));
            value = (val == nullptr) ? "" : std::string(val, RdUtils::RdSqlColBytes(stmtHandle_, index) - 1);
            break;
        }
        case ColumnType::TYPE_INTEGER: {
            int64_t val = static_cast<int64_t>(RdUtils::RdSqlColInt64(stmtHandle_, index));
            value = std::to_string(val);
            break;
        }
        case ColumnType::TYPE_FLOAT: {
            double val = RdUtils::RdSqlColDouble(stmtHandle_, index);
            std::ostringstream os;
            if (os << std::setprecision(SET_DATA_PRECISION) << val)
                value = os.str();
            break;
        }
        case ColumnType::TYPE_NULL: {
            value = "";
            return E_OK;
        }
        case ColumnType::TYPE_BLOB: {
            return E_INVALID_COLUMN_TYPE;
        }
        default:
            return E_ERROR;
    }
    return E_OK;
}

int RdStatement::GetColumnInt(int index, int &value)
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        return ret;
    }
    ColumnType type = RdUtils::RdSqlColType(stmtHandle_, index);
    if (type != ColumnType::TYPE_INTEGER) {
        return E_ERROR;
    }
    value = RdUtils::RdSqlColInt(stmtHandle_, index);
    return E_OK;
}

int RdStatement::GetColumnLong(int index, int64_t &value) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        return ret;
    }
    char *errStr = nullptr;
    ColumnType type = RdUtils::RdSqlColType(stmtHandle_, index);
    if (type == ColumnType::TYPE_INTEGER) {
        value = RdUtils::RdSqlColInt64(stmtHandle_, index);
    } else if (type == ColumnType::TYPE_STRING) {
        auto val = reinterpret_cast<const char *>(RdUtils::RdSqlColText(stmtHandle_, index));
        value = (val == nullptr) ? 0 : strtoll(val, &errStr, 0);
    } else if (type == ColumnType::TYPE_FLOAT) {
        double val = RdUtils::RdSqlColDouble(stmtHandle_, index);
        value = static_cast<int64_t>(val);
    } else if (type == ColumnType::TYPE_NULL) {
        value = 0;
    } else if (type == ColumnType::TYPE_BLOB) {
        return E_INVALID_COLUMN_TYPE;
    } else {
        return E_ERROR;
    }
    return E_OK;
}

int RdStatement::GetColumnDouble(int index, double &value) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        return ret;
    }
    char *ptr = nullptr;
    ColumnType type = RdUtils::RdSqlColType(stmtHandle_, index);
    if (type == ColumnType::TYPE_FLOAT) {
        value = RdUtils::RdSqlColDouble(stmtHandle_, index);
    } else if (type == ColumnType::TYPE_INTEGER) {
        int64_t val = static_cast<int64_t>(RdUtils::RdSqlColInt64(stmtHandle_, index));
        value = static_cast<double>(val);
    } else if (type == ColumnType::TYPE_STRING) {
        auto val = reinterpret_cast<const char *>(RdUtils::RdSqlColText(stmtHandle_, index));
        value = (val == nullptr) ? 0.0 : std::strtod(val, &ptr);
    } else if (type == ColumnType::TYPE_NULL) {
        value = 0.0;
    } else if (type == ColumnType::TYPE_BLOB) {
        return E_INVALID_COLUMN_TYPE;
    } else {
        LOG_ERROR("invalid type %{public}d.", type);
        return E_ERROR;
    }
    return E_OK;
}

int RdStatement::GetSize(int index, size_t &size) const
{
    size = 0;
    int ret = IsValid(index);
    if (ret != E_OK) {
        return ret;
    }
    ColumnType type = RdUtils::RdSqlColType(stmtHandle_, index);
    if (type == ColumnType::TYPE_BLOB || type == ColumnType::TYPE_STRING || type == ColumnType::TYPE_NULL ||
        type == ColumnType::TYPE_FLOAT32_ARRAY) {
        size = static_cast<size_t>(RdUtils::RdSqlColBytes(stmtHandle_, index));
        return E_OK;
    }
    return E_INVALID_COLUMN_TYPE;
}

int RdStatement::GetColumn(int index, ValueObject &value) const
{
    int ret = IsValid(index);
    if (ret != E_OK) {
        return ret;
    }

    ColumnType type = RdUtils::RdSqlColType(stmtHandle_, index);
    switch (type) {
        case ColumnType::TYPE_FLOAT:
            value = RdUtils::RdSqlColDouble(stmtHandle_, index);
            return E_OK;
        case ColumnType::TYPE_INTEGER:
            value = static_cast<int64_t>(RdUtils::RdSqlColInt64(stmtHandle_, index));
            return E_OK;
        case ColumnType::TYPE_STRING:
            value = reinterpret_cast<const char *>(RdUtils::RdSqlColText(stmtHandle_, index));
            return E_OK;
        case ColumnType::TYPE_NULL:
            return E_OK;
        case ColumnType::TYPE_FLOAT32_ARRAY: {
            uint32_t dim = 0;
            auto vectors =
                reinterpret_cast<const float *>(RdUtils::RdSqlColumnFloatVector(stmtHandle_, index, &dim));
            std::vector<float> vecData;
            if (dim > 0 || vectors != nullptr) {
                vecData.resize(dim);
                vecData.assign(vectors, vectors + dim);
            }
            value = std::move(vecData);
            return E_OK;
        }
        case ColumnType::TYPE_BLOB: {
            int size = RdUtils::RdSqlColBytes(stmtHandle_, index);
            auto blob = static_cast<const uint8_t *>(RdUtils::RdSqlColBlob(stmtHandle_, index));
            std::vector<uint8_t> rawData;
            if (size > 0 || blob != nullptr) {
                rawData.resize(size);
                rawData.assign(blob, blob + size);
            }
            value = std::move(rawData);
            return E_OK;
        }
        default:
            break;
    }
    return E_OK;
}

bool RdStatement::IsReadOnly() const
{
    return E_NOT_SUPPORT;
}

int RdStatement::IsValid(int index) const
{
    if (stmtHandle_ == nullptr) {
        LOG_ERROR("statement already close.");
        return E_ALREADY_CLOSED;
    }
    return E_OK;
}

} // namespace NativeRdb
} // namespace OHOS
