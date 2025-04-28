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
#define LOG_TAG "GdbStmt"
#include "graph_statement.h"

#include <utility>

#include "gdb_errors.h"
#include "connection.h"
#include "full_result.h"
#include "grd_error.h"
#include "logger.h"

namespace OHOS::DistributedDataAip {
GraphStatement::GraphStatement(GRD_DB *db, const std::string &gql, std::shared_ptr<Connection> conn, int32_t &errCode)
    : conn_(conn), gql_(gql), dbHandle_(db)
{
    errCode = E_OK;
    if (db == nullptr || gql.empty()) {
        errCode = E_PREPARE_CHECK_FAILED;
        return;
    }

    errCode = GrdAdapter::Prepare(dbHandle_, gql_.c_str(), gql_.size(), &stmtHandle_, nullptr);
    if (errCode != E_OK) {
        LOG_ERROR("GRD_GqlPrepare failed. ret=%{public}d", errCode);
        if (stmtHandle_ != nullptr) {
            GrdAdapter::Finalize(stmtHandle_);
        }
    }
}

GraphStatement::~GraphStatement()
{
    Finalize();
}

int32_t GraphStatement::Prepare()
{
    if (dbHandle_ == nullptr || gql_.empty()) {
        return E_PREPARE_CHECK_FAILED;
    }

    int32_t ret = GrdAdapter::Prepare(dbHandle_, gql_.c_str(), gql_.size(), &stmtHandle_, nullptr);
    if (ret != E_OK) {
        LOG_ERROR("GRD_GqlPrepare failed. ret=%{public}d", ret);
    }
    return ret;
}

int32_t GraphStatement::Step()
{
    if (stmtHandle_ == nullptr) {
        return E_STEP_CHECK_FAILED;
    }
    int32_t ret = GrdAdapter::Step(stmtHandle_);
    if (ret != E_OK && ret != E_GRD_NO_DATA) {
        LOG_ERROR("GRD_GqlStep failed. ret=%{public}d", ret);
    }
    return ret;
}

int32_t GraphStatement::Finalize()
{
    if (stmtHandle_ == nullptr) {
        return E_OK;
    }
    int32_t ret = GrdAdapter::Finalize(stmtHandle_);
    if (ret != E_OK) {
        LOG_ERROR("GRD_GqlFinalize failed. ret=%{public}d", ret);
        return ret;
    }
    stmtHandle_ = nullptr;
    gql_ = "";
    return E_OK;
}

uint32_t GraphStatement::GetColumnCount() const
{
    if (stmtHandle_ == nullptr) {
        return E_STATEMENT_EMPTY;
    }
    return GrdAdapter::ColumnCount(stmtHandle_);
}

std::pair<int32_t, std::string> GraphStatement::GetColumnName(int32_t index) const
{
    if (stmtHandle_ == nullptr) {
        return { E_STATEMENT_EMPTY, "" };
    }
    const char *name = GrdAdapter::ColumnName(stmtHandle_, index);
    if (name == nullptr) {
        LOG_ERROR("column_name is null. index=%{public}d", index);
        return { E_GETTED_COLNAME_EMPTY, "" };
    }
    return { E_OK, name };
}

std::pair<int32_t, ColumnType> GraphStatement::GetColumnType(int32_t index) const
{
    if (stmtHandle_ == nullptr) {
        return { E_STATEMENT_EMPTY, ColumnType::TYPE_NULL };
    }
    GRD_DbDataTypeE type = GrdAdapter::ColumnType(stmtHandle_, index);
    return { E_OK, GrdAdapter::TransColType(type) };
}

GraphValue GraphStatement::ParseJsonStr(const std::string &jsonStr, int32_t &errCode)
{
    if (jsonStr.empty()) {
        LOG_WARN("parse json string. jsonStr is empty");
        errCode = E_OK;
        return nullptr;
    }
    nlohmann::json json = nlohmann::json::parse(jsonStr, nullptr, false);
    if (json.is_discarded()) {
        LOG_ERROR("parse json string failed. jsonStr=%{public}s", jsonStr.c_str());
        errCode = E_PARSE_JSON_FAILED;
        return nullptr;
    }

    errCode = E_OK;
    if (json.is_null()) {
        LOG_WARN("parse json string. jsonStr is empty");
        return nullptr;
    }
    if (!json.is_object()) {
        LOG_ERROR("json format error. jsonStr=%{public}s", jsonStr.c_str());
        errCode = E_PARSE_JSON_FAILED;
        return nullptr;
    }

    if (json.contains(Path::SEGMENTS)) {
        return Path::Parse(json, errCode);
    }
    if (json.contains(Edge::SOURCEID) && json.contains(Edge::TARGETID)) {
        return Edge::Parse(json, errCode);
    }
    return Vertex::Parse(json, errCode);
}

std::pair<int32_t, GraphValue> GraphStatement::GetColumnValue(int32_t index) const
{
    if (stmtHandle_ == nullptr) {
        return { E_STATEMENT_EMPTY, nullptr };
    }
    ColumnType type = GetColumnType(index).second;
    GraphValue value;

    auto ret = 0;
    switch (type) {
        case ColumnType::TYPE_INTEGER:
            value = GrdAdapter::ColumnInt(stmtHandle_, index);
            break;
        case ColumnType::TYPE_FLOAT:
            value = GrdAdapter::ColumnDouble(stmtHandle_, index);
            break;
        case ColumnType::TYPE_JSONSTR: {
            auto text = "";
            text = GrdAdapter::ColumnText(stmtHandle_, index);
            value = ParseJsonStr(text, ret);
            if (ret != E_OK) {
                LOG_ERROR("ParseJsonStr failed. index=%{public}d, ret=%{public}d", index, ret);
                return { ret, nullptr };
            }
            break;
        }
        case ColumnType::TYPE_TEXT:
            value = GrdAdapter::ColumnText(stmtHandle_, index);
            break;
        case ColumnType::TYPE_BLOB:
            LOG_ERROR("not support blob type. index=%{public}d", index);
            return { E_NOT_SUPPORT, nullptr };
        case ColumnType::TYPE_FLOATVECTOR: {
            value = GrdAdapter::ColumnFloatVector(stmtHandle_, index);
            break;
        }
        case ColumnType::TYPE_NULL:
        default:
            value = nullptr;
    }
    return { E_OK, value };
}

bool GraphStatement::IsReady() const
{
    return !gql_.empty() && stmtHandle_ != nullptr && dbHandle_ != nullptr;
}
} // namespace OHOS::DistributedDataAip
