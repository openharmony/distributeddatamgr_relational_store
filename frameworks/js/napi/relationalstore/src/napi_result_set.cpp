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

#include "napi_result_set.h"

#include <functional>
#include <variant>

#include "js_logger.h"
#include "js_utils.h"
#include "napi_rdb_error.h"
#include "napi_rdb_trace.h"
#include "rdb_errno.h"
#include "values_bucket.h"

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
#include "rdb_result_set_bridge.h"
#include "string_ex.h"
#endif

using namespace OHOS::NativeRdb;
using namespace OHOS::AppDataMgrJsKit;

namespace OHOS {
namespace RelationalStoreJsKit {
static napi_ref __thread ctorRef_ = nullptr;
static const int E_OK = 0;

napi_value ResultSetProxy::NewInstance(napi_env env, std::shared_ptr<NativeRdb::ResultSet> resultSet)
{
    napi_value cons = GetConstructor(env);
    if (cons == nullptr) {
        LOG_ERROR("NewInstance GetConstructor is nullptr!");
        return nullptr;
    }
    napi_value instance;
    napi_status status = napi_new_instance(env, cons, 0, nullptr, &instance);
    if (status != napi_ok) {
        LOG_ERROR("NewInstance napi_new_instance failed! code:%{public}d!", status);
        return nullptr;
    }

    ResultSetProxy *proxy = nullptr;
    status = napi_unwrap(env, instance, reinterpret_cast<void **>(&proxy));
    if (proxy == nullptr) {
        LOG_ERROR("NewInstance native instance is nullptr! code:%{public}d!", status);
        return instance;
    }
    *proxy = std::move(resultSet);
    return instance;
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
std::shared_ptr<DataShare::ResultSetBridge> ResultSetProxy::Create()
{
    return std::make_shared<RdbDataShareAdapter::RdbResultSetBridge>(resultSet_);
}
#endif

napi_value ResultSetProxy::GetConstructor(napi_env env)
{
    napi_value cons;
    if (ctorRef_ != nullptr) {
        NAPI_CALL(env, napi_get_reference_value(env, ctorRef_, &cons));
        return cons;
    }

    LOG_INFO("GetConstructor result set constructor");
    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_FUNCTION("goToRow", GoToRow),
        DECLARE_NAPI_FUNCTION("getLong", GetLong),
        DECLARE_NAPI_FUNCTION("getColumnType", GetColumnType),
        DECLARE_NAPI_FUNCTION("goTo", GoTo),
        DECLARE_NAPI_FUNCTION("getColumnIndex", GetColumnIndex),
        DECLARE_NAPI_FUNCTION("getColumnName", GetColumnName),
        DECLARE_NAPI_FUNCTION("close", Close),
        DECLARE_NAPI_FUNCTION("goToFirstRow", GoToFirstRow),
        DECLARE_NAPI_FUNCTION("goToLastRow", GoToLastRow),
        DECLARE_NAPI_FUNCTION("goToNextRow", GoToNextRow),
        DECLARE_NAPI_FUNCTION("goToPreviousRow", GoToPreviousRow),
        DECLARE_NAPI_FUNCTION("getInt", GetInt),
        DECLARE_NAPI_FUNCTION("getBlob", GetBlob),
        DECLARE_NAPI_FUNCTION("getString", GetString),
        DECLARE_NAPI_FUNCTION("getDouble", GetDouble),
        DECLARE_NAPI_FUNCTION("isColumnNull", IsColumnNull),
        DECLARE_NAPI_FUNCTION("getRow", GetRow),

        DECLARE_NAPI_GETTER("columnNames", GetAllColumnNames),
        DECLARE_NAPI_GETTER("columnCount", GetColumnCount),
        DECLARE_NAPI_GETTER("isEnded", IsEnded),
        DECLARE_NAPI_GETTER("isStarted", IsBegin),
        DECLARE_NAPI_GETTER("isClosed", IsClosed),
        DECLARE_NAPI_GETTER("rowCount", GetRowCount),
        DECLARE_NAPI_GETTER("rowIndex", GetRowIndex),
        DECLARE_NAPI_GETTER("isAtFirstRow", IsAtFirstRow),
        DECLARE_NAPI_GETTER("isAtLastRow", IsAtLastRow),
    };

    NAPI_CALL(env, napi_define_class(env, "ResultSet", NAPI_AUTO_LENGTH, Initialize, nullptr,
                       sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
    NAPI_CALL(env, napi_create_reference(env, cons, 1, &ctorRef_));
    return cons;
}

napi_value ResultSetProxy::Initialize(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &self, nullptr));
    auto *proxy = new ResultSetProxy();
    auto finalize = [](napi_env env, void *data, void *hint) {
        ResultSetProxy *proxy = reinterpret_cast<ResultSetProxy *>(data);
        delete proxy;
    };
    napi_status status = napi_wrap(env, self, proxy, finalize, nullptr, nullptr);
    if (status != napi_ok) {
        LOG_ERROR("ResultSetProxy napi_wrap failed! code:%{public}d!", status);
        finalize(env, proxy, nullptr);
        return nullptr;
    }
    return self;
}

ResultSetProxy::~ResultSetProxy()
{
    LOG_INFO("ResultSetProxy destructor!");
    if (resultSet_ != nullptr && !resultSet_->IsClosed()) {
        resultSet_->Close();
    }
}

ResultSetProxy::ResultSetProxy(std::shared_ptr<ResultSet> resultSet)
{
    if (resultSet_ == resultSet) {
        return;
    }
    resultSet_ = std::move(resultSet);
}

ResultSetProxy &ResultSetProxy::operator=(std::shared_ptr<ResultSet> resultSet)
{
    if (resultSet_ == resultSet) {
        return *this;
    }
    resultSet_ = std::move(resultSet);
    return *this;
}

ResultSetProxy *ResultSetProxy::GetInnerResultSet(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &self, nullptr);

    ResultSetProxy *proxy = nullptr;
    napi_unwrap(env, self, reinterpret_cast<void **>(&proxy));
    RDB_NAPI_ASSERT(env, proxy && proxy->resultSet_, std::make_shared<InnerError>(E_RESULT_GOTO_ERROR));
    return proxy;
}

ResultSetProxy *ResultSetProxy::ParseInt32FieldByName(
    napi_env env, napi_callback_info info, int32_t &field, const std::string name)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    napi_value self = nullptr;
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &self, nullptr);
    RDB_NAPI_ASSERT(env, argc == 1, std::make_shared<ParamNumError>("1"));

    napi_status status = napi_get_value_int32(env, args[0], &field);
    RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<ParamError>(name, "a number."));

    ResultSetProxy *proxy = nullptr;
    napi_unwrap(env, self, reinterpret_cast<void **>(&proxy));
    RDB_NAPI_ASSERT(env, proxy && proxy->resultSet_, std::make_shared<ParamError>("resultSet", "null"));
    return proxy;
}

ResultSetProxy *ResultSetProxy::ParseFieldByName(
    napi_env env, napi_callback_info info, std::string &field, const std::string name)
{
    napi_value self = nullptr;
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &self, nullptr);
    RDB_NAPI_ASSERT(env, argc == 1, std::make_shared<ParamNumError>("1"));

    field = JSUtils::Convert2String(env, args[0]);
    RDB_NAPI_ASSERT(env, !field.empty(), std::make_shared<ParamError>(name, "a non empty string."));

    ResultSetProxy *proxy = nullptr;
    napi_unwrap(env, self, reinterpret_cast<void **>(&proxy));
    RDB_NAPI_ASSERT(env, proxy && proxy->resultSet_, std::make_shared<ParamError>("resultSet", "null"));
    return proxy;
}

napi_value ValuesRowInstance2Value(napi_env env, NativeRdb::RowInstance &rowInstance)
{
    napi_value ret;
    NAPI_CALL(env, napi_create_object(env, &ret));
    std::map<std::string, NativeRdb::ValueObject> values;
    rowInstance.Get(values);
    for (auto const &it : values) {
        auto valueObject = it.second;
        napi_value value = nullptr;
        switch (valueObject.GetType()) {
            case NativeRdb::ValueObjectType::TYPE_NULL: {
                value = JSUtils::Convert2Value(env, static_cast<std::monostate>(valueObject));
                break;
            }
            case NativeRdb::ValueObjectType::TYPE_INT: {
                value = JSUtils::Convert2JSValue(env, static_cast<int64_t>(valueObject));
                break;
            }
            case NativeRdb::ValueObjectType::TYPE_DOUBLE: {
                value = JSUtils::Convert2JSValue(env, static_cast<double>(valueObject));
                break;
            }
            case NativeRdb::ValueObjectType::TYPE_BLOB: {
                value = JSUtils::Convert2JSValue(env, static_cast<std::vector<uint8_t>>(valueObject));
                break;
            }
            case NativeRdb::ValueObjectType::TYPE_STRING: {
                value = JSUtils::Convert2JSValue(env, static_cast<std::string>(valueObject));
                break;
            }
            default: {
                RDB_NAPI_ASSERT(env, false, std::make_shared<InnerError>(E_INNER_ERROR));
                break;
            }
        }
        NAPI_CALL(env, napi_set_named_property(env, ret, it.first.c_str(), value));
    }
    return ret;
}

napi_value ResultSetProxy::GetAllColumnNames(napi_env env, napi_callback_info info)
{
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    std::vector<std::string> colNames;
    int errCode = resultSetProxy->resultSet_->GetAllColumnNames(colNames);
    if (errCode != E_OK) {
        LOG_ERROR("GetAllColumnNames failed code:%{public}d", errCode);
    }

    return JSUtils::Convert2JSValue(env, colNames);
}

napi_value ResultSetProxy::GetColumnCount(napi_env env, napi_callback_info info)
{
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    int32_t count = 0;
    int errCode = resultSetProxy->resultSet_->GetColumnCount(count);
    if (errCode != E_OK) {
        LOG_ERROR("GetColumnCount failed code:%{public}d", errCode);
    }

    return JSUtils::Convert2JSValue(env, count);
}

napi_value ResultSetProxy::GetColumnType(napi_env env, napi_callback_info info)
{
    int32_t columnIndex;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    ColumnType columnType;
    int errCode = resultSetProxy->resultSet_->GetColumnType(columnIndex, columnType);
    if (errCode != E_OK) {
        LOG_ERROR("GetColumnType failed code:%{public}d", errCode);
    }

    return JSUtils::Convert2JSValue(env, int32_t(columnType));
}

napi_value ResultSetProxy::GetRowCount(napi_env env, napi_callback_info info)
{
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    int32_t result;
    int errCode = resultSetProxy->resultSet_->GetRowCount(result);
    if (errCode != E_OK) {
        LOG_ERROR("GetRowCount failed code:%{public}d", errCode);
    }

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetRowIndex(napi_env env, napi_callback_info info)
{
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    int32_t result;
    int errCode = resultSetProxy->resultSet_->GetRowIndex(result);
    if (errCode != E_OK) {
        LOG_ERROR("GetRowIndex failed code:%{public}d", errCode);
    }

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::IsEnded(napi_env env, napi_callback_info info)
{
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    bool result = false;
    int errCode = resultSetProxy->resultSet_->IsEnded(result);
    if (errCode != E_OK) {
        LOG_ERROR("IsEnded failed code:%{public}d", errCode);
    }

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::IsBegin(napi_env env, napi_callback_info info)
{
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    bool result = false;
    int errCode = resultSetProxy->resultSet_->IsStarted(result);
    if (errCode != E_OK) {
        LOG_ERROR("IsBegin failed code:%{public}d", errCode);
    }

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::IsAtFirstRow(napi_env env, napi_callback_info info)
{
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    bool result = false;
    int errCode = resultSetProxy->resultSet_->IsAtFirstRow(result);
    if (errCode != E_OK) {
        LOG_ERROR("IsAtFirstRow failed code:%{public}d", errCode);
    }

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::IsAtLastRow(napi_env env, napi_callback_info info)
{
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    bool result = false;
    int errCode = resultSetProxy->resultSet_->IsAtLastRow(result);
    if (errCode != E_OK) {
        LOG_ERROR("IsAtLastRow failed code:%{public}d", errCode);
    }

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::Close(napi_env env, napi_callback_info info)
{
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    int errCode = resultSetProxy->resultSet_->Close();
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}

napi_value ResultSetProxy::GoToRow(napi_env env, napi_callback_info info)
{
    int32_t position;
    auto resultSetProxy = ParseInt32FieldByName(env, info, position, "position");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    int errCode = resultSetProxy->resultSet_->GoToRow(position);
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GoTo(napi_env env, napi_callback_info info)
{
    int32_t offset;
    auto resultSetProxy = ParseInt32FieldByName(env, info, offset, "offset");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    int errCode = resultSetProxy->resultSet_->GoTo(offset);
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GoToFirstRow(napi_env env, napi_callback_info info)
{
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    int errCode = resultSetProxy->resultSet_->GoToFirstRow();
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GoToLastRow(napi_env env, napi_callback_info info)
{
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    int errCode = resultSetProxy->resultSet_->GoToLastRow();
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GoToNextRow(napi_env env, napi_callback_info info)
{
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    int errCode = resultSetProxy->resultSet_->GoToNextRow();
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GoToPreviousRow(napi_env env, napi_callback_info info)
{
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    int errCode = resultSetProxy->resultSet_->GoToPreviousRow();
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GetInt(napi_env env, napi_callback_info info)
{
    int32_t columnIndex;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    int32_t result;
    int errCode = resultSetProxy->resultSet_->GetInt(columnIndex, result);
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetLong(napi_env env, napi_callback_info info)
{
    int32_t columnIndex;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    int64_t result;
    int errCode = resultSetProxy->resultSet_->GetLong(columnIndex, result);
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetBlob(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    std::vector<uint8_t> result;
    int errCode = resultSetProxy->resultSet_->GetBlob(columnIndex, result);
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetString(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    std::string result;
    int errCode = resultSetProxy->resultSet_->GetString(columnIndex, result);
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetDouble(napi_env env, napi_callback_info info)
{
    int32_t columnIndex;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    double result = 0.0;
    int errCode = resultSetProxy->resultSet_->GetDouble(columnIndex, result);
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetColumnIndex(napi_env env, napi_callback_info info)
{
    std::string input;
    auto resultSetProxy = ParseFieldByName(env, info, input, "columnName");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    int32_t result = -1;
    int errCode = resultSetProxy->resultSet_->GetColumnIndex(input, result);
    if (errCode != E_OK) {
        LOG_ERROR("IsAtLastRow failed code:%{public}d", errCode);
    }

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetColumnName(napi_env env, napi_callback_info info)
{
    int32_t columnIndex;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    std::string result;
    int errCode = resultSetProxy->resultSet_->GetColumnName(columnIndex, result);
    if (errCode != E_OK) {
        LOG_ERROR("IsAtLastRow failed code:%{public}d", errCode);
    }

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::IsColumnNull(napi_env env, napi_callback_info info)
{
    int32_t columnIndex;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    bool result = false;
    int errCode = resultSetProxy->resultSet_->IsColumnNull(columnIndex, result);
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(E_RESULT_GET_ERROR));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetRow(napi_env env, napi_callback_info info)
{
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);

    std::vector<std::string> columnNames;
    ValuesBucket valuesBucket;
    int errCode = resultSetProxy->resultSet_->GetRow(columnNames, valuesBucket);
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    return ValuesBucket2JSValue(env, valuesBucket);
}

napi_value ResultSetProxy::IsClosed(napi_env env, napi_callback_info info)
{
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->resultSet_);
    bool result = resultSetProxy->resultSet_->IsClosed();

    return JSUtils::Convert2JSValue(env, result);
}
} // namespace RelationalStoreJsKit
} // namespace OHOS
