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
#define LOG_TAG "ResultSetProxy"
#include "napi_result_set.h"

#include <functional>

#include "js_utils.h"
#include "logger.h"
#include "napi_rdb_error.h"
#include "napi_rdb_trace.h"

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
#include "rdb_result_set_bridge.h"
#include "string_ex.h"
#endif

using namespace OHOS::Rdb;
using namespace OHOS::NativeRdb;
using namespace OHOS::AppDataMgrJsKit;

namespace OHOS {
namespace RelationalStoreJsKit {
using Asset = AssetValue;
using Assets = std::vector<Asset>;
using FloatVector = std::vector<float>;
static const int E_OK = 0;

napi_value ResultSetProxy::NewInstance(napi_env env, std::shared_ptr<NativeRdb::ResultSet> resultSet)
{
    napi_value cons = JSUtils::GetClass(env, "ohos.data.relationalStore", "ResultSet");
    if (cons == nullptr) {
        LOG_ERROR("Constructor of ResultSet is nullptr!");
        return nullptr;
    }
    napi_value instance = nullptr;
    auto status = napi_new_instance(env, cons, 0, nullptr, &instance);
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
    proxy->SetInstance(std::move(resultSet));
    return instance;
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
std::shared_ptr<DataShare::ResultSetBridge> ResultSetProxy::Create()
{
    if (GetInstance() == nullptr) {
        LOG_ERROR("resultSet is null");
        return nullptr;
    }
    return std::make_shared<RdbDataShareAdapter::RdbResultSetBridge>(GetInstance());
}
#endif
napi_value ResultSetProxy::Initialize(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &self, nullptr));
    auto *proxy = new (std::nothrow) ResultSetProxy();
    if (proxy == nullptr) {
        LOG_ERROR("ResultSetProxy::Initialize new failed, proxy is nullptr");
        return nullptr;
    }
    auto finalize = [](napi_env env, void *data, void *hint) {
        if (data != hint) {
            LOG_ERROR("RdbStoreProxy memory corrupted! data:0x%016" PRIXPTR "hint:0x%016" PRIXPTR,
                uintptr_t(data), uintptr_t(hint));
            return;
        }
        ResultSetProxy *proxy = reinterpret_cast<ResultSetProxy *>(data);
        delete proxy;
    };
    napi_status status = napi_wrap(env, self, proxy, finalize, proxy, nullptr);
    if (status != napi_ok) {
        LOG_ERROR("ResultSetProxy napi_wrap failed! code:%{public}d!", status);
        finalize(env, proxy, proxy);
        return nullptr;
    }
    return self;
}

ResultSetProxy::~ResultSetProxy()
{
    LOG_DEBUG("ResultSetProxy destructor!");
}

ResultSetProxy::ResultSetProxy(std::shared_ptr<ResultSet> resultSet)
{
    if (GetInstance() == resultSet) {
        return;
    }
    SetInstance(std::move(resultSet));
}

ResultSetProxy &ResultSetProxy::operator=(std::shared_ptr<ResultSet> resultSet)
{
    if (GetInstance() == resultSet) {
        return *this;
    }
    SetInstance(std::move(resultSet));
    return *this;
}

ResultSetProxy *ResultSetProxy::GetInnerResultSet(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &self, nullptr);

    ResultSetProxy *proxy = nullptr;
    napi_unwrap(env, self, reinterpret_cast<void **>(&proxy));
    RDB_NAPI_ASSERT(env, proxy && proxy->GetInstance(), std::make_shared<InnerError>("napi_unwrap failed."));
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
    RDB_NAPI_ASSERT(env, proxy && proxy->GetInstance(), std::make_shared<ParamError>("resultSet", "not null"));
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
    RDB_NAPI_ASSERT(env, proxy && proxy->GetInstance(), std::make_shared<ParamError>("resultSet", "not null"));
    return proxy;
}

napi_value ResultSetProxy::GetAllColumnNames(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    std::vector<std::string> colNames;
    int errCode = resultSetProxy->GetInstance()->GetAllColumnNames(colNames);
    if (errCode != E_OK) {
        LOG_ERROR("GetAllColumnNames failed code:%{public}d", errCode);
    }

    return JSUtils::Convert2JSValue(env, colNames);
}

napi_value ResultSetProxy::GetColumnCount(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    int32_t count = 0;
    int errCode = resultSetProxy->GetInstance()->GetColumnCount(count);
    if (errCode != E_OK) {
        LOG_ERROR("GetColumnCount failed code:%{public}d", errCode);
    }

    return JSUtils::Convert2JSValue(env, count);
}

napi_value ResultSetProxy::GetColumnType(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    ColumnType columnType;
    int errCode = resultSetProxy->GetInstance()->GetColumnType(columnIndex, columnType);
    if (errCode != E_OK) {
        LOG_ERROR("GetColumnType failed code:%{public}d", errCode);
    }

    return JSUtils::Convert2JSValue(env, int32_t(columnType));
}

napi_value ResultSetProxy::GetRowCount(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    int32_t result;
    int errCode = resultSetProxy->GetInstance()->GetRowCount(result);
    if (errCode != E_OK) {
        LOG_ERROR("GetRowCount failed code:%{public}d", errCode);
    }

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetRowIndex(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    int32_t result;
    int errCode = resultSetProxy->GetInstance()->GetRowIndex(result);
    if (errCode != E_OK) {
        LOG_ERROR("GetRowIndex failed code:%{public}d", errCode);
    }

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::IsEnded(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    bool result = false;
    int errCode = resultSetProxy->GetInstance()->IsEnded(result);
    if (errCode != E_OK) {
        LOG_ERROR("IsEnded failed code:%{public}d", errCode);
        result = true;
    }

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::IsBegin(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    bool result = false;
    int errCode = resultSetProxy->GetInstance()->IsStarted(result);
    if (errCode != E_OK) {
        LOG_ERROR("IsBegin failed code:%{public}d", errCode);
    }

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::IsAtFirstRow(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    bool result = false;
    int errCode = resultSetProxy->GetInstance()->IsAtFirstRow(result);
    if (errCode != E_OK) {
        LOG_ERROR("IsAtFirstRow failed code:%{public}d", errCode);
    }

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::IsAtLastRow(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    bool result = false;
    int errCode = resultSetProxy->GetInstance()->IsAtLastRow(result);
    if (errCode != E_OK) {
        LOG_ERROR("IsAtLastRow failed code:%{public}d", errCode);
    }

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::Close(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    int errCode = resultSetProxy->GetInstance()->Close();
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}

napi_value ResultSetProxy::GoToRow(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t position;
    auto resultSetProxy = ParseInt32FieldByName(env, info, position, "position");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    int errCode = resultSetProxy->GetInstance()->GoToRow(position);
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GoTo(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t offset;
    auto resultSetProxy = ParseInt32FieldByName(env, info, offset, "offset");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    int errCode = resultSetProxy->GetInstance()->GoTo(offset);
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GoToFirstRow(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    int errCode = resultSetProxy->GetInstance()->GoToFirstRow();
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GoToLastRow(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    int errCode = resultSetProxy->GetInstance()->GoToLastRow();
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GoToNextRow(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    int errCode = resultSetProxy->GetInstance()->GoToNextRow();
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GoToPreviousRow(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    int errCode = resultSetProxy->GetInstance()->GoToPreviousRow();
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GetInt(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    int32_t result;
    int errCode = resultSetProxy->GetInstance()->GetInt(columnIndex, result);
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetLong(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    int64_t result;
    int errCode = resultSetProxy->GetInstance()->GetLong(columnIndex, result);
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetBlob(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    std::vector<uint8_t> result;
    int errCode = resultSetProxy->GetInstance()->GetBlob(columnIndex, result);
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetAsset(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    Asset result;
    int errCode = resultSetProxy->GetInstance()->GetAsset(columnIndex, result);
    if (errCode == E_NULL_OBJECT) {
        LOG_DEBUG("getAsset col %{public}d is null ", columnIndex);
        return JSUtils::Convert2JSValue(env, std::monostate());
    }
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetAssets(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    Assets result;
    int errCode = resultSetProxy->GetInstance()->GetAssets(columnIndex, result);
    if (errCode == E_NULL_OBJECT) {
        LOG_DEBUG("getAssets col %{public}d is null ", columnIndex);
        return JSUtils::Convert2JSValue(env, std::monostate());
    }
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetFloat32Array(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    FloatVector result = {};
    int errCode = resultSetProxy->GetInstance()->GetFloat32Array(columnIndex, result);
    if (errCode == E_NULL_OBJECT) {
        LOG_DEBUG("GetFloat32Array col %{public}d is null ", columnIndex);
        return JSUtils::Convert2JSValue(env, std::monostate());
    }
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetString(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    std::string result;
    int errCode = resultSetProxy->GetInstance()->GetString(columnIndex, result);
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetDouble(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    double result = 0.0;
    int errCode = resultSetProxy->GetInstance()->GetDouble(columnIndex, result);
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetColumnIndex(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::string input;
    auto resultSetProxy = ParseFieldByName(env, info, input, "columnName");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    int32_t result = -1;
    resultSetProxy->GetInstance()->GetColumnIndex(input, result);
    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetColumnName(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    std::string result;
    int errCode = resultSetProxy->GetInstance()->GetColumnName(columnIndex, result);
    if (errCode != E_OK) {
        LOG_ERROR("IsAtLastRow failed code:%{public}d", errCode);
    }

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::IsColumnNull(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    bool result = false;
    int errCode = resultSetProxy->GetInstance()->IsColumnNull(columnIndex, result);
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetRow(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    RowEntity rowEntity;
    int errCode = resultSetProxy->GetInstance()->GetRow(rowEntity);
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    return JSUtils::Convert2JSValue(env, rowEntity);
}

napi_value ResultSetProxy::GetValue(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());

    ValueObject object;
    int errCode = resultSetProxy->GetInstance()->Get(columnIndex, object);
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    return JSUtils::Convert2JSValue(env, object);
}

napi_value ResultSetProxy::IsClosed(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info);
    CHECK_RETURN_NULL(resultSetProxy && resultSetProxy->GetInstance());
    bool result = resultSetProxy->GetInstance()->IsClosed();

    return JSUtils::Convert2JSValue(env, result);
}

void ResultSetProxy::Init(napi_env env, napi_value exports)
{
    auto lambda = []() -> std::vector<napi_property_descriptor> {
        std::vector<napi_property_descriptor> properties = {
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
            DECLARE_NAPI_FUNCTION("getAsset", GetAsset),
            DECLARE_NAPI_FUNCTION("getAssets", GetAssets),
            DECLARE_NAPI_FUNCTION("getFloat32Array", GetFloat32Array),
            DECLARE_NAPI_FUNCTION("getString", GetString),
            DECLARE_NAPI_FUNCTION("getDouble", GetDouble),
            DECLARE_NAPI_FUNCTION("isColumnNull", IsColumnNull),
            DECLARE_NAPI_FUNCTION("getValue", GetValue),
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
        return properties;
    };

    auto jsCtor = JSUtils::DefineClass(env, "ohos.data.relationalStore", "ResultSet", lambda, Initialize);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, exports, "ResultSet", jsCtor));

    LOG_DEBUG("ResultSetProxy::Init end");
}
} // namespace RelationalStoreJsKit
} // namespace OHOS
