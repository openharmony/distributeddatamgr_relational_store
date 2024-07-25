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
#include "rdb_errno.h"

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
#include "abs_shared_result_set.h"
#include "rdb_result_set_bridge.h"
#include "shared_block.h"
#include "string_ex.h"
#endif

using namespace OHOS::Rdb;
using namespace OHOS::NativeRdb;
using namespace OHOS::AppDataMgrJsKit;

namespace OHOS {
namespace RdbJsKit {
static napi_ref __thread ctorRef_ = nullptr;
static napi_ref __thread ctorRefV9_ = nullptr;
static const int E_OK = 0;

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
napi_value ResultSetProxy::NewInstance(napi_env env, std::shared_ptr<AbsSharedResultSet> resultSet, int version)
{
    auto instance = NewInstance(env, std::static_pointer_cast<NativeRdb::ResultSet>(resultSet), version);
    ResultSetProxy *proxy = nullptr;
    auto status = napi_unwrap(env, instance, reinterpret_cast<void **>(&proxy));
    if (proxy == nullptr) {
        LOG_ERROR("NewInstance native instance is nullptr! code:%{public}d!", status);
        return instance;
    }

    if (resultSet != nullptr && resultSet->GetBlock() != nullptr) {
        proxy->sharedBlockName_ = resultSet->GetBlock()->Name();
        proxy->sharedBlockAshmemFd_ = resultSet->GetBlock()->GetFd();
    }
    proxy->sharedResultSet_ = resultSet;
    return instance;
}
#endif

napi_value ResultSetProxy::NewInstance(napi_env env, std::shared_ptr<NativeRdb::ResultSet> resultSet, int version)
{
    napi_value cons = GetConstructor(env, version);
    if (cons == nullptr) {
        LOG_ERROR("NewInstance GetConstructor is nullptr!");
        return nullptr;
    }
    napi_value instance = nullptr;
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
std::shared_ptr<NativeRdb::AbsSharedResultSet> ResultSetProxy::GetNativeObject(
    napi_env const env, napi_value const arg)
{
    if (arg == nullptr) {
        LOG_ERROR("ResultSetProxy GetNativeObject arg is null.");
        return nullptr;
    }
    ResultSetProxy *proxy = nullptr;
    napi_unwrap(env, arg, reinterpret_cast<void **>(&proxy));
    if (proxy == nullptr || proxy->sharedResultSet_ == nullptr) {
        LOG_ERROR("ResultSetProxy GetNativeObject proxy or sharedResultSet_ is null.");
        return nullptr;
    }
    return proxy->sharedResultSet_;
}

std::shared_ptr<DataShare::ResultSetBridge> ResultSetProxy::Create()
{
    auto instance = GetInstance();
    if (instance == nullptr) {
        LOG_ERROR("resultSet_ is null.");
        return nullptr;
    }
    SetInstance(nullptr);
    return std::make_shared<RdbDataShareAdapter::RdbResultSetBridge>(instance);
}
#endif

napi_value ResultSetProxy::GetConstructor(napi_env env, int version)
{
    napi_value cons = nullptr;
    if (version > APIVERSION_8 && ctorRefV9_ != nullptr) {
        NAPI_CALL(env, napi_get_reference_value(env, ctorRefV9_, &cons));
        return cons;
    }
    if (version == APIVERSION_8 && ctorRef_ != nullptr) {
        NAPI_CALL(env, napi_get_reference_value(env, ctorRef_, &cons));
        return cons;
    }

    napi_property_descriptor clzDes[] = {
        DECLARE_NAPI_FUNCTION("goToRow", GoToRow),
        DECLARE_NAPI_FUNCTION("getLong", GetLong),
        DECLARE_NAPI_FUNCTION("getColumnType", GetColumnType),
        DECLARE_NAPI_FUNCTION("goTo", GoTo),
        DECLARE_NAPI_FUNCTION("getColumnIndex", GetColumnIndex),
        DECLARE_NAPI_FUNCTION("getInt", GetInt),
        DECLARE_NAPI_FUNCTION("getColumnName", GetColumnName),
        DECLARE_NAPI_FUNCTION("close", Close),
        DECLARE_NAPI_FUNCTION("goToFirstRow", GoToFirstRow),
        DECLARE_NAPI_FUNCTION("goToLastRow", GoToLastRow),
        DECLARE_NAPI_FUNCTION("goToNextRow", GoToNextRow),
        DECLARE_NAPI_FUNCTION("goToPreviousRow", GoToPreviousRow),
        DECLARE_NAPI_FUNCTION("getBlob", GetBlob),
        DECLARE_NAPI_FUNCTION("getString", GetString),
        DECLARE_NAPI_FUNCTION("getDouble", GetDouble),
        DECLARE_NAPI_FUNCTION("isColumnNull", IsColumnNull),

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

    if (version > APIVERSION_8) {
        NAPI_CALL(env, napi_define_class(env, "ResultSetV9", NAPI_AUTO_LENGTH, InitializeV9, nullptr,
                           sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
        NAPI_CALL(env, napi_create_reference(env, cons, 1, &ctorRefV9_));
        return cons;
    }

    NAPI_CALL(env, napi_define_class(env, "ResultSet", NAPI_AUTO_LENGTH, Initialize, nullptr,
                       sizeof(clzDes) / sizeof(napi_property_descriptor), clzDes, &cons));
    NAPI_CALL(env, napi_create_reference(env, cons, 1, &ctorRef_));
    return cons;
}

napi_value ResultSetProxy::InnerInitialize(napi_env env, napi_callback_info info, int version)
{
    napi_value self = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &self, nullptr));
    auto *proxy = new (std::nothrow) ResultSetProxy();
    if (proxy == nullptr) {
        LOG_ERROR("ResultSetProxy::InnerInitialize new failed, proxy is nullptr.");
        return nullptr;
    }
    proxy->apiversion = version;
    auto finalize = [](napi_env env, void *data, void *hint) {
        ResultSetProxy *proxy = reinterpret_cast<ResultSetProxy *>(data);
        delete proxy;
    };
    napi_status status = napi_wrap(env, self, proxy, finalize, nullptr, nullptr);
    if (status != napi_ok) {
        LOG_ERROR("ResultSetProxy napi_wrap failed! code:%{public}d!, version:%{public}d.", status, version);
        finalize(env, proxy, nullptr);
        return nullptr;
    }
    return self;
}

napi_value ResultSetProxy::Initialize(napi_env env, napi_callback_info info)
{
    return InnerInitialize(env, info, APIVERSION_8);
}

napi_value ResultSetProxy::InitializeV9(napi_env env, napi_callback_info info)
{
    return InnerInitialize(env, info, APIVERSION_V9);
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

ResultSetProxy *ResultSetProxy::GetInnerResultSet(napi_env env, napi_callback_info info, int &version)
{
    ResultSetProxy *resultSetProxy = nullptr;
    napi_value self = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &self, nullptr);
    napi_unwrap(env, self, reinterpret_cast<void **>(&resultSetProxy));
    RDB_NAPI_ASSERT_FROMV9(env, resultSetProxy && resultSetProxy->GetInstance(), std::make_shared<ResultGotoError>(),
        resultSetProxy->apiversion);

    version = resultSetProxy->apiversion;
    return resultSetProxy;
}

ResultSetProxy *ResultSetProxy::ParseInt32FieldByName(
    napi_env env, napi_callback_info info, int32_t &field, const std::string& name)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    napi_value self = nullptr;
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &self, nullptr);
    ResultSetProxy *resultSetProxy = nullptr;
    napi_unwrap(env, self, reinterpret_cast<void **>(&resultSetProxy));
    RDB_NAPI_ASSERT_FROMV9(env, resultSetProxy && resultSetProxy->GetInstance(),
        std::make_shared<ParamTypeError>("resultSet", "not null"), resultSetProxy->apiversion);
    RDB_NAPI_ASSERT_FROMV9(
        env, argc == 1, std::make_shared<ParamNumError>("1"), resultSetProxy->apiversion);

    napi_status status = napi_get_value_int32(env, args[0], &field);
    RDB_NAPI_ASSERT_FROMV9(
        env, status == napi_ok, std::make_shared<ParamTypeError>(name, "a number."), resultSetProxy->apiversion);
    return resultSetProxy;
}

ResultSetProxy *ResultSetProxy::ParseFieldByName(napi_env env, napi_callback_info info, std::string &field)
{
    napi_value self = nullptr;
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &self, nullptr);
    ResultSetProxy *resultSetProxy = nullptr;
    napi_unwrap(env, self, reinterpret_cast<void **>(&resultSetProxy));
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");
    RDB_NAPI_ASSERT_FROMV9(
        env, argc == 1, std::make_shared<ParamNumError>("1"), resultSetProxy->apiversion);

    field = JSUtils::Convert2String(env, args[0]);
    return resultSetProxy;
}

napi_value ResultSetProxy::GetAllColumnNames(napi_env env, napi_callback_info info)
{
    std::vector<std::string> colNames;
    int version = 0;
    auto resultSetProxy = GetInnerResultSet(env, info, version);
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    int errCode = resultSetProxy->GetInstance()->GetAllColumnNames(colNames);
    if (errCode != E_OK) {
        LOG_ERROR("GetAllColumnNames failed code:%{public}d, version:%{public}d.", errCode, version);
    }
    return JSUtils::Convert2JSValue(env, colNames);
}

napi_value ResultSetProxy::GoToRow(napi_env env, napi_callback_info info)
{
    int32_t position;
    auto resultSetProxy = ParseInt32FieldByName(env, info, position, "position");
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    int errCode = resultSetProxy->GetInstance()->GoToRow(position);
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GetColumnCount(napi_env env, napi_callback_info info)
{
    int32_t count = 0;
    int version = 0;
    auto resultSetProxy = GetInnerResultSet(env, info, version);
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    int errCode = resultSetProxy->GetInstance()->GetColumnCount(count);
    if (errCode != E_OK) {
        LOG_ERROR("GetColumnCount failed code:%{public}d, version:%{public}d.", errCode, version);
    }
    return JSUtils::Convert2JSValue(env, count);
}

napi_value ResultSetProxy::GetLong(napi_env env, napi_callback_info info)
{
    int32_t columnIndex;
    int64_t result;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    int errCode = resultSetProxy->GetInstance()->GetLong(columnIndex, result);
    int version = resultSetProxy->apiversion;
    RDB_NAPI_ASSERT_FROMV9(env, errCode == E_OK, std::make_shared<ResultGetError>(), version);
    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetColumnType(napi_env env, napi_callback_info info)
{
    int32_t columnIndex;
    ColumnType columnType;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    int errCode = resultSetProxy->GetInstance()->GetColumnType(columnIndex, columnType);
    if (errCode != E_OK) {
        LOG_ERROR("GetColumnType failed code:%{public}d, version:%{public}d.", errCode, resultSetProxy->apiversion);
    }
    return JSUtils::Convert2JSValue(env, int32_t(columnType));
}

napi_value ResultSetProxy::GoTo(napi_env env, napi_callback_info info)
{
    int32_t offset;
    auto resultSetProxy = ParseInt32FieldByName(env, info, offset, "offset");
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    int errCode = resultSetProxy->GetInstance()->GoTo(offset);
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GetColumnIndex(napi_env env, napi_callback_info info)
{
    std::string input;
    int32_t result = -1;
    auto resultSetProxy = ParseFieldByName(env, info, input);
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    int errCode = resultSetProxy->GetInstance()->GetColumnIndex(input, result);
    if (errCode != E_OK) {
        LOG_ERROR("GetColumnIndex failed code:%{public}d, version:%{public}d.", errCode, resultSetProxy->apiversion);
    }
    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetInt(napi_env env, napi_callback_info info)
{
    int32_t columnIndex;
    int32_t result;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    int errCode = resultSetProxy->GetInstance()->GetInt(columnIndex, result);
    int version = resultSetProxy->apiversion;
    RDB_NAPI_ASSERT_FROMV9(env, errCode == E_OK, std::make_shared<ResultGetError>(), version);
    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetColumnName(napi_env env, napi_callback_info info)
{
    int32_t columnIndex;
    std::string result;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    int errCode = resultSetProxy->GetInstance()->GetColumnName(columnIndex, result);
    if (errCode != E_OK) {
        LOG_ERROR("GetColumnName failed code:%{public}d, version:%{public}d.", errCode, resultSetProxy->apiversion);
    }
    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::Close(napi_env env, napi_callback_info info)
{
    int version = 0;
    auto resultSetProxy = GetInnerResultSet(env, info, version);
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    int errCode = resultSetProxy->GetInstance()->Close();
    RDB_NAPI_ASSERT_FROMV9(env, errCode == E_OK, std::make_shared<ResultGotoError>(), version);
    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}

napi_value ResultSetProxy::GetRowCount(napi_env env, napi_callback_info info)
{
    int version = 0;
    ResultSetProxy *resultSetProxy = GetInnerResultSet(env, info, version);
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    int32_t result;
    int errCode = resultSetProxy->GetInstance()->GetRowCount(result);
    if (errCode != E_OK) {
        LOG_ERROR("GetRowCount failed code:%{public}d, version:%{public}d.", errCode, version);
    }
    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetRowIndex(napi_env env, napi_callback_info info)
{
    int version = 0;
    auto resultSetProxy = GetInnerResultSet(env, info, version);
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    int32_t result;
    int errCode = resultSetProxy->GetInstance()->GetRowIndex(result);
    if (errCode != E_OK) {
        LOG_ERROR("GetRowIndex failed code:%{public}d, version:%{public}d.", errCode, version);
    }
    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::IsEnded(napi_env env, napi_callback_info info)
{
    int version = 0;
    auto resultSetProxy = GetInnerResultSet(env, info, version);
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    bool result = false;
    int errCode = resultSetProxy->GetInstance()->IsEnded(result);
    if (errCode != E_OK) {
        LOG_ERROR("IsEnded failed code:%{public}d, version:%{public}d.", errCode, version);
        result = true;
    }
    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::IsBegin(napi_env env, napi_callback_info info)
{
    int version = 0;
    auto resultSetProxy = GetInnerResultSet(env, info, version);
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    bool result = false;
    int errCode = resultSetProxy->GetInstance()->IsStarted(result);
    if (errCode != E_OK) {
        LOG_ERROR("IsBegin failed code:%{public}d, version:%{public}d.", errCode, version);
    }
    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GoToFirstRow(napi_env env, napi_callback_info info)
{
    int version = 0;
    auto resultSetProxy = GetInnerResultSet(env, info, version);
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    int errCode = resultSetProxy->GetInstance()->GoToFirstRow();
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GoToLastRow(napi_env env, napi_callback_info info)
{
    int version = 0;
    auto resultSetProxy = GetInnerResultSet(env, info, version);
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    int errCode = resultSetProxy->GetInstance()->GoToLastRow();
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GoToNextRow(napi_env env, napi_callback_info info)
{
    int version = 0;
    auto resultSetProxy = GetInnerResultSet(env, info, version);
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    int errCode = resultSetProxy->GetInstance()->GoToNextRow();
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GoToPreviousRow(napi_env env, napi_callback_info info)
{
    int version = 0;
    auto resultSetProxy = GetInnerResultSet(env, info, version);
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    int errCode = resultSetProxy->GetInstance()->GoToPreviousRow();
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::IsAtFirstRow(napi_env env, napi_callback_info info)
{
    int version = 0;
    auto resultSetProxy = GetInnerResultSet(env, info, version);
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    bool result = false;
    int errCode = resultSetProxy->GetInstance()->IsAtFirstRow(result);
    if (errCode != E_OK) {
        LOG_ERROR("IsAtFirstRow failed code:%{public}d, version:%{public}d.", errCode, version);
    }
    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::IsAtLastRow(napi_env env, napi_callback_info info)
{
    int version = 0;
    auto resultSetProxy = GetInnerResultSet(env, info, version);
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    bool result = false;
    int errCode = resultSetProxy->GetInstance()->IsAtLastRow(result);
    if (errCode != E_OK) {
        LOG_ERROR("IsAtLastRow failed code:%{public}d, version:%{public}d.", errCode, version);
    }
    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetBlob(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    std::vector<uint8_t> result;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    int errCode = resultSetProxy->GetInstance()->GetBlob(columnIndex, result);
    int version = resultSetProxy->apiversion;
    RDB_NAPI_ASSERT_FROMV9(env, errCode == E_OK, std::make_shared<ResultGetError>(), version);
    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetString(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    std::string result;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    int errCode = resultSetProxy->GetInstance()->GetString(columnIndex, result);
    int version = resultSetProxy->apiversion;
    RDB_NAPI_ASSERT_FROMV9(env, errCode == E_OK, std::make_shared<ResultGetError>(), version);
    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetDouble(napi_env env, napi_callback_info info)
{
    int32_t columnIndex;
    double result = 0.0;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    int errCode = resultSetProxy->GetInstance()->GetDouble(columnIndex, result);
    int version = resultSetProxy->apiversion;
    RDB_NAPI_ASSERT_FROMV9(env, errCode == E_OK, std::make_shared<ResultGetError>(), version);
    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::IsColumnNull(napi_env env, napi_callback_info info)
{
    int32_t columnIndex;
    bool result = false;
    auto resultSetProxy = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    int errCode = resultSetProxy->GetInstance()->IsColumnNull(columnIndex, result);
    int version = resultSetProxy->apiversion;
    RDB_NAPI_ASSERT_FROMV9(env, errCode == E_OK, std::make_shared<ResultGetError>(), version);
    napi_value output = nullptr;
    napi_get_boolean(env, result, &output);
    return output;
}

napi_value ResultSetProxy::IsClosed(napi_env env, napi_callback_info info)
{
    int version = 0;
    auto resultSetProxy = GetInnerResultSet(env, info, version);
    RDB_CHECK_RETURN_NULLPTR(resultSetProxy && resultSetProxy->GetInstance(), "Proxy or instance is nullptr");

    int result = resultSetProxy->GetInstance()->IsClosed();
    napi_value output = nullptr;
    napi_get_boolean(env, result, &output);
    return output;
}

napi_value ResultSetProxy::GetSharedBlockName(napi_env env, napi_callback_info info)
{
    napi_value thiz = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr));

    ResultSetProxy *proxy;
    NAPI_CALL(env, napi_unwrap(env, thiz, reinterpret_cast<void **>(&proxy)));
    RDB_CHECK_RETURN_NULLPTR(proxy != nullptr,
        "ResultSetProxy::GetSharedBlockName proxy is nullptr");

    return JSUtils::Convert2JSValue(env, proxy->sharedBlockName_);
}

napi_value ResultSetProxy::GetSharedBlockAshmemFd(napi_env env, napi_callback_info info)
{
    napi_value thiz = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thiz, nullptr));

    ResultSetProxy *proxy;
    NAPI_CALL(env, napi_unwrap(env, thiz, reinterpret_cast<void **>(&proxy)));
    RDB_CHECK_RETURN_NULLPTR(proxy != nullptr,
        "ResultSetProxy::GetSharedBlockAshmemFd proxy is nullptr");

    return JSUtils::Convert2JSValue(env, proxy->sharedBlockAshmemFd_);
}
} // namespace RdbJsKit
} // namespace OHOS

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)

__attribute__((visibility("default"))) napi_value NewCInstance(napi_env env,
    napi_value arg) asm("NAPI_OHOS_Data_RdbJsKit_ResultSetProxy_NewInstance");
napi_value NewCInstance(napi_env env, std::shared_ptr<OHOS::NativeRdb::AbsSharedResultSet> resultSet)
{
    return OHOS::RdbJsKit::ResultSetProxy::NewInstance(env, resultSet);
}

__attribute__((visibility("default"))) std::shared_ptr<OHOS::NativeRdb::AbsSharedResultSet> GetCObject(napi_env env,
    napi_value arg) asm("NAPI_OHOS_Data_RdbJsKit_ResultSetProxy_GetNativeObject");
std::shared_ptr<OHOS::NativeRdb::AbsSharedResultSet> GetCObject(napi_env env, napi_value arg)
{
    return OHOS::RdbJsKit::ResultSetProxy::GetNativeObject(env, arg);
}
#endif