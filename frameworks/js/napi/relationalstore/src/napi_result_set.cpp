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
#include <memory>
#include <string>

#include "js_df_manager.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "js_utils.h"
#include "logger.h"
#include "napi_rdb_error.h"
#include "napi_rdb_js_utils.h"
#include "napi_rdb_sendable_utils.h"
#include "napi_rdb_trace.h"
#include "rdb_errno.h"
#include "result_set.h"
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
static const int INIT_POSITION = -1;

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
    if (status != napi_ok || proxy == nullptr) {
        LOG_ERROR("NewInstance native instance is nullptr! code:%{public}d!", status);
        return nullptr;
    }
    proxy->SetInstance(std::move(resultSet));
    return instance;
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
std::shared_ptr<DataShare::ResultSetBridge> ResultSetProxy::Create()
{
    auto instance = GetInstance();
    if (instance == nullptr) {
        LOG_ERROR("ResultSet is null.");
        return nullptr;
    }
    SetInstance(nullptr);
    return std::make_shared<RdbDataShareAdapter::RdbResultSetBridge>(instance);
}
#endif

napi_value ResultSetProxy::Initialize(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &self, nullptr));
    auto *proxy = new (std::nothrow) ResultSetProxy();
    if (proxy == nullptr) {
        LOG_ERROR("ResultSetProxy::Initialize new failed, proxy is nullptr.");
        return nullptr;
    }
    auto finalize = [](napi_env env, void *data, void *hint) {
        if (data == nullptr) {
            LOG_ERROR("data is nullptr.");
            return;
        }
        auto tid = JSDFManager::GetInstance().GetFreedTid(data);
        if (tid != 0) {
            LOG_ERROR("(T:%{public}d) freed! data:0x%016" PRIXPTR, tid, uintptr_t(data) & LOWER_24_BITS_MASK);
        }
        if (data != hint) {
            LOG_ERROR("RdbStoreProxy memory corrupted! data:0x%016" PRIXPTR "hint:0x%016" PRIXPTR,
                uintptr_t(data) & LOWER_24_BITS_MASK, uintptr_t(hint) & LOWER_24_BITS_MASK);
            return;
        }
        ResultSetProxy *proxy = reinterpret_cast<ResultSetProxy *>(data);
        proxy->SetInstance(nullptr);
        delete proxy;
    };
    napi_status status = napi_wrap(env, self, proxy, finalize, proxy, nullptr);
    if (status != napi_ok) {
        LOG_ERROR("ResultSetProxy napi_wrap failed! code:%{public}d!", status);
        finalize(env, proxy, proxy);
        return nullptr;
    }
    JSDFManager::GetInstance().AddNewInfo(proxy);
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

static ResultSetProxy *GetResultSetProxy(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &self, nullptr);

    ResultSetProxy *proxy = nullptr;
    napi_status status = napi_unwrap(env, self, reinterpret_cast<void **>(&proxy));
    RDB_NAPI_ASSERT(env, status == napi_ok && proxy != nullptr, std::make_shared<InnerError>("napi_unwrap failed."));
    return proxy;
}

static std::shared_ptr<ResultSet> GetInnerResultSet(napi_env env, napi_callback_info info)
{
    ResultSetProxy *proxy = GetResultSetProxy(env, info);
    return proxy == nullptr ? nullptr : proxy->GetInstance();
}

static std::shared_ptr<ResultSet> ParseInt32FieldByName(
    napi_env env, napi_callback_info info, int32_t &field, const std::string &name)
{
    napi_value self = nullptr;
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &self, nullptr);
    RDB_NAPI_ASSERT(env, argc == 1, std::make_shared<ParamNumError>("1"));

    napi_status status = napi_get_value_int32(env, args[0], &field);
    RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<ParamError>(name, "a number."));

    ResultSetProxy *proxy = nullptr;
    status = napi_unwrap(env, self, reinterpret_cast<void **>(&proxy));
    RDB_NAPI_ASSERT(env, status == napi_ok && proxy != nullptr, std::make_shared<InnerError>("napi_unwrap failed."));
    return proxy->GetInstance();
}

static std::shared_ptr<ResultSet> ParseFieldByName(
    napi_env env, napi_callback_info info, std::string &field, const std::string &name)
{
    napi_value self = nullptr;
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &self, nullptr);
    RDB_NAPI_ASSERT(env, argc == 1, std::make_shared<ParamNumError>("1"));

    field = JSUtils::Convert2String(env, args[0]);
    RDB_NAPI_ASSERT(env, !field.empty(), std::make_shared<ParamError>(name, "a non empty string."));

    ResultSetProxy *proxy = nullptr;
    napi_status status = napi_unwrap(env, self, reinterpret_cast<void **>(&proxy));
    RDB_NAPI_ASSERT(env, status == napi_ok && proxy != nullptr, std::make_shared<InnerError>("napi_unwrap failed."));
    return proxy->GetInstance();
}

napi_value ResultSetProxy::GetAllColumnNames(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto resultSet = GetInnerResultSet(env, info);
    std::vector<std::string> colNames;
    if (resultSet != nullptr) {
        resultSet->GetAllColumnNames(colNames);
    }
    return JSUtils::Convert2JSValue(env, colNames);
}

napi_value ResultSetProxy::GetWholeColumnNames(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto resultSet = GetInnerResultSet(env, info);
    int errCode = E_ALREADY_CLOSED;
    std::vector<std::string> colNames;
    if (resultSet != nullptr) {
        std::tie(errCode, colNames) = resultSet->GetWholeColumnNames();
    }
    if (errCode == E_INVALID_ARGS) {
        errCode = E_INVALID_ARGS_NEW;
    }
    RDB_NAPI_ASSERT_INT(env, errCode == E_OK, std::make_shared<InnerErrorExt>(errCode));
    return JSUtils::Convert2JSValue(env, std::move(colNames));
}

napi_value ResultSetProxy::GetColumnCount(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto resultSet = GetInnerResultSet(env, info);
    int32_t count = 0;
    if (resultSet != nullptr) {
        resultSet->GetColumnCount(count);
    }

    return JSUtils::Convert2JSValue(env, count);
}

napi_value ResultSetProxy::GetColumnType(napi_env env, napi_callback_info info)
{
    struct TypeContextBase : public ContextBase {
    public:
        int32_t columnIndex = 0;
        std::string columnName;
        ColumnType columnType = ColumnType::TYPE_NULL;
        std::weak_ptr<ResultSet> resultSet;
    };
    std::shared_ptr<TypeContextBase> context = std::make_shared<TypeContextBase>();
    auto resultSet = GetInnerResultSet(env, info);
    RDB_NAPI_ASSERT(env, resultSet != nullptr, std::make_shared<InnerError>(E_ALREADY_CLOSED));
    context->resultSet = resultSet;
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc > 0, std::make_shared<ParamNumError>("1"));
        napi_valuetype type = napi_undefined;
        napi_typeof(env, argv[0], &type);
        if (type == napi_number) {
            auto errCode = JSUtils::Convert2ValueExt(env, argv[0], context->columnIndex);
            CHECK_RETURN_SET_E(
                OK == errCode && context->columnIndex >= 0, std::make_shared<ParamError>("Invalid columnIndex"));
        } else {
            auto errCode = JSUtils::Convert2Value(env, argv[0], context->columnName);
            CHECK_RETURN_SET_E(OK == errCode && !context->columnName.empty(),
                std::make_shared<ParamError>("columnName", "a non empty string."));
        }
    };
    auto exec = [context]() -> int {
        auto result = context->resultSet.lock();
        if (result == nullptr) {
            return E_ALREADY_CLOSED;
        }
        int errCode = E_OK;
        if (!context->columnName.empty()) {
            errCode = result->GetColumnIndex(context->columnName, context->columnIndex);
        }
        if (errCode == E_OK) {
            errCode = result->GetColumnType(context->columnIndex, context->columnType);
        }
        if (errCode == E_INVALID_ARGS) {
            return E_PARAM_ERROR;
        }
        return errCode;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = JSUtils::Convert2JSValue(env, static_cast<int32_t>(context->columnType));
    };
    context->SetAction(env, info, input, exec, output);
    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value ResultSetProxy::GetRowCount(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto resultSet = GetInnerResultSet(env, info);
    // If resultSet is closed, the default rowCount is -1.
    int32_t rowCount = -1;
    if (resultSet != nullptr) {
        resultSet->GetRowCount(rowCount);
    }

    return JSUtils::Convert2JSValue(env, rowCount);
}

napi_value ResultSetProxy::GetRowIndex(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto resultSet = GetInnerResultSet(env, info);
    // If resultSet is closed, the default rowIndex is -1.
    int32_t rowIndex = -1;
    if (resultSet != nullptr) {
        resultSet->GetRowIndex(rowIndex);
    }

    return JSUtils::Convert2JSValue(env, rowIndex);
}

napi_value ResultSetProxy::IsEnded(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto resultSet = GetInnerResultSet(env, info);
    bool isEnded = true;
    if (resultSet != nullptr) {
        resultSet->IsEnded(isEnded);
    }
    return JSUtils::Convert2JSValue(env, isEnded);
}

napi_value ResultSetProxy::IsBegin(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto resultSet = GetInnerResultSet(env, info);
    bool isStarted = false;
    if (resultSet != nullptr) {
        resultSet->IsStarted(isStarted);
    }
    return JSUtils::Convert2JSValue(env, isStarted);
}

napi_value ResultSetProxy::IsAtFirstRow(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto resultSet = GetInnerResultSet(env, info);
    bool isAtFirstRow = false;
    if (resultSet != nullptr) {
        resultSet->IsAtFirstRow(isAtFirstRow);
    }

    return JSUtils::Convert2JSValue(env, isAtFirstRow);
}

napi_value ResultSetProxy::IsAtLastRow(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto resultSet = GetInnerResultSet(env, info);
    bool isAtLastRow = false;
    if (resultSet != nullptr) {
        resultSet->IsAtLastRow(isAtLastRow);
    }

    return JSUtils::Convert2JSValue(env, isAtLastRow);
}

napi_value ResultSetProxy::Close(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    ResultSetProxy *resultSetProxy = GetResultSetProxy(env, info);
    if (resultSetProxy == nullptr) {
        return nullptr;
    }
    if (resultSetProxy->GetInstance() != nullptr) {
        std::shared_ptr<ResultSet> res = resultSetProxy->GetInstance();
        resultSetProxy->SetInstance(nullptr);
        if (res.use_count() != 1) {
            LOG_WARN("use_count = %{public}ld", res.use_count());
        }
    }
    napi_value result = nullptr;
    napi_get_null(env, &result);
    return result;
}

napi_value ResultSetProxy::GoToRow(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t position;
    auto resultSet = ParseInt32FieldByName(env, info, position, "position");
    int errCode = E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GoToRow(position);
    }
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GoTo(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t offset;
    auto resultSet = ParseInt32FieldByName(env, info, offset, "offset");
    int errCode = E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GoTo(offset);
    }
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GoToFirstRow(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto resultSet = GetInnerResultSet(env, info);
    int errCode = E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GoToFirstRow();
    }
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GoToLastRow(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto resultSet = GetInnerResultSet(env, info);
    int errCode = E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GoToLastRow();
    }
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GoToNextRow(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto resultSet = GetInnerResultSet(env, info);
    int errCode = E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GoToNextRow();
    }
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GoToPreviousRow(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto resultSet = GetInnerResultSet(env, info);
    int errCode = E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GoToPreviousRow();
    }
    return JSUtils::Convert2JSValue(env, (errCode == E_OK));
}

napi_value ResultSetProxy::GetInt(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSet = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    int32_t result;
    int errCode = E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GetInt(columnIndex, result);
    }
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetLong(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSet = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    int64_t result;
    int errCode = E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GetLong(columnIndex, result);
    }
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetBlob(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSet = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    std::vector<uint8_t> result;
    int errCode = E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GetBlob(columnIndex, result);
    }
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetAsset(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSet = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    Asset result;
    int errCode = E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GetAsset(columnIndex, result);
    }
    if (errCode == E_NULL_OBJECT) {
        LOG_DEBUG("GetAsset col %{public}d is null.", columnIndex);
        return JSUtils::Convert2JSValue(env, std::monostate());
    }
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetAssets(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSet = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    Assets result;
    int errCode = E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GetAssets(columnIndex, result);
    }
    if (errCode == E_NULL_OBJECT) {
        LOG_DEBUG("GetAssets col %{public}d is null.", columnIndex);
        return JSUtils::Convert2JSValue(env, std::monostate());
    }
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetFloat32Array(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSet = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    FloatVector result = {};
    int errCode = E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GetFloat32Array(columnIndex, result);
    }
    if (errCode == E_NULL_OBJECT) {
        LOG_DEBUG("GetFloat32Array col %{public}d is null.", columnIndex);
        return JSUtils::Convert2JSValue(env, std::monostate());
    }
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetString(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSet = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    std::string result;
    int errCode = E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GetString(columnIndex, result);
    }
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetDouble(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSet = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    double result = 0.0;
    int errCode = E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GetDouble(columnIndex, result);
    }
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetColumnIndex(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    std::string input;
    auto resultSet = ParseFieldByName(env, info, input, "columnName");
    int32_t result = -1;
    int errCode = E_OK;
    if (resultSet != nullptr) {
        errCode = resultSet->GetColumnIndex(input, result);
    }
    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetColumnName(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSet = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    std::string result;
    int errCode = E_OK;
    if (resultSet != nullptr) {
        errCode = resultSet->GetColumnName(columnIndex, result);
    }
    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::IsColumnNull(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSet = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    bool result = false;
    int errCode = E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->IsColumnNull(columnIndex, result);
    }
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, result);
}

napi_value ResultSetProxy::GetRow(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto resultSet = GetInnerResultSet(env, info);
    RowEntity rowEntity;
    int errCode = E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GetRow(rowEntity);
    }
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));

    return JSUtils::Convert2JSValue(env, rowEntity);
}

napi_value ResultSetProxy::GetRowData(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto resultSet = GetInnerResultSet(env, info);
    std::vector<ValueObject> rowData;
    int errCode = E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        std::tie(errCode, rowData) = resultSet->GetRowData();
    }
    RDB_NAPI_ASSERT_INT(env, errCode == E_OK, std::make_shared<InnerErrorExt>(errCode));

    return JSUtils::Convert2JSValue(env, std::move(rowData));
}

std::pair<int, std::vector<RowEntity>> ResultSetProxy::GetRows(ResultSet &resultSet, int32_t maxCount, int32_t position)
{
    int rowPos = 0;
    resultSet.GetRowIndex(rowPos);
    int errCode = E_OK;
    if (position != INIT_POSITION && position != rowPos) {
        errCode = resultSet.GoToRow(position);
    } else if (rowPos == INIT_POSITION) {
        errCode = resultSet.GoToFirstRow();
        if (errCode == E_ROW_OUT_RANGE) {
            return { E_OK, std::vector<RowEntity>() };
        }
    }

    if (errCode != E_OK) {
        LOG_ERROR("Failed code:%{public}d. [%{public}d, %{public}d]", errCode, maxCount, position);
        return { errCode, std::vector<RowEntity>() };
    }

    std::vector<RowEntity> rowEntities;
    for (int32_t i = 0; i < maxCount; ++i) {
        RowEntity rowEntity;
        int errCode = resultSet.GetRow(rowEntity);
        if (errCode == E_ROW_OUT_RANGE) {
            break;
        }
        if (errCode != E_OK) {
            return { errCode, std::vector<RowEntity>() };
        }
        rowEntities.push_back(rowEntity);
        errCode = resultSet.GoToNextRow();
        if (errCode == E_ROW_OUT_RANGE) {
            break;
        }
        if (errCode != E_OK) {
            return { errCode, std::vector<RowEntity>() };
        }
    }
    return { E_OK, rowEntities };
}

napi_value ResultSetProxy::GetRows(napi_env env, napi_callback_info info)
{
    struct RowsContextBase : public ContextBase {
    public:
        int32_t maxCount = 0;
        int32_t position = INIT_POSITION;
        std::weak_ptr<ResultSet> resultSet;
        std::vector<RowEntity> rowEntities;
    };
    std::shared_ptr<RowsContextBase> context = std::make_shared<RowsContextBase>();
    auto resultSet = GetInnerResultSet(env, info);
    RDB_NAPI_ASSERT(env, resultSet != nullptr, std::make_shared<InnerError>(E_ALREADY_CLOSED));
    context->resultSet = resultSet;
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc > 0, std::make_shared<ParamNumError>("1 or 2"));
        auto errCode = JSUtils::Convert2ValueExt(env, argv[0], context->maxCount);
        CHECK_RETURN_SET_E(OK == errCode && context->maxCount > 0, std::make_shared<ParamError>("Invalid maxCount"));
        if (argc == 2) {
            errCode = JSUtils::Convert2ValueExt(env, argv[1], context->position);
            CHECK_RETURN_SET_E(
                OK == errCode && context->position >= 0, std::make_shared<ParamError>("Invalid position"));
        }
    };
    auto exec = [context]() -> int {
        auto result = context->resultSet.lock();
        if (result == nullptr) {
            return E_ALREADY_CLOSED;
        }
        int errCode = E_OK;
        std::tie(errCode, context->rowEntities) = GetRows(*result, context->maxCount, context->position);
        return errCode;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = JSUtils::Convert2JSValue(env, context->rowEntities);
    };
    context->SetAction(env, info, input, exec, output);
    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value ResultSetProxy::GetRowsData(napi_env env, napi_callback_info info)
{
    struct RowsContextBase : public ResultSetContext {
    public:
        int32_t maxCount = 0;
        int32_t position = INIT_POSITION;
        std::weak_ptr<ResultSet> resultSet;
        std::vector<std::vector<ValueObject>> rowsData;
    };
    std::shared_ptr<RowsContextBase> context = std::make_shared<RowsContextBase>();
    auto resultSet = GetInnerResultSet(env, info);
    RDB_NAPI_ASSERT_INT(env, resultSet != nullptr, std::make_shared<InnerErrorExt>(E_ALREADY_CLOSED));
    context->resultSet = resultSet;
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc > 0, std::make_shared<ParamNumError>("1 or 2"));
        auto errCode = JSUtils::Convert2ValueExt(env, argv[0], context->maxCount);
        CHECK_RETURN_SET_E(OK == errCode && context->maxCount > 0,
            std::make_shared<InnerErrorExt>(E_INVALID_ARGS_NEW, "Invalid maxCount"));
        // parameter number is 2
        if (argc == 2 && !JSUtils::IsNull(env, argv[1])) {
            errCode = JSUtils::Convert2ValueExt(env, argv[1], context->position);
            CHECK_RETURN_SET_E(OK == errCode && context->position >= 0,
                std::make_shared<InnerErrorExt>(E_INVALID_ARGS_NEW, "Invalid position"));
        }
    };
    auto exec = [context]() -> int {
        auto result = context->resultSet.lock();
        if (result == nullptr) {
            return E_ALREADY_CLOSED;
        }
        int errCode = E_OK;
        std::tie(errCode, context->rowsData) = result->GetRowsData(context->maxCount, context->position);
        return errCode;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = JSUtils::Convert2JSValue(env, std::move(context->rowsData));
    };
    context->InitAction(env, info, input, exec, output);
    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value ResultSetProxy::GetSendableRow(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto resultSet = GetInnerResultSet(env, info);
    RowEntity rowEntity;
    int errCode = E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->GetRow(rowEntity);
    }
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    return JSUtils::Convert2Sendable(env, rowEntity);
}

napi_value ResultSetProxy::GetValue(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    int32_t columnIndex;
    auto resultSet = ParseInt32FieldByName(env, info, columnIndex, "columnIndex");
    ValueObject object;
    int errCode = E_ALREADY_CLOSED;
    if (resultSet != nullptr) {
        errCode = resultSet->Get(columnIndex, object);
    }
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    return JSUtils::Convert2JSValue(env, object);
}

napi_value ResultSetProxy::IsClosed(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    return JSUtils::Convert2JSValue(env, GetInnerResultSet(env, info) == nullptr);
}

void ResultSetProxy::Init(napi_env env, napi_value exports)
{
    auto lambda = []() -> std::vector<napi_property_descriptor> {
        std::vector<napi_property_descriptor> properties = {
            DECLARE_NAPI_FUNCTION("goToRow", GoToRow),
            DECLARE_NAPI_FUNCTION("getLong", GetLong),
            DECLARE_NAPI_FUNCTION_WITH_DATA("getColumnType", GetColumnType, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("getColumnTypeSync", GetColumnType, SYNC),
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
            DECLARE_NAPI_FUNCTION("getRows", GetRows),
            DECLARE_NAPI_FUNCTION("getSendableRow", GetSendableRow),
            DECLARE_NAPI_FUNCTION("getColumnNames", GetWholeColumnNames),
            DECLARE_NAPI_FUNCTION("getCurrentRowData", GetRowData),
            DECLARE_NAPI_FUNCTION("getRowsData", GetRowsData),

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

    LOG_DEBUG("ResultSetProxy::Init end.");
}
} // namespace RelationalStoreJsKit
} // namespace OHOS
