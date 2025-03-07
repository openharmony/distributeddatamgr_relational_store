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

#define LOG_TAG "NapiRdbStore"
#include "napi_rdb_store.h"

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <string>
#include <vector>

#include "js_df_manager.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "js_utils.h"
#include "logger.h"
#include "napi_rdb_context.h"
#include "napi_rdb_error.h"
#include "napi_rdb_js_utils.h"
#include "napi_rdb_statistics_observer.h"
#include "napi_rdb_store_observer.h"
#include "napi_rdb_trace.h"
#include "napi_result_set.h"
#include "napi_transaction.h"
#include "rdb_errno.h"
#include "rdb_sql_statistic.h"
#include "rdb_fault_hiview_reporter.h"
#include "securec.h"

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
#include "rdb_utils.h"
using namespace OHOS::DataShare;
#endif

using namespace OHOS::Rdb;
using namespace OHOS::AppDataMgrJsKit;
using namespace OHOS::AppDataMgrJsKit::JSUtils;

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
using OHOS::DistributedRdb::SubscribeMode;
using OHOS::DistributedRdb::SubscribeOption;
using OHOS::DistributedRdb::SyncOption;

using OHOS::DistributedRdb::Details;
using OHOS::DistributedRdb::SyncResult;
#endif

namespace OHOS {
namespace RelationalStoreJsKit {

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
struct PredicatesProxy {
    std::shared_ptr<DataShareAbsPredicates> predicates_;
};
#endif
using Reportor = RdbFaultHiViewReporter;
constexpr int32_t KEY_INDEX = 0;
constexpr int32_t VALUE_INDEX = 1;

RdbStoreProxy::RdbStoreProxy() {}

RdbStoreProxy::~RdbStoreProxy()
{
    UnregisterAll();
}

void RdbStoreProxy::UnregisterAll()
{
    auto rdbStore = GetInstance();
    if (rdbStore == nullptr) {
        return;
    }
#if !defined(CROSS_PLATFORM)
    for (int32_t mode = SubscribeMode::REMOTE; mode < SubscribeMode::LOCAL; mode++) {
        for (auto &obs : observers_[mode]) {
            if (obs == nullptr) {
                continue;
            }
            rdbStore->UnSubscribe({ static_cast<SubscribeMode>(mode) }, obs.get());
        }
    }
    rdbStore->UnsubscribeObserver({ SubscribeMode::LOCAL_DETAIL }, nullptr);
    for (const auto &[event, observers] : localObservers_) {
        rdbStore->UnSubscribe({ static_cast<SubscribeMode>(DistributedRdb::LOCAL), event }, nullptr);
    }
    for (const auto &[event, observers] : localSharedObservers_) {
        rdbStore->UnSubscribe({ static_cast<SubscribeMode>(DistributedRdb::LOCAL_SHARED), event }, nullptr);
    }
    for (const auto &obs : syncObservers_) {
        rdbStore->UnregisterAutoSyncCallback(obs);
    }
    for (const auto &obs : statisticses_) {
        DistributedRdb::SqlStatistic::Unsubscribe(obs);
    }
#endif
}

RdbStoreProxy::RdbStoreProxy(std::shared_ptr<NativeRdb::RdbStore> rdbStore)
{
    if (GetInstance() == rdbStore) {
        return;
    }
    SetInstance(std::move(rdbStore));
}

RdbStoreProxy &RdbStoreProxy::operator=(std::shared_ptr<NativeRdb::RdbStore> rdbStore)
{
    if (GetInstance() == rdbStore) {
        return *this;
    }
    SetInstance(std::move(rdbStore));
    return *this;
}

bool RdbStoreProxy::IsSystemAppCalled()
{
    return isSystemAppCalled_;
}

std::string RdbStoreProxy::GetBundleName()
{
    return bundleName_;
}

bool IsNapiTypeString(napi_env env, size_t argc, napi_value *argv, size_t arg)
{
    if (arg >= argc) {
        return false;
    }
    napi_valuetype type = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, argv[arg], &type), false);
    return type == napi_string;
}

Descriptor RdbStoreProxy::GetDescriptors()
{
    return []() -> std::vector<napi_property_descriptor> {
        std::vector<napi_property_descriptor> properties = {
            DECLARE_NAPI_FUNCTION_WITH_DATA("delete", Delete, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("update", Update, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("insert", Insert, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("batchInsert", BatchInsert, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA(
                "batchInsertWithConflictResolution", BatchInsertWithConflictResolution, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("querySql", QuerySql, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("query", Query, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("executeSql", ExecuteSql, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("execute", Execute, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("replace", Replace, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("queryByStep", QueryByStep, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("rollback", RollBackByTxId, ASYNC),
            DECLARE_NAPI_FUNCTION("backup", Backup),
            DECLARE_NAPI_FUNCTION("beginTransaction", BeginTransaction),
            DECLARE_NAPI_FUNCTION("beginTrans", BeginTrans),
            DECLARE_NAPI_FUNCTION("rollBack", RollBack),
            DECLARE_NAPI_FUNCTION("commit", Commit),
            DECLARE_NAPI_FUNCTION("restore", Restore),
            DECLARE_NAPI_GETTER_SETTER("version", GetVersion, SetVersion),
            DECLARE_NAPI_GETTER("rebuilt", GetRebuilt),
            DECLARE_NAPI_FUNCTION("close", Close),
            DECLARE_NAPI_FUNCTION("attach", Attach),
            DECLARE_NAPI_FUNCTION("detach", Detach),
            DECLARE_NAPI_FUNCTION("createTransaction", CreateTransaction),
        };
#if !defined(CROSS_PLATFORM)
        AddDistributedFunctions(properties);
#endif
        AddSyncFunctions(properties);
        return properties;
    };
}

void RdbStoreProxy::AddSyncFunctions(std::vector<napi_property_descriptor> &properties)
{
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("deleteSync", Delete, SYNC));
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("updateSync", Update, SYNC));
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("insertSync", Insert, SYNC));
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("batchInsertSync", BatchInsert, SYNC));
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("batchInsertWithConflictResolutionSync",
        BatchInsertWithConflictResolution, SYNC));
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("querySqlSync", QueryByStep, SYNC));
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("executeSync", Execute, SYNC));
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("querySync", QueryByStep, SYNC));
}

void RdbStoreProxy::Init(napi_env env, napi_value exports)
{
    auto jsCtor = JSUtils::DefineClass(env, "ohos.data.relationalStore", "RdbStore", GetDescriptors(), Initialize);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, exports, "RdbStore", jsCtor));
}

napi_value RdbStoreProxy::Initialize(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, NULL, NULL, &self, nullptr));
    auto finalize = [](napi_env env, void *data, void *hint) {
        auto tid = JSDFManager::GetInstance().GetFreedTid(data);
        if (tid != 0) {
            LOG_ERROR("(T:%{public}d) freed! data:0x%016" PRIXPTR, tid, uintptr_t(data) & LOWER_24_BITS_MASK);
        }
        if (data != hint) {
            LOG_ERROR("RdbStoreProxy memory corrupted! data:0x%016" PRIXPTR "hint:0x%016" PRIXPTR, uintptr_t(data),
                uintptr_t(hint));
            return;
        }
        RdbStoreProxy *proxy = reinterpret_cast<RdbStoreProxy *>(data);
        proxy->UnregisterAll();
        proxy->SetInstance(nullptr);
        delete proxy;
    };
    auto *proxy = new (std::nothrow) RdbStoreProxy();
    if (proxy == nullptr) {
        return nullptr;
    }
    napi_status status = napi_wrap(env, self, proxy, finalize, proxy, nullptr);
    if (status != napi_ok) {
        LOG_ERROR("RdbStoreProxy napi_wrap failed! code:%{public}d!", status);
        finalize(env, proxy, proxy);
        return nullptr;
    }
    JSDFManager::GetInstance().AddNewInfo(proxy);
    return self;
}

napi_value RdbStoreProxy::NewInstance(
    napi_env env, std::shared_ptr<NativeRdb::RdbStore> value, bool isSystemAppCalled, const std::string &bundleName)
{
    if (value == nullptr) {
        LOG_ERROR("Value is nullptr ? %{public}d", (value == nullptr));
        return nullptr;
    }
    napi_value cons = JSUtils::GetClass(env, "ohos.data.relationalStore", "RdbStore");
    if (cons == nullptr) {
        LOG_ERROR("Constructor of ResultSet is nullptr!");
        return nullptr;
    }

    napi_value instance = nullptr;
    auto status = napi_new_instance(env, cons, 0, nullptr, &instance);
    if (status != napi_ok) {
        LOG_ERROR("RdbStoreProxy::NewInstance napi_new_instance failed! code:%{public}d!", status);
        return nullptr;
    }

    RdbStoreProxy *proxy = nullptr;
    status = napi_unwrap(env, instance, reinterpret_cast<void **>(&proxy));
    if (status != napi_ok || proxy == nullptr) {
        LOG_ERROR("RdbStoreProxy::NewInstance native instance is nullptr! code:%{public}d!", status);
        return nullptr;
    }
    proxy->queue_ = std::make_shared<AppDataMgrJsKit::UvQueue>(env);
    proxy->dbType = value->GetDbType();
    proxy->SetInstance(std::move(value));
    proxy->isSystemAppCalled_ = isSystemAppCalled;
    proxy->bundleName_ = bundleName;
    return instance;
}

RdbStoreProxy *GetNativeInstance(napi_env env, napi_value self)
{
    RdbStoreProxy *proxy = nullptr;
    napi_status status = napi_unwrap(env, self, reinterpret_cast<void **>(&proxy));
    if (proxy == nullptr) {
        LOG_ERROR("RdbStoreProxy native instance is nullptr! code:%{public}d!", status);
        return nullptr;
    }
    return proxy;
}

int ParserThis(const napi_env &env, const napi_value &self, std::shared_ptr<RdbStoreContextBase> context)
{
    RdbStoreProxy *obj = GetNativeInstance(env, self);
    CHECK_RETURN_SET(obj != nullptr, std::make_shared<ParamError>("RdbStore", "not nullptr."));
    CHECK_RETURN_SET(obj->GetInstance() != nullptr, std::make_shared<InnerError>(NativeRdb::E_ALREADY_CLOSED));
    context->boundObj = obj;
    context->rdbStore = obj->GetInstance();
    return OK;
}

int ParseTableName(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    context->tableName = JSUtils::Convert2String(env, arg);
    CHECK_RETURN_SET(!context->tableName.empty(), std::make_shared<ParamError>("table", "not empty string."));
    return OK;
}

int ParseCursor(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    double cursor = 0;
    auto status = JSUtils::Convert2Value(env, arg, cursor);
    CHECK_RETURN_SET(status == napi_ok && cursor > 0, std::make_shared<ParamError>("cursor", "valid cursor."));
    context->cursor = static_cast<uint64_t>(cursor);
    return OK;
}

int ParseColumnName(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    context->columnName = JSUtils::Convert2String(env, arg);
    CHECK_RETURN_SET(!context->columnName.empty(), std::make_shared<ParamError>("columnName", "not empty string."));
    return OK;
}

int ParsePrimaryKey(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    JSUtils::Convert2Value(env, arg, context->keys);
    CHECK_RETURN_SET(!context->keys.empty(), std::make_shared<ParamError>("PRIKey", "number or string."));
    return OK;
}

int ParseDevice(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    context->device = JSUtils::Convert2String(env, arg);
    CHECK_RETURN_SET(!context->device.empty(), std::make_shared<ParamError>("device", "not empty"));
    return OK;
}

int ParseTablesName(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    int32_t ret = JSUtils::Convert2Value(env, arg, context->tablesNames);
    CHECK_RETURN_SET(ret == napi_ok, std::make_shared<ParamError>("tablesNames", "not empty string."));
    return OK;
}

int ParseSyncModeArg(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    napi_valuetype type = napi_undefined;
    napi_typeof(env, arg, &type);
    CHECK_RETURN_SET(type == napi_number, std::make_shared<ParamError>("mode", "a SyncMode Type."));
    napi_status status = napi_get_value_int32(env, arg, &context->enumArg);
    CHECK_RETURN_SET(status == napi_ok, std::make_shared<ParamError>("mode", "a SyncMode Type."));
    bool checked = context->enumArg == 0 || context->enumArg == 1;
    CHECK_RETURN_SET(checked, std::make_shared<ParamError>("mode", "a SyncMode of device."));
    return OK;
}

int ParseDistributedTypeArg(
    const napi_env &env, size_t argc, napi_value *argv, std::shared_ptr<RdbStoreContext> context)
{
    context->distributedType = DistributedRdb::DISTRIBUTED_DEVICE;
    if (argc > 1) {
        auto status = JSUtils::Convert2ValueExt(env, argv[1], context->distributedType);
        bool checked = status == napi_ok && context->distributedType >= DistributedRdb::DISTRIBUTED_DEVICE &&
                       context->distributedType <= DistributedRdb::DISTRIBUTED_CLOUD;
        CHECK_RETURN_SET(JSUtils::IsNull(env, argv[1]) || checked,
            std::make_shared<ParamError>("distributedType", "a DistributedType"));
    }
    return OK;
}

int ParseDistributedConfigArg(
    const napi_env &env, size_t argc, napi_value *argv, std::shared_ptr<RdbStoreContext> context)
{
    context->distributedConfig = { false };
    // '2' Ensure that the incoming argv contains 3 parameter
    if (argc > 2) {
        auto status = JSUtils::Convert2Value(env, argv[2], context->distributedConfig);
        bool checked = status == napi_ok || JSUtils::IsNull(env, argv[2]);
        CHECK_RETURN_SET(checked, std::make_shared<ParamError>("distributedConfig", "a DistributedConfig type"));
    }
    return OK;
}

int ParseCloudSyncModeArg(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    auto status = JSUtils::Convert2ValueExt(env, arg, context->syncMode);
    bool checked = (status == napi_ok && context->syncMode >= DistributedRdb::TIME_FIRST &&
                    context->syncMode <= DistributedRdb::CLOUD_FIRST);
    CHECK_RETURN_SET(checked, std::make_shared<ParamError>("mode", "a SyncMode of cloud."));
    return OK;
}

int ParseCallback(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, arg, &valueType);
    CHECK_RETURN_SET(
        (status == napi_ok && valueType == napi_function), std::make_shared<ParamError>("callback", "a function."));
    NAPI_CALL_BASE(env, napi_create_reference(env, arg, 1, &context->callback_), ERR);
    return OK;
}

int ParseCloudSyncCallback(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, arg, &valueType);
    CHECK_RETURN_SET(valueType == napi_function, std::make_shared<ParamError>("progress", "a callback type"));
    NAPI_CALL_BASE(env, napi_create_reference(env, arg, 1, &context->asyncHolder), ERR);
    return OK;
}

int ParsePredicates(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    auto status = napi_unwrap(env, arg, reinterpret_cast<void **>(&context->predicatesProxy));
    CHECK_RETURN_SET(status == napi_ok && context->predicatesProxy != nullptr,
        std::make_shared<ParamError>("predicates", "an RdbPredicates."));
    context->tableName = context->predicatesProxy->GetPredicates()->GetTableName();
    context->rdbPredicates = context->predicatesProxy->GetPredicates();
    return OK;
}

int ParseDataSharePredicates(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
    RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
    CHECK_RETURN_SET(obj->IsSystemAppCalled(), std::make_shared<NonSystemError>());
    PredicatesProxy *proxy = nullptr;
    napi_status status = napi_unwrap(env, arg, reinterpret_cast<void **>(&proxy));
    bool checked = (status == napi_ok) && (proxy != nullptr) && (proxy->predicates_ != nullptr);
    CHECK_RETURN_SET(checked, std::make_shared<ParamError>("predicates", "an DataShare Predicates."));

    std::shared_ptr<DataShareAbsPredicates> dsPredicates = proxy->predicates_;
    RdbPredicates rdbPredicates = RdbDataShareAdapter::RdbUtils::ToPredicates(*dsPredicates, context->tableName);
    context->rdbPredicates = std::make_shared<RdbPredicates>(rdbPredicates);
#endif
    return OK;
}

int ParseSrcName(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    context->srcName = JSUtils::Convert2String(env, arg);
    CHECK_RETURN_SET(!context->srcName.empty(), std::make_shared<ParamError>("srcName", "not empty"));
    return OK;
}

int ParseColumns(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    napi_valuetype type = napi_undefined;
    napi_typeof(env, arg, &type);
    if (type == napi_undefined || type == napi_null) {
        return OK;
    }
    int32_t ret = JSUtils::Convert2Value(env, arg, context->columns);
    CHECK_RETURN_SET(ret == napi_ok, std::make_shared<ParamError>("columns", "a string array"));
    return OK;
}

int ParseBindArgs(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    context->bindArgs.clear();
    napi_valuetype type = napi_undefined;
    napi_typeof(env, arg, &type);
    if (type == napi_undefined || type == napi_null) {
        return OK;
    }
    bool isArray = false;
    napi_status status = napi_is_array(env, arg, &isArray);
    CHECK_RETURN_SET(status == napi_ok && isArray, std::make_shared<ParamError>("values", "a BindArgs array."));

    uint32_t arrLen = 0;
    status = napi_get_array_length(env, arg, &arrLen);
    CHECK_RETURN_SET(status == napi_ok, std::make_shared<ParamError>("values", "not empty."));
    for (size_t i = 0; i < arrLen; ++i) {
        napi_value element = nullptr;
        napi_get_element(env, arg, i, &element);
        ValueObject valueObject;
        int32_t ret = JSUtils::Convert2Value(env, element, valueObject.value);
        CHECK_RETURN_SET(ret == OK, std::make_shared<ParamError>(std::to_string(i), "ValueObject"));
        // The blob is an empty vector.
        // If the API version is less than 14, and insert null. Otherwise, insert an empty vector.
        if (valueObject.GetType() == ValueObject::TYPE_BLOB && JSUtils::GetHapVersion() < 14) {
            std::vector<uint8_t> tmpValue;
            valueObject.GetBlob(tmpValue);
            if (tmpValue.empty()) {
                valueObject = ValueObject();
            }
        }
        context->bindArgs.push_back(std::move(valueObject));
    }
    return OK;
}

int ParseSql(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    context->sql = JSUtils::Convert2String(env, arg);
    CHECK_RETURN_SET(!context->sql.empty(), std::make_shared<ParamError>("sql", "not empty"));
    return OK;
}

int ParseTxId(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    int64_t txId = 0;
    auto status = JSUtils::Convert2ValueExt(env, arg, txId);
    CHECK_RETURN_SET(status == napi_ok && txId >= 0, std::make_shared<ParamError>("txId", "not invalid txId"));
    context->txId = txId;
    return OK;
}

int ParseSendableValuesBucket(const napi_env env, const napi_value map, std::shared_ptr<RdbStoreContext> context)
{
    uint32_t length = 0;
    napi_status status = napi_map_get_size(env, map, &length);
    auto error = std::make_shared<ParamError>("ValuesBucket is invalid.");
    CHECK_RETURN_SET(status == napi_ok && length > 0, error);
    napi_value entries = nullptr;
    status = napi_map_get_entries(env, map, &entries);
    CHECK_RETURN_SET(status == napi_ok, std::make_shared<InnerError>("napi_map_get_entries failed."));
    for (uint32_t i = 0; i < length; ++i) {
        napi_value iter = nullptr;
        status = napi_map_iterator_get_next(env, entries, &iter);
        CHECK_RETURN_SET(status == napi_ok, std::make_shared<InnerError>("napi_map_iterator_get_next failed."));
        napi_value values = nullptr;
        status = napi_get_named_property(env, iter, "value", &values);
        CHECK_RETURN_SET(status == napi_ok, std::make_shared<InnerError>("napi_get_named_property value failed."));
        napi_value key = nullptr;
        status = napi_get_element(env, values, KEY_INDEX, &key);
        CHECK_RETURN_SET(status == napi_ok, std::make_shared<InnerError>("napi_get_element key failed."));
        std::string keyStr = JSUtils::Convert2String(env, key);
        napi_value value = nullptr;
        status = napi_get_element(env, values, VALUE_INDEX, &value);
        CHECK_RETURN_SET(status == napi_ok, std::make_shared<InnerError>("napi_get_element value failed."));
        ValueObject valueObject;
        int32_t ret = JSUtils::Convert2Value(env, value, valueObject.value);
        if (ret == napi_ok) {
            context->valuesBucket.Put(keyStr, valueObject);
        } else if (ret != napi_generic_failure) {
            CHECK_RETURN_SET(false, std::make_shared<ParamError>("The value type of " + keyStr, "invalid."));
        }
    }
    return OK;
}

int ParseValuesBucket(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    bool isMap = false;
    napi_status status = napi_is_map(env, arg, &isMap);
    CHECK_RETURN_SET(
        status == napi_ok, std::make_shared<InnerError>("call napi_is_map failed" + std::to_string(status)));
    if (isMap) {
        return ParseSendableValuesBucket(env, arg, context);
    }
    napi_value keys = nullptr;
    napi_get_all_property_names(env, arg, napi_key_own_only,
        static_cast<napi_key_filter>(napi_key_enumerable | napi_key_skip_symbols), napi_key_numbers_to_strings, &keys);
    uint32_t arrLen = 0;
    status = napi_get_array_length(env, keys, &arrLen);
    CHECK_RETURN_SET(status == napi_ok && arrLen > 0, std::make_shared<ParamError>("ValuesBucket is invalid"));

    for (size_t i = 0; i < arrLen; ++i) {
        napi_value key = nullptr;
        status = napi_get_element(env, keys, i, &key);
        CHECK_RETURN_SET(status == napi_ok, std::make_shared<ParamError>("ValuesBucket is invalid."));
        std::string keyStr = JSUtils::Convert2String(env, key);
        napi_value value = nullptr;
        napi_get_property(env, arg, key, &value);
        ValueObject valueObject;
        int32_t ret = JSUtils::Convert2Value(env, value, valueObject.value);
        // The blob is an empty vector.
        // If the API version is less than 14, and insert null. Otherwise, insert an empty vector.
        if (ret == napi_ok && valueObject.GetType() == ValueObject::TYPE_BLOB && JSUtils::GetHapVersion() < 14) {
            std::vector<uint8_t> tmpValue;
            valueObject.GetBlob(tmpValue);
            if (tmpValue.empty()) {
                valueObject = ValueObject();
            }
            auto proxy = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
            if (tmpValue.empty() && (proxy != nullptr)) {
                Reportor::ReportFault(RdbEmptyBlobEvent(proxy->GetBundleName()));
            }
        }
        if (ret == napi_ok) {
            context->valuesBucket.Put(keyStr, valueObject);
        } else if (ret != napi_generic_failure) {
            CHECK_RETURN_SET(false, std::make_shared<ParamError>("The value type of " + keyStr, "invalid."));
        }
    }
    return OK;
}

int ParseValuesBuckets(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    bool isArray = false;
    napi_is_array(env, arg, &isArray);
    CHECK_RETURN_SET(isArray, std::make_shared<ParamError>("ValuesBuckets is invalid."));

    uint32_t arrLen = 0;
    napi_status status = napi_get_array_length(env, arg, &arrLen);
    CHECK_RETURN_SET(status == napi_ok && arrLen > 0, std::make_shared<ParamError>("ValuesBuckets is invalid."));

    for (uint32_t i = 0; i < arrLen; ++i) {
        napi_value obj = nullptr;
        status = napi_get_element(env, arg, i, &obj);
        CHECK_RETURN_SET(status == napi_ok, std::make_shared<InnerError>("napi_get_element failed."));

        CHECK_RETURN_ERR(ParseValuesBucket(env, obj, context) == OK);
        context->sharedValuesBuckets.Put(context->valuesBucket);
        context->valuesBucket.Clear();
    }
    return OK;
}

int ParseConflictResolution(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    int32_t conflictResolution = 0;
    napi_get_value_int32(env, arg, &conflictResolution);
    int32_t min = static_cast<int32_t>(NativeRdb::ConflictResolution::ON_CONFLICT_NONE);
    int32_t max = static_cast<int32_t>(NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    bool checked = (conflictResolution >= min) && (conflictResolution <= max);
    CHECK_RETURN_SET(checked, std::make_shared<ParamError>("conflictResolution", "a ConflictResolution."));
    context->conflictResolution = static_cast<NativeRdb::ConflictResolution>(conflictResolution);
    return OK;
}

napi_value RdbStoreProxy::Insert(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 2 || argc == 3, std::make_shared<ParamNumError>("2 to 4"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseTableName(env, argv[0], context));
        CHECK_RETURN(OK == ParseValuesBucket(env, argv[1], context));
        CHECK_RETURN_SET_E(!HasDuplicateAssets(context->valuesBucket), std::make_shared<ParamError>("Duplicate assets "
                                                                                                    "are not allowed"));
        if (argc == 3) {
            CHECK_RETURN(OK == ParseConflictResolution(env, argv[2], context));
        }
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->rdbStore != nullptr);
        auto rdbStore = std::move(context->rdbStore);
        return rdbStore->InsertWithConflictResolution(
            context->int64Output, context->tableName, context->valuesBucket, context->conflictResolution);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->int64Output, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(!(context->error) || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

int ParseTransactionOptions(
    const napi_env &env, size_t argc, napi_value *argv, std::shared_ptr<CreateTransactionContext> context)
{
    context->transactionOptions.transactionType = Transaction::DEFERRED;
    if (argc > 0 && !JSUtils::IsNull(env, argv[0])) {
        auto status = JSUtils::Convert2Value(env, argv[0], context->transactionOptions);
        CHECK_RETURN_SET(status == napi_ok, std::make_shared<ParamError>("options", "a transactionOptions"));
    }
    return OK;
}

napi_value RdbStoreProxy::BatchInsert(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseTableName(env, argv[0], context));
        CHECK_RETURN(OK == ParseValuesBuckets(env, argv[1], context));
        CHECK_RETURN_SET_E(!HasDuplicateAssets(context->sharedValuesBuckets),
            std::make_shared<ParamError>("Duplicate assets are not allowed"));
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->rdbStore != nullptr);
        auto rdbStore = std::move(context->rdbStore);
        auto [ret, output] = rdbStore->BatchInsert(context->tableName, context->sharedValuesBuckets);
        context->int64Output = output;
        return ret;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->int64Output, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::BatchInsertWithConflictResolution(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 3, std::make_shared<ParamNumError>("3"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseTableName(env, argv[0], context));
        // 'argv[1]' represents a valuesBucket
        CHECK_RETURN(OK == ParseValuesBuckets(env, argv[1], context));
        CHECK_RETURN_SET_E(!HasDuplicateAssets(context->sharedValuesBuckets),
            std::make_shared<ParamError>("Duplicate assets are not allowed"));
        // 'argv[2]' represents a ConflictResolution
        CHECK_RETURN_SET_E(!JSUtils::IsNull(env, argv[2]), std::make_shared<ParamError>("conflict", "not null"));
        // 'argv[2]' represents a ConflictResolution
        CHECK_RETURN(OK == ParseConflictResolution(env, argv[2], context));
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->rdbStore != nullptr);
        auto rdbStore = std::move(context->rdbStore);
        auto [ret, output] = rdbStore->BatchInsertWithConflictResolution(
            context->tableName, context->sharedValuesBuckets, context->conflictResolution);
        context->int64Output = output;
        return ret;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->int64Output, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);
    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::Delete(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 1 || argc == 2, std::make_shared<ParamNumError>("1 to 3"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        if (argc == 2) {
            CHECK_RETURN(OK == ParseTableName(env, argv[0], context));
            CHECK_RETURN(OK == ParseDataSharePredicates(env, argv[1], context));
        } else {
            CHECK_RETURN(OK == ParsePredicates(env, argv[0], context));
        }
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->rdbStore != nullptr && context->rdbPredicates != nullptr);
        auto rdbStore = std::move(context->rdbStore);
        return rdbStore->Delete(context->intOutput, *(context->rdbPredicates));
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->intOutput, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::Update(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN(OK == ParserThis(env, self, context));
        if (IsNapiTypeString(env, argc, argv, 0)) {
            CHECK_RETURN_SET_E(argc == 3 || argc == 4, std::make_shared<ParamNumError>("2 to 5"));
            CHECK_RETURN(OK == ParseTableName(env, argv[0], context));
            CHECK_RETURN(OK == ParseValuesBucket(env, argv[1], context));
            CHECK_RETURN(OK == ParseDataSharePredicates(env, argv[2], context));
            if (argc == 4) {
                CHECK_RETURN(OK == ParseConflictResolution(env, argv[3], context));
            }
        } else {
            CHECK_RETURN_SET_E(argc == 2 || argc == 3, std::make_shared<ParamNumError>("2 to 5"));
            CHECK_RETURN(OK == ParseValuesBucket(env, argv[0], context));
            CHECK_RETURN(OK == ParsePredicates(env, argv[1], context));
            if (argc == 3) {
                CHECK_RETURN(OK == ParseConflictResolution(env, argv[2], context));
            }
        }
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->rdbStore != nullptr && context->rdbPredicates != nullptr);
        auto rdbStore = std::move(context->rdbStore);
        return rdbStore->UpdateWithConflictResolution(context->intOutput, context->tableName, context->valuesBucket,
            context->rdbPredicates->GetWhereClause(), context->rdbPredicates->GetBindArgs(),
            context->conflictResolution);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->intOutput, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::Query(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN(OK == ParserThis(env, self, context));
        if (IsNapiTypeString(env, argc, argv, 0)) {
            CHECK_RETURN_SET_E(argc == 2 || argc == 3, std::make_shared<ParamNumError>("1 to 4"));
            CHECK_RETURN(OK == ParseTableName(env, argv[0], context));
            CHECK_RETURN(OK == ParseDataSharePredicates(env, argv[1], context));
            if (argc == 3) {
                CHECK_RETURN(OK == ParseColumns(env, argv[2], context));
            }
        } else {
            CHECK_RETURN_SET_E(argc == 1 || argc == 2, std::make_shared<ParamNumError>("1 to 4"));
            CHECK_RETURN(OK == ParsePredicates(env, argv[0], context));
            if (argc == 2) {
                CHECK_RETURN(OK == ParseColumns(env, argv[1], context));
            }
        }
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->rdbStore != nullptr && context->rdbPredicates != nullptr);
#if defined(WINDOWS_PLATFORM) || defined(MAC_PLATFORM) || defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
        context->resultSet = context->rdbStore->QueryByStep(*(context->rdbPredicates), context->columns);
#else
        context->resultSet = context->rdbStore->Query(*(context->rdbPredicates), context->columns);
#endif
        context->rdbStore = nullptr;
        // If the API version is greater than or equal to 16, throw E_ALREADY_CLOSED.
        return (context->resultSet != nullptr) ? E_OK : (JSUtils::GetHapVersion() >= 16) ? E_ALREADY_CLOSED : E_ERROR;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = ResultSetProxy::NewInstance(env, std::move(context->resultSet));
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
napi_value RdbStoreProxy::RemoteQuery(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 3 || argc == 4, std::make_shared<ParamNumError>("3 to 5"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseDevice(env, argv[0], context));
        CHECK_RETURN(OK == ParseTableName(env, argv[1], context));
        CHECK_RETURN(OK == ParsePredicates(env, argv[2], context));
        if (argc == 4) {
            CHECK_RETURN(OK == ParseColumns(env, argv[3], context));
        }
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->rdbStore != nullptr && context->rdbPredicates != nullptr);
        int errCode = E_ERROR;
        context->resultSet =
            context->rdbStore->RemoteQuery(context->device, *(context->rdbPredicates), context->columns, errCode);
        context->rdbStore = nullptr;
        return errCode;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = ResultSetProxy::NewInstance(env, std::move(context->resultSet));
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}
#endif

napi_value RdbStoreProxy::QuerySql(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 1 || argc == 2, std::make_shared<ParamNumError>("1 to 3"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseSql(env, argv[0], context));
        if (argc == 2) {
            CHECK_RETURN(OK == ParseBindArgs(env, argv[1], context));
        }
    };
    auto exec = [context]() -> int {
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && context->rdbStore != nullptr);
        if (obj->dbType == DB_VECTOR) {
            context->resultSet = context->rdbStore->QueryByStep(context->sql, context->bindArgs);
            return (context->resultSet != nullptr) ? E_OK : E_ERROR;
        }
#if defined(WINDOWS_PLATFORM) || defined(MAC_PLATFORM) || defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
        context->resultSet = context->rdbStore->QueryByStep(context->sql, context->bindArgs);
#else
        context->resultSet = context->rdbStore->QuerySql(context->sql, context->bindArgs);
#endif
        context->rdbStore = nullptr;
        // If the API version is greater than or equal to 16, throw E_ALREADY_CLOSED.
        return (context->resultSet != nullptr) ? E_OK : (JSUtils::GetHapVersion() >= 16) ? E_ALREADY_CLOSED : E_ERROR;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = ResultSetProxy::NewInstance(env, std::move(context->resultSet));
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::ExecuteSql(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 1 || argc == 2, std::make_shared<ParamNumError>("1 to 3"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseSql(env, argv[0], context));
        if (argc == 2) {
            CHECK_RETURN(OK == ParseBindArgs(env, argv[1], context));
            CHECK_RETURN_SET_E(!HasDuplicateAssets(context->bindArgs), std::make_shared<ParamError>("Duplicate assets "
                                                                                                    "are not allowed"));
        }
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->rdbStore != nullptr);
        auto rdbStore = std::move(context->rdbStore);
        return rdbStore->ExecuteSql(context->sql, context->bindArgs);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::Execute(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 1 || argc == 2 || argc == 3, std::make_shared<ParamNumError>("1 to 3"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseSql(env, argv[0], context));
        if (argc == 2) {
            napi_valuetype type = napi_undefined;
            napi_typeof(env, argv[1], &type);
            if (type == napi_number) {
                CHECK_RETURN(OK == ParseTxId(env, argv[1], context));
            } else {
                CHECK_RETURN(OK == ParseBindArgs(env, argv[1], context));
                CHECK_RETURN_SET_E(!HasDuplicateAssets(context->bindArgs),
                    std::make_shared<ParamError>("Duplicate assets are not allowed"));
            }
        }
        if (argc == 3) {
            CHECK_RETURN(OK == ParseTxId(env, argv[1], context));
            CHECK_RETURN(OK == ParseBindArgs(env, argv[2], context));
            CHECK_RETURN_SET_E(!HasDuplicateAssets(context->bindArgs),
                std::make_shared<ParamError>("Duplicate assets are not allowed"));
        }
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->rdbStore != nullptr);
        auto status = E_ERROR;
        std::tie(status, context->sqlExeOutput) =
            context->rdbStore->Execute(context->sql, context->bindArgs, context->txId);
        context->rdbStore = nullptr;
        return status;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = JSUtils::Convert2JSValue(env, context->sqlExeOutput);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::Replace(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseTableName(env, argv[0], context));
        CHECK_RETURN(OK == ParseValuesBucket(env, argv[1], context));
        CHECK_RETURN_SET_E(!HasDuplicateAssets(context->valuesBucket),
            std::make_shared<ParamError>("Duplicate assets are not allowed"));
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->rdbStore != nullptr);
        auto rdbStore = std::move(context->rdbStore);
        return rdbStore->Replace(context->int64Output, context->tableName, context->valuesBucket);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->int64Output, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::Backup(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 1, std::make_shared<ParamNumError>("1 or 2"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseTableName(env, argv[0], context));
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->rdbStore != nullptr);
        auto rdbStore = std::move(context->rdbStore);
        auto res = rdbStore->Backup(context->tableName, context->newKey);
        if (res == E_DB_NOT_EXIST) {
            return E_OK;
        }
        return res;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

struct AttachContext : public RdbStoreContextBase {
    ContextParam param;
    RdbConfig config;
    std::string attachName;
    int32_t waitTime;
    int32_t attachedNum;
};

napi_value RdbStoreProxy::Attach(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<AttachContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN(OK == ParserThis(env, self, context));
        int32_t errCode;
        // The parameter must be between 2 and 4
        CHECK_RETURN_SET_E(argc >= 2 && argc <= 4, std::make_shared<ParamNumError>("2 or 3 or 4"));
        // argv[0] may be a string or context.
        bool isString = IsNapiString(env, argv[0]);
        if (isString) {
            errCode = Convert2Value(env, argv[0], context->config.path);
            CHECK_RETURN_SET_E(napi_ok == errCode && !context->config.path.empty(),
                std::make_shared<ParamError>("fullPath cannot be empty."));
        } else {
            errCode = Convert2Value(env, argv[0], context->param);
            CHECK_RETURN_SET_E(OK == errCode, std::make_shared<ParamError>("Illegal context."));

            int errCode = Convert2Value(env, argv[1], context->config);
            CHECK_RETURN_SET_E(OK == errCode, std::make_shared<ParamError>("Illegal StoreConfig or name."));

            auto [code, err] = GetRealPath(env, argv[0], context->config, context->param);
            CHECK_RETURN_SET_E(OK == code, err);
        }
        // when the first parameter is string, the pos of attachName is 1; otherwise, it is 2
        size_t pos = isString ? 1 : 2;
        errCode = Convert2Value(env, argv[pos++], context->attachName);
        CHECK_RETURN_SET_E(napi_ok == errCode && !context->attachName.empty(),
            std::make_shared<ParamError>("attachName cannot be empty."));
        context->waitTime = WAIT_TIME_DEFAULT;
        if (pos < argc) {
            errCode = Convert2ValueExt(env, argv[pos], context->waitTime);
            CHECK_RETURN_SET_E(napi_ok == errCode && context->waitTime >= 1 && context->waitTime <= WAIT_TIME_LIMIT,
                std::make_shared<ParamError>("waitTime cannot exceed 300s."));
        }
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->rdbStore != nullptr);
        auto res = context->rdbStore->Attach(
            GetRdbStoreConfig(context->config, context->param), context->attachName, context->waitTime);
        context->rdbStore = nullptr;
        context->attachedNum = res.second;
        return res.first;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = Convert2JSValue(env, context->attachedNum);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::Detach(napi_env env, napi_callback_info info)
{
    struct DetachContext : public RdbStoreContextBase {
        std::string attachName;
        int32_t waitTime;
        int32_t attachedNum;
    };
    auto context = std::make_shared<DetachContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        // this interface has 1 or 2 parameters
        CHECK_RETURN_SET_E(argc == 1 || argc == 2, std::make_shared<ParamNumError>("1 or 2"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        int32_t errCode = Convert2Value(env, argv[0], context->attachName);
        CHECK_RETURN_SET_E(napi_ok == errCode && !context->attachName.empty(),
            std::make_shared<ParamError>("attachName cannot be empty."));
        context->waitTime = WAIT_TIME_DEFAULT;
        // parse waitTime when the number of parameters is 2
        if (argc == 2) {
            errCode = Convert2ValueExt(env, argv[1], context->waitTime);
            CHECK_RETURN_SET_E(napi_ok == errCode && context->waitTime < WAIT_TIME_LIMIT,
                std::make_shared<ParamError>("waitTime cannot exceed 300s."));
        }
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->rdbStore != nullptr);
        auto res = context->rdbStore->Detach(context->attachName, context->waitTime);
        context->rdbStore = nullptr;
        context->attachedNum = res.second;
        return res.first;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = Convert2JSValue(env, context->attachedNum);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::GetPath(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(
        env, rdbStoreProxy && rdbStoreProxy->GetInstance(), std::make_shared<ParamError>("RdbStore", "valid"));
    std::string path = rdbStoreProxy->GetInstance()->GetPath();
    LOG_DEBUG("RdbStoreProxy::GetPath path is empty ? %{public}d", path.empty());
    return JSUtils::Convert2JSValue(env, path);
}

napi_value RdbStoreProxy::BeginTransaction(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr));
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(env, rdbStoreProxy != nullptr, std::make_shared<ParamError>("RdbStore", "valid"));
    RDB_NAPI_ASSERT(
        env, rdbStoreProxy->GetInstance() != nullptr, std::make_shared<InnerError>(NativeRdb::E_ALREADY_CLOSED));
    int errCode = rdbStoreProxy->GetInstance()->BeginTransaction();
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    LOG_DEBUG("RdbStoreProxy::BeginTransaction end, errCode is:%{public}d", errCode);
    return nullptr;
}

napi_value RdbStoreProxy::BeginTrans(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 0, std::make_shared<ParamNumError>("0"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->rdbStore != nullptr);
        LOG_DEBUG("RdbStoreProxy::BeginTrans start");
        auto status = E_ERROR;
        std::tie(status, context->intOutput) = context->rdbStore->BeginTrans();
        context->rdbStore = nullptr;
        return status;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->intOutput, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(!(context->error) || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::RollBack(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr));
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(env, rdbStoreProxy != nullptr, std::make_shared<ParamError>("RdbStore", "valid"));
    RDB_NAPI_ASSERT(
        env, rdbStoreProxy->GetInstance() != nullptr, std::make_shared<InnerError>(NativeRdb::E_ALREADY_CLOSED));
    int errCode = rdbStoreProxy->GetInstance()->RollBack();
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    LOG_DEBUG("RdbStoreProxy::RollBack end, errCode is:%{public}d", errCode);
    return nullptr;
}

napi_value RdbStoreProxy::RollBackByTxId(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 0 || argc == 1, std::make_shared<ParamNumError>("1 to 2"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        if (argc == 1) {
            CHECK_RETURN(OK == ParseTxId(env, argv[0], context));
        }
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::roll back by txId start async.");
        CHECK_RETURN_ERR(context->rdbStore != nullptr);
        auto rdbStore = std::move(context->rdbStore);
        return rdbStore->RollBack(context->txId);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::Commit(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    size_t argc = MAX_INPUT_COUNT;
    napi_value argv[MAX_INPUT_COUNT] = { nullptr };
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisObj, nullptr);
    RDB_NAPI_ASSERT(
        env, status == napi_ok && (argc == 0 || argc == 1), std::make_shared<ParamError>("parameter", "1 to 2"));
    auto context = std::make_shared<RdbStoreContext>();
    RDB_NAPI_ASSERT(env, OK == ParserThis(env, thisObj, context), context->error);
    if (argc == 0) {
        int errCode = context->rdbStore->Commit();
        RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
        LOG_DEBUG("RdbStoreProxy::Commit end, errCode is:%{public}d.", errCode);
        return nullptr;
    }

    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN(OK == ParseTxId(env, argv[0], context));
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::commit by txId start async.");
        CHECK_RETURN_ERR(context != nullptr);
        auto rdbStore = std::move(context->rdbStore);
        return rdbStore->Commit(context->txId);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::QueryByStep(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 1 || argc == 2, std::make_shared<ParamNumError>("1 or 2"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        if (IsNapiTypeString(env, argc, argv, 0)) {
            context->isQuerySql = true;
            CHECK_RETURN(OK == ParseSql(env, argv[0], context));
            if (argc == 2) {
                CHECK_RETURN(OK == ParseBindArgs(env, argv[1], context));
            }
        } else {
            CHECK_RETURN(OK == ParsePredicates(env, argv[0], context));
            if (argc == 2) {
                CHECK_RETURN(OK == ParseColumns(env, argv[1], context));
            }
        }
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->rdbStore != nullptr);
        auto rdbStore = std::move(context->rdbStore);
        context->resultSet = context->isQuerySql ? rdbStore->QueryByStep(context->sql, context->bindArgs)
                                                 : rdbStore->QueryByStep(*(context->rdbPredicates), context->columns);
        // If the API version is greater than or equal to 16, throw E_ALREADY_CLOSED.
        return (context->resultSet != nullptr) ? E_OK : (JSUtils::GetHapVersion() >= 16) ? E_ALREADY_CLOSED : E_ERROR;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = ResultSetProxy::NewInstance(env, std::move(context->resultSet));
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);
    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::GetVersion(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(env, rdbStoreProxy != nullptr, std::make_shared<ParamError>("RdbStore", "valid"));
    RDB_NAPI_ASSERT(
        env, rdbStoreProxy->GetInstance() != nullptr, std::make_shared<InnerError>(NativeRdb::E_ALREADY_CLOSED));
    int32_t version = 0;
    int out = rdbStoreProxy->GetInstance()->GetVersion(version);
    RDB_NAPI_ASSERT(env, out == E_OK, std::make_shared<InnerError>(out));
    LOG_DEBUG("RdbStoreProxy::GetVersion out is : %{public}d", out);
    return JSUtils::Convert2JSValue(env, version);
}

napi_value RdbStoreProxy::GetRebuilt(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(env, rdbStoreProxy != nullptr, std::make_shared<ParamError>("RdbStore", "valid"));
    RDB_NAPI_ASSERT(
        env, rdbStoreProxy->GetInstance() != nullptr, std::make_shared<InnerError>(NativeRdb::E_ALREADY_CLOSED));
    auto rebuilt = RebuiltType::NONE;
    rdbStoreProxy->GetInstance()->GetRebuilt(rebuilt);
    return JSUtils::Convert2JSValue(env, (uint32_t)rebuilt);
}

napi_value RdbStoreProxy::SetVersion(napi_env env, napi_callback_info info)
{
    napi_value thiz = nullptr;
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thiz);
    RDB_NAPI_ASSERT(env, rdbStoreProxy != nullptr, std::make_shared<ParamError>("RdbStore", "valid"));
    RDB_NAPI_ASSERT(
        env, rdbStoreProxy->GetInstance() != nullptr, std::make_shared<InnerError>(NativeRdb::E_ALREADY_CLOSED));
    int32_t version = 0;
    napi_get_value_int32(env, args[0], &version);
    RDB_NAPI_ASSERT(env, version > 0, std::make_shared<ParamError>("version", "> 0"));
    int out = rdbStoreProxy->GetInstance()->SetVersion(version);
    RDB_NAPI_ASSERT(env, out == E_OK, std::make_shared<InnerError>(out));
    LOG_DEBUG("RdbStoreProxy::SetVersion out is : %{public}d", out);
    return nullptr;
}

napi_value RdbStoreProxy::Restore(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 0 || argc == 1, std::make_shared<ParamNumError>("0 to 2"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        if (argc == 1) {
            CHECK_RETURN(OK == ParseSrcName(env, argv[0], context));
        }
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::Restore Async.");
        CHECK_RETURN_ERR(context->rdbStore != nullptr);
        auto rdbStore = std::move(context->rdbStore);
        return rdbStore->Restore(context->srcName, context->newKey);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
        LOG_DEBUG("RdbStoreProxy::Restore end.");
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

#if !defined(CROSS_PLATFORM)
void RdbStoreProxy::AddDistributedFunctions(std::vector<napi_property_descriptor> &properties)
{
    properties.push_back(DECLARE_NAPI_FUNCTION("remoteQuery", RemoteQuery));
    properties.push_back(DECLARE_NAPI_FUNCTION("setDistributedTables", SetDistributedTables));
    properties.push_back(DECLARE_NAPI_FUNCTION("obtainDistributedTableName", ObtainDistributedTableName));
    properties.push_back(DECLARE_NAPI_FUNCTION("sync", Sync));
    properties.push_back(DECLARE_NAPI_FUNCTION("cloudSync", CloudSync));
    properties.push_back(DECLARE_NAPI_FUNCTION("getModifyTime", GetModifyTime));
    properties.push_back(DECLARE_NAPI_FUNCTION("cleanDirtyData", CleanDirtyData));
    properties.push_back(DECLARE_NAPI_FUNCTION("on", OnEvent));
    properties.push_back(DECLARE_NAPI_FUNCTION("off", OffEvent));
    properties.push_back(DECLARE_NAPI_FUNCTION("emit", Notify));
    properties.push_back(DECLARE_NAPI_FUNCTION("querySharingResource", QuerySharingResource));
    properties.push_back(DECLARE_NAPI_FUNCTION("lockRow", LockRow));
    properties.push_back(DECLARE_NAPI_FUNCTION("unlockRow", UnlockRow));
    properties.push_back(DECLARE_NAPI_FUNCTION("queryLockedRow", QueryLockedRow));
    properties.push_back(DECLARE_NAPI_FUNCTION("lockCloudContainer", LockCloudContainer));
    properties.push_back(DECLARE_NAPI_FUNCTION("unlockCloudContainer", UnlockCloudContainer));
}

napi_value RdbStoreProxy::SetDistributedTables(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(1 <= argc && argc <= 3, std::make_shared<ParamNumError>("1 - 4"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseTablesName(env, argv[0], context));
        CHECK_RETURN(OK == ParseDistributedTypeArg(env, argc, argv, context));
        CHECK_RETURN(OK == ParseDistributedConfigArg(env, argc, argv, context));
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->rdbStore != nullptr);
        auto rdbStore = std::move(context->rdbStore);
        return rdbStore->SetDistributedTables(
            context->tablesNames, context->distributedType, context->distributedConfig);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::ObtainDistributedTableName(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseDevice(env, argv[0], context));
        CHECK_RETURN(OK == ParseTableName(env, argv[1], context));
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::ObtainDistributedTableName Async.");
        CHECK_RETURN_ERR(context->rdbStore != nullptr);
        int errCode = E_ERROR;
        context->tableName =
            context->rdbStore->ObtainDistributedTableName(context->device, context->tableName, errCode);
        context->rdbStore = nullptr;
        return errCode;
    };
    auto output = [context](napi_env env, napi_value &result) {
        std::string table = context->tableName;
        napi_status status = napi_create_string_utf8(env, table.c_str(), table.length(), &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
        LOG_DEBUG("RdbStoreProxy::ObtainDistributedTableName end.");
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::Sync(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseSyncModeArg(env, argv[0], context));
        CHECK_RETURN(OK == ParsePredicates(env, argv[1], context));
    };
    context->SetAction(env, info, std::move(input), nullptr, nullptr);
    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
    auto queue = obj->queue_;
    napi_value promise = nullptr;
    auto defer = context->defer_;
    auto callback = context->callback_;
    context->callback_ = nullptr;
    if (callback == nullptr) {
        napi_status status = napi_create_promise(env, &defer, &promise);
        RDB_NAPI_ASSERT_BASE(env, status == napi_ok,
            std::make_shared<InnerError>("failed(" + std::to_string(status) + ") to create promise"), nullptr);
    } else {
        napi_get_undefined(env, &promise);
    }
    auto predicates = *context->predicatesProxy->GetPredicates();
    auto exec = [queue, defer, callback, predicates, rdbStore = std::move(context->rdbStore),
                    enumArg = context->enumArg]() mutable {
        SyncOption option{ static_cast<DistributedRdb::SyncMode>(enumArg), false };
        auto ret = rdbStore->Sync(option, predicates, [queue, defer, callback](const SyncResult &result) {
            auto args = [result](napi_env env, int &argc, napi_value *argv) {
                argv[1] = JSUtils::Convert2JSValue(env, result);
            };
            callback ? queue->AsyncCall({ callback }, args) : queue->AsyncPromise({ defer }, args);
        });
        if (ret != NativeRdb::E_OK) {
            auto args = [ret](napi_env env, int &argc, napi_value *argv) mutable {
                SetBusinessError(env, std::make_shared<InnerError>(ret), &argv[0]);
            };
            callback ? queue->AsyncCall({ callback }, args) : queue->AsyncPromise({ defer }, args);
        }
    };
    queue->Execute(std::move(exec));
    context = nullptr;
    return promise;
}

void RdbStoreProxy::SetBusinessError(napi_env env, std::shared_ptr<Error> error, napi_value *businessError)
{
    if (error != nullptr) {
        napi_value code = nullptr;
        napi_value msg = nullptr;
        napi_create_int32(env, error->GetCode(), &code);
        napi_create_string_utf8(env, error->GetMessage().c_str(), NAPI_AUTO_LENGTH, &msg);
        napi_create_error(env, code, msg, businessError);
    }
}

InputAction GetCloudSyncInput(std::shared_ptr<RdbStoreContext> context)
{
    return [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        // The number of parameters should be in range (1, 5)
        CHECK_RETURN_SET_E(argc > 1 && argc < 5, std::make_shared<ParamNumError>("2 - 4"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseCloudSyncModeArg(env, argv[0], context));
        uint32_t index = 1;
        bool isArray = false;
        napi_is_array(env, argv[index], &isArray);
        if (isArray) {
            CHECK_RETURN(OK == ParseTablesName(env, argv[index], context));
            index++;
        } else {
            auto status = napi_unwrap(env, argv[index], reinterpret_cast<void **>(&context->predicatesProxy));
            if (status == napi_ok && context->predicatesProxy != nullptr) {
                RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
                CHECK_RETURN_SET_E(obj != nullptr && obj->IsSystemAppCalled(), std::make_shared<NonSystemError>());
                context->rdbPredicates = context->predicatesProxy->GetPredicates();
                index++;
            }
        }
        CHECK_RETURN(OK == ParseCloudSyncCallback(env, argv[index++], context));
        CHECK_RETURN_SET_E(index == argc - 1 || index == argc, std::make_shared<ParamNumError>("2 - 4"));
        if (index == argc - 1) {
            CHECK_RETURN(OK == ParseCallback(env, argv[index], context));
        }
    };
}

napi_value RdbStoreProxy::CloudSync(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = GetCloudSyncInput(context);
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::CloudSync Async.");
        auto *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        SyncOption option;
        option.mode = static_cast<DistributedRdb::SyncMode>(context->syncMode);
        option.isBlock = false;
        CHECK_RETURN_ERR(obj != nullptr && context->rdbStore != nullptr);
        auto rdbStore = std::move(context->rdbStore);
        auto async = [queue = obj->queue_, callback = context->asyncHolder](const Details &details) {
            if (queue == nullptr || callback == nullptr) {
                return;
            }
            bool repeat = !details.empty() && details.begin()->second.progress != DistributedRdb::SYNC_FINISH;
            queue->AsyncCallInOrder({ callback, repeat }, [details](napi_env env, int &argc, napi_value *argv) -> void {
                argc = 1;
                argv[0] = details.empty() ? nullptr : JSUtils::Convert2JSValue(env, details.begin()->second);
            });
        };
        if (context->rdbPredicates == nullptr) {
            context->execCode_ = rdbStore->Sync(option, context->tablesNames, async);
        } else {
            context->execCode_ = rdbStore->Sync(option, *(context->rdbPredicates), async);
        }
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) {
        LOG_DEBUG("RdbStoreProxy::CloudSync output.");
        if (context->execCode_ != E_OK && context->asyncHolder != nullptr) {
            napi_delete_reference(env, context->asyncHolder);
        }
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAll(env, info, input, exec, output);
    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::GetModifyTime(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::GetModifyTime start.");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 3, std::make_shared<ParamNumError>("3 - 4"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseTableName(env, argv[0], context));
        CHECK_RETURN(OK == ParseColumnName(env, argv[1], context));
        CHECK_RETURN(OK == ParsePrimaryKey(env, argv[2], context));
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::GetModifyTime Async.");
        CHECK_RETURN_ERR(context->rdbStore != nullptr);
        context->modifyTime = context->rdbStore->GetModifyTime(context->tableName, context->columnName, context->keys);
        context->rdbStore = nullptr;
        return context->modifyTime.empty() ? E_ERROR : E_OK;
    };
    auto output = [context](napi_env env, napi_value &result) {
        LOG_DEBUG("RdbStoreProxy::GetModifyTime output.");
        result = JSUtils::Convert2JSValue(env, context->modifyTime);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::CleanDirtyData(napi_env env, napi_callback_info info)
{
    LOG_INFO("RdbStoreProxy::Clean start.");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc >= 1, std::make_shared<ParamNumError>("1 - 3"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseTableName(env, argv[0], context));
        if (argc == 2) {
            CHECK_RETURN(OK == ParseCursor(env, argv[1], context));
        }
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::CleanDirtyData Async.");
        CHECK_RETURN_ERR(context->rdbStore != nullptr);
        auto rdbStore = std::move(context->rdbStore);
        return rdbStore->CleanDirtyData(context->tableName, context->cursor);
    };

    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::OnRemote(napi_env env, size_t argc, napi_value *argv)
{
    napi_valuetype type = napi_undefined;
    int32_t mode = SubscribeMode::SUBSCRIBE_MODE_MAX;
    napi_get_value_int32(env, argv[0], &mode);
    bool valid = (mode >= 0 && mode < SubscribeMode::SUBSCRIBE_MODE_MAX);
    RDB_NAPI_ASSERT(env, valid, std::make_shared<ParamError>("type", "SubscribeType"));

    napi_typeof(env, argv[1], &type);
    RDB_NAPI_ASSERT(env, type == napi_function, std::make_shared<ParamError>("observer", "function"));

    bool result = std::any_of(observers_[mode].begin(), observers_[mode].end(),
        [argv](const auto &observer) { return *observer == argv[1]; });
    if (result) {
        LOG_INFO("Duplicate subscribe.");
        return nullptr;
    }
    SubscribeOption option;
    option.mode = static_cast<SubscribeMode>(mode);
    option.event = "dataChange";
    auto uvQueue = std::make_shared<UvQueue>(env);
    auto observer = std::make_shared<NapiRdbStoreObserver>(argv[1], uvQueue, mode);
    int errCode = E_OK;
    if (option.mode == SubscribeMode::LOCAL_DETAIL) {
        errCode = GetInstance()->SubscribeObserver(option, observer);
    } else {
        errCode = GetInstance()->Subscribe(option, observer.get());
    }
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    observers_[mode].push_back(observer);
    LOG_INFO("Subscribe success.");
    return nullptr;
}

napi_value RdbStoreProxy::RegisteredObserver(
    napi_env env, const DistributedRdb::SubscribeOption &option, napi_value callback)
{
    auto &observers = option.mode == SubscribeMode::LOCAL ? localObservers_ : localSharedObservers_;
    observers.try_emplace(option.event);
    auto &list = observers.find(option.event)->second;
    bool result =
        std::any_of(list.begin(), list.end(), [callback](const auto &observer) { return *observer == callback; });
    if (result) {
        LOG_INFO("Duplicate subscribe event: %{public}s", option.event.c_str());
        return nullptr;
    }

    auto uvQueue = std::make_shared<UvQueue>(env);
    auto localObserver = std::make_shared<NapiRdbStoreObserver>(callback, uvQueue);
    int errCode = GetInstance()->Subscribe(option, localObserver.get());
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    observers[option.event].push_back(localObserver);
    LOG_INFO("Subscribe success event: %{public}s", option.event.c_str());
    return nullptr;
}

napi_value RdbStoreProxy::OffRemote(napi_env env, size_t argc, napi_value *argv)
{
    napi_valuetype type = napi_undefined;
    napi_typeof(env, argv[0], &type);
    RDB_NAPI_ASSERT(env, type == napi_number, std::make_shared<ParamError>("type", "SubscribeType"));

    int32_t mode = SubscribeMode::SUBSCRIBE_MODE_MAX;
    napi_get_value_int32(env, argv[0], &mode);
    bool valid = (mode >= 0 && mode < SubscribeMode::SUBSCRIBE_MODE_MAX);
    RDB_NAPI_ASSERT(env, valid, std::make_shared<ParamError>("type", "SubscribeType"));

    bool isNotNull = argc >= 2 && !JSUtils::IsNull(env, argv[1]);
    if (isNotNull) {
        napi_typeof(env, argv[1], &type);
        RDB_NAPI_ASSERT(env, type == napi_function, std::make_shared<ParamError>("observer", "function"));
    }

    SubscribeOption option;
    option.mode = static_cast<SubscribeMode>(mode);
    option.event = "dataChange";
    for (auto it = observers_[mode].begin(); it != observers_[mode].end();) {
        if (*it == nullptr) {
            it = observers_[mode].erase(it);
            continue;
        }
        if (isNotNull && !(**it == argv[1])) {
            ++it;
            continue;
        }
        int errCode = E_OK;
        if (option.mode == SubscribeMode::LOCAL_DETAIL) {
            errCode = GetInstance()->UnsubscribeObserver(option, *it);
        } else {
            errCode = GetInstance()->UnSubscribe(option, it->get());
        }
        RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
        (*it)->Clear();
        it = observers_[mode].erase(it);
        LOG_DEBUG("Observer unsubscribe success");
    }
    return nullptr;
}

napi_value RdbStoreProxy::UnRegisteredObserver(
    napi_env env, const DistributedRdb::SubscribeOption &option, napi_value callback)
{
    auto &observers = option.mode == SubscribeMode::LOCAL ? localObservers_ : localSharedObservers_;
    auto obs = observers.find(option.event);
    if (obs == observers.end()) {
        LOG_INFO("Observer not found, event: %{public}s", option.event.c_str());
        return nullptr;
    }

    if (callback) {
        auto &list = obs->second;
        for (auto it = list.begin(); it != list.end(); it++) {
            if (**it == callback) {
                int errCode = GetInstance()->UnSubscribe(option, it->get());
                RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
                list.erase(it);
                break;
            }
        }
        if (list.empty()) {
            observers.erase(option.event);
        }
    } else {
        int errCode = GetInstance()->UnSubscribe(option, nullptr);
        RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
        observers.erase(option.event);
    }
    LOG_INFO("Unsubscribe success, event: %{public}s", option.event.c_str());
    return nullptr;
}

napi_value RdbStoreProxy::OnEvent(napi_env env, napi_callback_info info)
{
    size_t argc = 3;
    napi_value argv[3]{};
    napi_value self = nullptr;
    int32_t status = napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
    // 'argc == 3 || argc == 2' represents the number of parameters is three or two
    RDB_NAPI_ASSERT(env, status == napi_ok && (argc == 3 || argc == 2), std::make_shared<ParamNumError>("2 or 3"));

    auto proxy = GetNativeInstance(env, self);
    RDB_NAPI_ASSERT(env, proxy != nullptr, std::make_shared<ParamError>("RdbStore", "valid"));
    RDB_NAPI_ASSERT(env, proxy->GetInstance() != nullptr, std::make_shared<InnerError>(NativeRdb::E_ALREADY_CLOSED));

    std::string event;
    // 'argv[0]' represents a event
    status = JSUtils::Convert2Value(env, argv[0], event);
    RDB_NAPI_ASSERT(
        env, status == napi_ok && !event.empty(), std::make_shared<ParamError>("event", "a not empty string."));
    for (auto &eventInfo : onEventHandlers_) {
        if (eventInfo.event == event) {
            return (proxy->*(eventInfo.handle))(env, argc - 1, argv + 1);
        }
    }

    bool valueBool = false;
    status = JSUtils::Convert2Value(env, argv[1], valueBool);
    RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<ParamError>("interProcess", "a boolean."));
    napi_valuetype type = napi_undefined;
    // 'argv[2]' is observer function
    napi_typeof(env, argv[2], &type);
    RDB_NAPI_ASSERT(env, type == napi_function, std::make_shared<ParamError>("observer", "function"));
    SubscribeOption option;
    option.event = event;
    option.mode = valueBool ? SubscribeMode::LOCAL_SHARED : SubscribeMode::LOCAL;
    // 'argv[2]' represents a callback function
    return proxy->RegisteredObserver(env, option, argv[2]);
}

napi_value RdbStoreProxy::OffEvent(napi_env env, napi_callback_info info)
{
    size_t argc = 3;
    // 'argv[3]' represents an array containing three elements
    napi_value argv[3] = { nullptr };
    napi_value self = nullptr;
    int32_t status = napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
    // '1 <= argc && argc <= 3' represents the number of parameters is 1 - 3
    RDB_NAPI_ASSERT(env, status == napi_ok && 1 <= argc && argc <= 3, std::make_shared<ParamNumError>("1 - 3"));

    auto proxy = GetNativeInstance(env, self);
    RDB_NAPI_ASSERT(env, proxy != nullptr, std::make_shared<ParamError>("RdbStore", "valid"));
    RDB_NAPI_ASSERT(env, proxy->GetInstance() != nullptr, std::make_shared<InnerError>(NativeRdb::E_ALREADY_CLOSED));

    std::string event;
    status = JSUtils::Convert2Value(env, argv[0], event);
    RDB_NAPI_ASSERT(
        env, status == napi_ok && !event.empty(), std::make_shared<ParamError>("event", "a not empty string."));
    for (auto &eventInfo : offEventHandlers_) {
        if (eventInfo.event == event) {
            return (proxy->*(eventInfo.handle))(env, argc - 1, argv + 1);
        }
    }

    bool valueBool = false;
    status = JSUtils::Convert2Value(env, argv[1], valueBool);
    RDB_NAPI_ASSERT(env, status == napi_ok, std::make_shared<ParamError>("interProcess", "a boolean."));

    // 'argc == 3' represents determine whether the value of variable 'argc' is equal to '3'
    if (argc == 3) {
        napi_valuetype type = napi_undefined;
        // 'argv[2]' represents a callback function
        napi_typeof(env, argv[2], &type);
        RDB_NAPI_ASSERT(env, type == napi_function, std::make_shared<ParamError>("observer", "function"));
    }
    SubscribeOption option;
    option.event = event;
    valueBool ? option.mode = SubscribeMode::LOCAL_SHARED : option.mode = SubscribeMode::LOCAL;
    // 'argv[2]' represents a callback function, 'argc == 3' represents determine if 'argc' is equal to '3'
    return proxy->UnRegisteredObserver(env, option, argc == 3 ? argv[2] : nullptr);
}

napi_value RdbStoreProxy::Notify(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1]{};
    napi_value self = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
    RDB_NAPI_ASSERT(env, status == napi_ok && argc == 1, std::make_shared<ParamNumError>("1"));
    auto *proxy = GetNativeInstance(env, self);
    RDB_NAPI_ASSERT(env, proxy != nullptr, std::make_shared<ParamError>("RdbStore", "valid"));
    RDB_NAPI_ASSERT(env, proxy->GetInstance() != nullptr, std::make_shared<InnerError>(NativeRdb::E_ALREADY_CLOSED));
    int errCode = proxy->GetInstance()->Notify(JSUtils::Convert2String(env, argv[0]));
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    return nullptr;
}

napi_value RdbStoreProxy::QuerySharingResource(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc > 0 && argc < 4, std::make_shared<ParamNumError>("1 to 3"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        // 'argv[0]' represents a RdbPredicates parameter
        CHECK_RETURN(OK == ParsePredicates(env, argv[0], context));
        // 'argv[1]' represents an optional std::vector<std::string> parameter
        CHECK_RETURN(argc < 2 || JSUtils::IsNull(env, argv[1]) || OK == ParseColumns(env, argv[1], context));
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_SET_E(obj != nullptr && obj->IsSystemAppCalled(), std::make_shared<NonSystemError>());
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->rdbStore != nullptr);
        auto status = E_ERROR;
        std::tie(status, context->resultSet) =
            context->rdbStore->QuerySharingResource(*(context->rdbPredicates), context->columns);
        context->rdbStore = nullptr;
        LOG_DEBUG("RdbStoreProxy::QuerySharingResource resultSet is nullptr:%{public}d, status:%{public}d",
            context->resultSet == nullptr, status);
        return (status == E_OK && context->resultSet != nullptr) ? E_OK : E_ERROR;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = ResultSetProxy::NewInstance(env, std::move(context->resultSet));
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
        LOG_DEBUG("RdbStoreProxy::QuerySharingResource end.");
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::RegisterSyncCallback(napi_env env, size_t argc, napi_value *argv)
{
    napi_valuetype type = napi_undefined;
    napi_typeof(env, argv[0], &type);
    RDB_NAPI_ASSERT(env, type == napi_function, std::make_shared<ParamError>("progress", "function"));
    bool result = std::any_of(
        syncObservers_.begin(), syncObservers_.end(), [argv](const auto &observer) { return *observer == argv[0]; });
    if (result) {
        LOG_DEBUG("Duplicate subscribe.");
        return nullptr;
    }
    auto observer = std::make_shared<SyncObserver>(env, argv[0], queue_);
    int errCode = GetInstance()->RegisterAutoSyncCallback(observer);
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    syncObservers_.push_back(std::move(observer));
    LOG_INFO("Progress subscribe success.");
    return nullptr;
}

napi_value RdbStoreProxy::UnregisterSyncCallback(napi_env env, size_t argc, napi_value *argv)
{
    napi_valuetype type;
    bool isNotNull = argc >= 1 && !JSUtils::IsNull(env, argv[0]);
    if (isNotNull) {
        napi_typeof(env, argv[0], &type);
        RDB_NAPI_ASSERT(env, type == napi_function, std::make_shared<ParamError>("progress", "function"));
    }

    for (auto it = syncObservers_.begin(); it != syncObservers_.end();) {
        if (*it == nullptr) {
            it = syncObservers_.erase(it);
            continue;
        }
        if (isNotNull && !(**it == argv[0])) {
            ++it;
            continue;
        }

        int errCode = GetInstance()->UnregisterAutoSyncCallback(*it);
        RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
        (*it)->Clear();
        it = syncObservers_.erase(it);
        LOG_DEBUG("Observer unsubscribe success.");
    }
    return nullptr;
}

napi_value RdbStoreProxy::OnStatistics(napi_env env, size_t argc, napi_value *argv)
{
    napi_valuetype type = napi_undefined;
    napi_typeof(env, argv[0], &type);
    RDB_NAPI_ASSERT(env, type == napi_function, std::make_shared<ParamError>("statistics", "function"));
    bool result = std::any_of(statisticses_.begin(), statisticses_.end(),
        [argv](std::shared_ptr<NapiStatisticsObserver> obs) { return obs && *obs == argv[0]; });
    if (result) {
        LOG_DEBUG("Duplicate subscribe.");
        return nullptr;
    }
    auto observer = std::make_shared<NapiStatisticsObserver>(env, argv[0], queue_);
    int errCode = DistributedRdb::SqlStatistic::Subscribe(observer);
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    statisticses_.push_back(std::move(observer));
    LOG_DEBUG("Statistics subscribe success.");
    return nullptr;
}

napi_value RdbStoreProxy::OffStatistics(napi_env env, size_t argc, napi_value *argv)
{
    napi_valuetype type;
    napi_typeof(env, argv[0], &type);
    RDB_NAPI_ASSERT(env, type == napi_function || type == napi_undefined || type == napi_null,
        std::make_shared<ParamError>("statistics", "function"));

    auto it = statisticses_.begin();
    while (it != statisticses_.end()) {
        if (*it == nullptr) {
            it = statisticses_.erase(it);
            LOG_WARN("statisticsObserver is nullptr.");
            continue;
        }
        if (type == napi_function && !(**it == argv[0])) {
            ++it;
            continue;
        }
        int errCode = DistributedRdb::SqlStatistic::Unsubscribe(*it);
        RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
        (*it)->Clear();
        it = statisticses_.erase(it);
    }
    return nullptr;
}

RdbStoreProxy::SyncObserver::SyncObserver(
    napi_env env, napi_value callback, std::shared_ptr<AppDataMgrJsKit::UvQueue> queue)
    : env_(env), queue_(queue)
{
    napi_create_reference(env, callback, 1, &callback_);
}

RdbStoreProxy::SyncObserver::~SyncObserver()
{
}

void RdbStoreProxy::SyncObserver::Clear()
{
    if (callback_ == nullptr) {
        return;
    }
    napi_delete_reference(env_, callback_);
    callback_ = nullptr;
}

bool RdbStoreProxy::SyncObserver::operator==(napi_value value)
{
    return JSUtils::Equal(env_, callback_, value);
}

void RdbStoreProxy::SyncObserver::ProgressNotification(const Details &details)
{
    if (queue_ == nullptr) {
        return;
    }
    queue_->AsyncCall({ [observer = shared_from_this()](napi_env env) -> napi_value {
        if (observer->callback_ == nullptr) {
            return nullptr;
        }
        napi_value callback = nullptr;
        napi_get_reference_value(env, observer->callback_, &callback);
        return callback;
    } },
        [syncDetails = std::move(details)](napi_env env, int &argc, napi_value *argv) {
            argc = 1;
            argv[0] = syncDetails.empty() ? nullptr : JSUtils::Convert2JSValue(env, syncDetails.begin()->second);
        });
}

napi_value RdbStoreProxy::ModifyLockStatus(napi_env env, napi_callback_info info, bool isLock)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc >= 1, std::make_shared<ParamNumError>("1"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParsePredicates(env, argv[0], context));
    };
    auto exec = [context, isLock]() -> int {
        CHECK_RETURN_ERR(context->rdbStore != nullptr && context->rdbPredicates != nullptr);
        auto rdbStore = std::move(context->rdbStore);
        return rdbStore->ModifyLockStatus(*(context->rdbPredicates), isLock);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::LockRow(napi_env env, napi_callback_info info)
{
    return ModifyLockStatus(env, info, true);
}

napi_value RdbStoreProxy::UnlockRow(napi_env env, napi_callback_info info)
{
    return ModifyLockStatus(env, info, false);
}

napi_value RdbStoreProxy::QueryLockedRow(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN_SET_E(argc >= 1, std::make_shared<ParamNumError>("1 to 2"));
        CHECK_RETURN(OK == ParsePredicates(env, argv[0], context));
        if (argc >= 2) {
            CHECK_RETURN(OK == ParseColumns(env, argv[1], context));
        }
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->rdbStore != nullptr && context->rdbPredicates != nullptr);
        context->rdbPredicates->BeginWrap()->EqualTo(AbsRdbPredicates::LOCK_STATUS, AbsRdbPredicates::LOCKED)->Or();
        context->rdbPredicates->EqualTo(AbsRdbPredicates::LOCK_STATUS, AbsRdbPredicates::LOCK_CHANGED)->EndWrap();
        context->resultSet = context->rdbStore->QueryByStep(*(context->rdbPredicates), context->columns);
        context->rdbStore = nullptr;
        // If the API version is greater than or equal to 16, throw E_ALREADY_CLOSED.
        return (context->resultSet != nullptr) ? E_OK : (JSUtils::GetHapVersion() >= 16) ? E_ALREADY_CLOSED : E_ERROR;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = ResultSetProxy::NewInstance(env, std::move(context->resultSet));
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::LockCloudContainer(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::LockCloudContainer start.");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN(OK == ParserThis(env, self, context));
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_SET_E(obj != nullptr && obj->IsSystemAppCalled(), std::make_shared<NonSystemError>());
    };

    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::LockCloudContainer Async.");
        CHECK_RETURN_ERR(context->rdbStore != nullptr);
        auto rdbStore = std::move(context->rdbStore);
        auto result = rdbStore->LockCloudContainer();
        context->expiredTime = result.second;
        return result.first;
    };

    auto output = [context](napi_env env, napi_value &res) {
        auto status = napi_create_uint32(env, context->expiredTime, &res);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::UnlockCloudContainer(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::UnlockCloudContainer start.");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN(OK == ParserThis(env, self, context));
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_SET_E(obj != nullptr && obj->IsSystemAppCalled(), std::make_shared<NonSystemError>());
    };
    auto exec = [context]() {
        LOG_DEBUG("RdbStoreProxy::UnlockCloudContainer Async.");
        CHECK_RETURN_ERR(context->rdbStore != nullptr);
        auto rdbStore = std::move(context->rdbStore);
        return rdbStore->UnlockCloudContainer();
    };
    auto output = [context](napi_env env, napi_value &result) {
        auto status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}
#endif

napi_value RdbStoreProxy::Close(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN(OK == ParserThis(env, self, context));
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        obj->UnregisterAll();
        obj->SetInstance(nullptr);
    };
    auto exec = [context]() -> int {
        context->rdbStore = nullptr;
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value RdbStoreProxy::CreateTransaction(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<CreateTransactionContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseTransactionOptions(env, argc, argv, context));
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->rdbStore != nullptr);
        int32_t code = E_ERROR;
        std::tie(code, context->transaction) =
            context->StealRdbStore()->CreateTransaction(context->transactionOptions.transactionType);
        if (code != E_OK) {
            context->transaction = nullptr;
            return code;
        }
        return context->transaction != nullptr ? OK : E_ERROR;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = TransactionProxy::NewInstance(env, context->transaction);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}
} // namespace RelationalStoreJsKit
} // namespace OHOS