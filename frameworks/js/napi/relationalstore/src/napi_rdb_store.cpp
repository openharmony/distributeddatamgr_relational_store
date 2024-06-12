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

#include <cinttypes>
#include <string>
#include <vector>
#include <algorithm>

#include "js_native_api_types.h"
#include "js_utils.h"
#include "napi_rdb_js_utils.h"
#include "logger.h"
#include "napi_async_call.h"
#include "napi_rdb_error.h"
#include "napi_rdb_predicates.h"
#include "napi_rdb_trace.h"
#include "napi_result_set.h"
#include "rdb_errno.h"
#include "securec.h"

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
#include "rdb_utils.h"
using namespace OHOS::DataShare;
#endif

using namespace OHOS::Rdb;
using namespace OHOS::NativeRdb;
using namespace OHOS::AppDataMgrJsKit;
using namespace OHOS::AppDataMgrJsKit::JSUtils;

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
using OHOS::DistributedRdb::SubscribeMode;
using OHOS::DistributedRdb::SubscribeOption;
using OHOS::DistributedRdb::SyncOption;

using OHOS::DistributedRdb::SyncResult;
using OHOS::DistributedRdb::Details;
#endif

namespace OHOS {
namespace RelationalStoreJsKit {

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
struct PredicatesProxy {
    std::shared_ptr<DataShareAbsPredicates> predicates_;
};
#endif
struct RdbStoreContext : public ContextBase {
    std::string device;
    std::string tableName;
    std::vector<std::string> tablesNames;
    std::string whereClause;
    std::string sql;
    RdbPredicatesProxy *predicatesProxy;
    std::vector<std::string> columns;
    ValuesBucket valuesBucket;
    std::vector<ValuesBucket> valuesBuckets;
    std::map<std::string, ValueObject> numberMaps;
    std::vector<ValueObject> bindArgs;
    int64_t int64Output;
    int intOutput;
    ValueObject sqlExeOutput;
    std::vector<uint8_t> newKey;
    std::shared_ptr<ResultSet> resultSet;
    std::string aliasName;
    std::string pathName;
    std::string srcName;
    std::string columnName;
    int32_t enumArg;
    int32_t distributedType;
    int32_t syncMode;
    uint64_t cursor = UINT64_MAX;
    int64_t txId = 0;
    DistributedRdb::DistributedConfig distributedConfig;
    napi_ref asyncHolder = nullptr;
    NativeRdb::ConflictResolution conflictResolution;
    DistributedRdb::SyncResult syncResult;
    std::shared_ptr<RdbPredicates> rdbPredicates = nullptr;
    std::vector<NativeRdb::RdbStore::PRIKey> keys;
    std::map<RdbStore::PRIKey, RdbStore::Date> modifyTime;
    bool isQuerySql = false;

    RdbStoreContext()
        : predicatesProxy(nullptr), int64Output(0), intOutput(0), enumArg(-1),
          distributedType(DistributedRdb::DistributedTableType::DISTRIBUTED_DEVICE),
          syncMode(DistributedRdb::SyncMode::PUSH),
          conflictResolution(ConflictResolution::ON_CONFLICT_NONE)
    {
    }
    virtual ~RdbStoreContext()
    {
    }
};

RdbStoreProxy::RdbStoreProxy()
{
}

RdbStoreProxy::~RdbStoreProxy()
{
    LOG_DEBUG("RdbStoreProxy destructor");
    auto rdbStore = GetInstance();
    if (rdbStore == nullptr) {
        return;
    }
    for (int32_t mode = DistributedRdb::REMOTE; mode < DistributedRdb::LOCAL; mode++) {
        for (auto &obs : observers_[mode]) {
            if (obs == nullptr) {
                continue;
            }
            rdbStore->UnSubscribe({ static_cast<SubscribeMode>(mode) }, obs.get());
        }
    }
    for (const auto &[event, observers] : localObservers_) {
        for (const auto &obs : observers) {
            if (obs == nullptr) {
                continue;
            }
            rdbStore->UnSubscribe({ static_cast<SubscribeMode>(DistributedRdb::LOCAL), event }, obs.get());
        }
    }
    for (const auto &[event, observers] : localSharedObservers_) {
        for (const auto &obs : observers) {
            if (obs == nullptr) {
                continue;
            }
            rdbStore->UnSubscribe({ static_cast<SubscribeMode>(DistributedRdb::LOCAL_SHARED), event }, obs.get());
        }
    }
    for (const auto &obs : syncObservers_) {
        rdbStore->UnregisterAutoSyncCallback(obs);
    }
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
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
            DECLARE_NAPI_FUNCTION("remoteQuery", RemoteQuery),
            DECLARE_NAPI_FUNCTION("setDistributedTables", SetDistributedTables),
            DECLARE_NAPI_FUNCTION("obtainDistributedTableName", ObtainDistributedTableName),
            DECLARE_NAPI_FUNCTION("sync", Sync),
            DECLARE_NAPI_FUNCTION("cloudSync", CloudSync),
            DECLARE_NAPI_FUNCTION("getModifyTime", GetModifyTime),
            DECLARE_NAPI_FUNCTION("cleanDirtyData", CleanDirtyData),
            DECLARE_NAPI_FUNCTION("on", OnEvent),
            DECLARE_NAPI_FUNCTION("off", OffEvent),
            DECLARE_NAPI_FUNCTION("emit", Notify),
            DECLARE_NAPI_FUNCTION("querySharingResource", QuerySharingResource),
            DECLARE_NAPI_FUNCTION("lockRow", LockRow),
            DECLARE_NAPI_FUNCTION("unlockRow", UnlockRow),
            DECLARE_NAPI_FUNCTION("queryLockedRow", QueryLockedRow),
#endif
        };
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
        if (data != hint) {
            LOG_ERROR("RdbStoreProxy memory corrupted! data:0x%016" PRIXPTR "hint:0x%016" PRIXPTR,
                uintptr_t(data), uintptr_t(hint));
            return;
        }
        RdbStoreProxy *proxy = reinterpret_cast<RdbStoreProxy *>(data);
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
    return self;
}

napi_value RdbStoreProxy::NewInstance(napi_env env, std::shared_ptr<NativeRdb::RdbStore> value, bool isSystemAppCalled)
{
    if (value == nullptr) {
        LOG_ERROR("value is nullptr ? %{public}d", (value == nullptr));
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
    if (proxy == nullptr) {
        LOG_ERROR("RdbStoreProxy::NewInstance native instance is nullptr! code:%{public}d!", status);
        return instance;
    }
    proxy->queue_ = std::make_shared<AppDataMgrJsKit::UvQueue>(env);
    proxy->SetInstance(std::move(value));
    proxy->isSystemAppCalled_ = isSystemAppCalled;
    return instance;
}

RdbStoreProxy *GetNativeInstance(napi_env env, napi_value self)
{
    RdbStoreProxy *proxy = nullptr;
    napi_status status = napi_unwrap(env, self, reinterpret_cast<void **>(&proxy));
    if (proxy == nullptr) {
        LOG_ERROR("RdbStoreProxy::GetNativePredicates native instance is nullptr! code:%{public}d!", status);
        return nullptr;
    }
    return proxy;
}

int ParserThis(const napi_env &env, const napi_value &self, std::shared_ptr<ContextBase> context)
{
    RdbStoreProxy *obj = GetNativeInstance(env, self);
    CHECK_RETURN_SET(obj && obj->GetInstance(), std::make_shared<ParamError>("RdbStore", "not nullptr."));
    context->boundObj = obj;
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

int ParseDistributedTypeArg(const napi_env &env, size_t argc, napi_value * argv,
    std::shared_ptr<RdbStoreContext> context)
{
    context->distributedType = DistributedRdb::DISTRIBUTED_DEVICE;
    if (argc > 1) {
        auto status = JSUtils::Convert2ValueExt(env, argv[1], context->distributedType);
        bool checked = status == napi_ok && context->distributedType >= DistributedRdb::DISTRIBUTED_DEVICE
                       && context->distributedType <= DistributedRdb::DISTRIBUTED_CLOUD;
        CHECK_RETURN_SET(JSUtils::IsNull(env, argv[1]) || checked,
            std::make_shared<ParamError>("distributedType", "a DistributedType"));
    }
    return OK;
}

int ParseDistributedConfigArg(const napi_env &env, size_t argc, napi_value * argv,
    std::shared_ptr<RdbStoreContext> context)
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
    bool checked = (status == napi_ok && context->syncMode >= DistributedRdb::TIME_FIRST
                    && context->syncMode <= DistributedRdb::CLOUD_FIRST);
    CHECK_RETURN_SET(checked, std::make_shared<ParamError>("mode", "a SyncMode of cloud."));
    return OK;
}

int ParseCallback(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, arg, &valueType);
    CHECK_RETURN_SET((status == napi_ok && valueType == napi_function),
        std::make_shared<ParamError>("callback", "a function."));
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

int ParseAlias(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    context->aliasName = JSUtils::Convert2String(env, arg);
    CHECK_RETURN_SET(!context->aliasName.empty(), std::make_shared<ParamError>("aliasName", "not empty"));
    return OK;
}

int ParsePath(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    context->pathName = JSUtils::Convert2String(env, arg);
    CHECK_RETURN_SET(!context->pathName.empty(), std::make_shared<ParamError>("pathName", "not empty"));
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

int ParseValuesBucket(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    napi_value keys = nullptr;
    napi_get_all_property_names(env, arg, napi_key_own_only,
        static_cast<napi_key_filter>(napi_key_enumerable | napi_key_skip_symbols),
        napi_key_numbers_to_strings, &keys);
    uint32_t arrLen = 0;
    napi_status status = napi_get_array_length(env, keys, &arrLen);
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
    CHECK_RETURN_SET(isArray, std::make_shared<ParamError>("ValuesBucket is invalid."));

    uint32_t arrLen = 0;
    napi_status status = napi_get_array_length(env, arg, &arrLen);
    CHECK_RETURN_SET(status == napi_ok && arrLen > 0, std::make_shared<ParamError>("ValuesBucket is invalid."));

    for (uint32_t i = 0; i < arrLen; ++i) {
        napi_value obj = nullptr;
        status = napi_get_element(env, arg, i, &obj);
        CHECK_RETURN_SET(status == napi_ok, std::make_shared<InnerError>("napi_get_element failed."));

        CHECK_RETURN_ERR(ParseValuesBucket(env, obj, context) == OK);
        context->valuesBuckets.push_back(context->valuesBucket);
        context->valuesBucket.Clear();
    }
    return OK;
}

int ParseConflictResolution(const napi_env env, const napi_value arg, std::shared_ptr<RdbStoreContext> context)
{
    int32_t conflictResolution = 0;
    napi_get_value_int32(env, arg, &conflictResolution);
    int min = static_cast<int32_t>(NativeRdb::ConflictResolution::ON_CONFLICT_NONE);
    int max = static_cast<int32_t>(NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
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
        if (argc == 3) {
            CHECK_RETURN(OK == ParseConflictResolution(env, argv[2], context));
        }
    };
    auto exec = [context]() -> int {
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        return obj->GetInstance()->InsertWithConflictResolution(
            context->int64Output, context->tableName, context->valuesBucket, context->conflictResolution);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->int64Output, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(!(context->error) || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::BatchInsert(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseTableName(env, argv[0], context));
        CHECK_RETURN(OK == ParseValuesBuckets(env, argv[1], context));
    };
    auto exec = [context]() -> int {
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        return obj->GetInstance()->BatchInsert(context->int64Output, context->tableName, context->valuesBuckets);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->int64Output, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
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
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        CHECK_RETURN_ERR(context->rdbPredicates != nullptr);
        return obj->GetInstance()->Delete(context->intOutput, *(context->rdbPredicates));
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->intOutput, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
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
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        CHECK_RETURN_ERR(context->rdbPredicates != nullptr);
        return obj->GetInstance()->UpdateWithConflictResolution(context->intOutput, context->tableName,
            context->valuesBucket, context->rdbPredicates->GetWhereClause(), context->rdbPredicates->GetBindArgs(),
            context->conflictResolution);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->intOutput, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
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
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        CHECK_RETURN_ERR(context->rdbPredicates != nullptr);
        context->resultSet = obj->GetInstance()->Query(*(context->rdbPredicates), context->columns);
        return (context->resultSet != nullptr) ? E_OK : E_ERROR;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = ResultSetProxy::NewInstance(env, context->resultSet);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
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
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        int errCode = E_ERROR;
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        CHECK_RETURN_ERR(context->rdbPredicates != nullptr);
        context->resultSet =
            obj->GetInstance()->RemoteQuery(context->device, *(context->rdbPredicates), context->columns, errCode);
        return errCode;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = ResultSetProxy::NewInstance(env, context->resultSet);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
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
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
#if defined(WINDOWS_PLATFORM) || defined(MAC_PLATFORM) || defined(ANDROID_PLATFORM) || defined(IOS_PLATFORM)
        context->resultSet = obj->GetInstance()->QueryByStep(context->sql, context->bindArgs);
#else
        context->resultSet = obj->GetInstance()->QuerySql(context->sql, context->bindArgs);
#endif
        return (context->resultSet != nullptr) ? E_OK : E_ERROR;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = ResultSetProxy::NewInstance(env, context->resultSet);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
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
        }
    };
    auto exec = [context]() -> int {
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        return obj->GetInstance()->ExecuteSql(context->sql, context->bindArgs);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
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
            }
        }
        if (argc == 3) {
            CHECK_RETURN(OK == ParseTxId(env, argv[1], context));
            CHECK_RETURN(OK == ParseBindArgs(env, argv[2], context));
        }
    };
    auto exec = [context]() -> int {
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        auto status = E_ERROR;
        std::tie(status, context->sqlExeOutput) =
            obj->GetInstance()->Execute(context->sql, context->bindArgs, context->txId);
        return status;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = JSUtils::Convert2JSValue(env, context->sqlExeOutput);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::Count(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 1, std::make_shared<ParamNumError>("1 or 2"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParsePredicates(env, argv[0], context));
    };
    auto exec = [context]() -> int {
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        CHECK_RETURN_ERR(context->predicatesProxy != nullptr && context->predicatesProxy->GetPredicates() != nullptr);
        return obj->GetInstance()->Count(context->int64Output, *(context->predicatesProxy->GetPredicates()));
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->int64Output, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::Replace(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseTableName(env, argv[0], context));
        CHECK_RETURN(OK == ParseValuesBucket(env, argv[1], context));
    };
    auto exec = [context]() -> int {
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        return obj->GetInstance()->Replace(context->int64Output, context->tableName, context->valuesBucket);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->int64Output, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
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
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        return obj->GetInstance()->Backup(context->tableName, context->newKey);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

struct AttachContext : public ContextBase {
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
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        auto res = obj->GetInstance()->Attach(
            GetRdbStoreConfig(context->config, context->param), context->attachName, context->waitTime);
        context->attachedNum = res.second;
        return res.first;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = Convert2JSValue(env, context->attachedNum);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::Detach(napi_env env, napi_callback_info info)
{
    struct DetachContext : public ContextBase {
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
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        auto res = obj->GetInstance()->Detach(context->attachName, context->waitTime);
        context->attachedNum = res.second;
        return res.first;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = Convert2JSValue(env, context->attachedNum);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::IsReadOnly(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(
        env, rdbStoreProxy && rdbStoreProxy->GetInstance(), std::make_shared<ParamError>("RdbStore", "valid"));
    bool out = rdbStoreProxy->GetInstance()->IsReadOnly();
    LOG_DEBUG("RdbStoreProxy::IsReadOnly out is : %{public}d", out);
    return JSUtils::Convert2JSValue(env, out);
}

napi_value RdbStoreProxy::IsMemoryRdb(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(
        env, rdbStoreProxy && rdbStoreProxy->GetInstance(), std::make_shared<ParamError>("RdbStore", "valid"));
    bool out = rdbStoreProxy->GetInstance()->IsMemoryRdb();
    LOG_DEBUG("RdbStoreProxy::IsMemoryRdb out is : %{public}d", out);
    return JSUtils::Convert2JSValue(env, out);
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
    RDB_NAPI_ASSERT(
        env, rdbStoreProxy && rdbStoreProxy->GetInstance(), std::make_shared<ParamError>("RdbStore", "valid"));
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
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        LOG_DEBUG("RdbStoreProxy::BeginTrans start");
        auto status = E_ERROR;
        std::tie(status, context->intOutput) = obj->GetInstance()->BeginTrans();
        return status;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->intOutput, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(!(context->error) || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::RollBack(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr));
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(
        env, rdbStoreProxy && rdbStoreProxy->GetInstance(), std::make_shared<ParamError>("RdbStore", "valid"));
    int errCode = rdbStoreProxy->GetInstance()->RollBack();
    NAPI_ASSERT(env, errCode == E_OK, "call RollBack failed");
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
        LOG_DEBUG("RdbStoreProxy::roll back by txId start async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        return obj->GetInstance()->RollBack(context->txId);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::Commit(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    size_t argc = MAX_INPUT_COUNT;
    napi_value argv[MAX_INPUT_COUNT] = { nullptr };
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &thisObj, nullptr);
    RDB_NAPI_ASSERT(
        env, status == napi_ok && (argc == 0 || argc == 1), std::make_shared<ParamError>("parameter", "1 to 2"));
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(
        env, rdbStoreProxy && rdbStoreProxy->GetInstance(), std::make_shared<ParamError>("RdbStore", "valid"));
    if (argc == 0) {
        int errCode = rdbStoreProxy->GetInstance()->Commit();
        NAPI_ASSERT(env, errCode == E_OK, "call Commit failed");
        LOG_DEBUG("RdbStoreProxy::Commit end, errCode is:%{public}d", errCode);
        return nullptr;
    }

    auto context = std::make_shared<RdbStoreContext>();
    context->boundObj = rdbStoreProxy;

    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN(OK == ParseTxId(env, argv[0], context));
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::commit by txId start async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        return obj->GetInstance()->Commit(context->txId);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
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
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        context->resultSet = context->isQuerySql
                                 ? obj->GetInstance()->QueryByStep(context->sql, context->bindArgs)
                                 : obj->GetInstance()->QueryByStep(*(context->rdbPredicates), context->columns);
        return (context->resultSet != nullptr) ? E_OK : E_ERROR;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = ResultSetProxy::NewInstance(env, context->resultSet);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);
    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::IsInTransaction(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(
        env, rdbStoreProxy && rdbStoreProxy->GetInstance(), std::make_shared<ParamError>("RdbStore", "valid"));
    bool out = rdbStoreProxy->GetInstance()->IsInTransaction();
    LOG_DEBUG("RdbStoreProxy::IsInTransaction out is : %{public}d", out);
    return JSUtils::Convert2JSValue(env, out);
}

napi_value RdbStoreProxy::IsOpen(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(
        env, rdbStoreProxy && rdbStoreProxy->GetInstance(), std::make_shared<ParamError>("RdbStore", "valid"));
    bool out = rdbStoreProxy->GetInstance()->IsOpen();
    LOG_DEBUG("RdbStoreProxy::IsOpen out is : %{public}d", out);
    return JSUtils::Convert2JSValue(env, out);
}

napi_value RdbStoreProxy::GetVersion(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(
        env, rdbStoreProxy && rdbStoreProxy->GetInstance(), std::make_shared<ParamError>("RdbStore", "valid"));
    int32_t version = 0;
    int out = rdbStoreProxy->GetInstance()->GetVersion(version);
    LOG_DEBUG("RdbStoreProxy::GetVersion out is : %{public}d", out);
    return JSUtils::Convert2JSValue(env, version);
}

napi_value RdbStoreProxy::GetRebuilt(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(
        env, rdbStoreProxy && rdbStoreProxy->GetInstance(), std::make_shared<ParamError>("RdbStore", "valid"));
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
    RDB_NAPI_ASSERT(
        env, rdbStoreProxy && rdbStoreProxy->GetInstance(), std::make_shared<ParamError>("RdbStore", "valid"));
    int32_t version = 0;
    napi_get_value_int32(env, args[0], &version);
    RDB_NAPI_ASSERT(env, version > 0, std::make_shared<ParamError>("version", "> 0"));
    int out = rdbStoreProxy->GetInstance()->SetVersion(version);
    LOG_DEBUG("RdbStoreProxy::SetVersion out is : %{public}d", out);
    return nullptr;
}

napi_value RdbStoreProxy::Restore(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::Restore start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 1, std::make_shared<ParamNumError>("1 or 2"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseSrcName(env, argv[0], context));
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::Restore Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        return obj->GetInstance()->Restore(context->srcName, context->newKey);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
        LOG_DEBUG("RdbStoreProxy::Restore end");
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM) && !defined(ANDROID_PLATFORM) && !defined(IOS_PLATFORM)
napi_value RdbStoreProxy::SetDistributedTables(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::SetDistributedTables start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(1 <= argc && argc <= 3, std::make_shared<ParamNumError>("1 - 4"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseTablesName(env, argv[0], context));
        CHECK_RETURN(OK == ParseDistributedTypeArg(env, argc, argv, context));
        CHECK_RETURN(OK == ParseDistributedConfigArg(env, argc, argv, context));
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::SetDistributedTables Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        return obj->GetInstance()->SetDistributedTables(
            context->tablesNames, context->distributedType, context->distributedConfig);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
        LOG_DEBUG("RdbStoreProxy::SetDistributedTables end");
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::ObtainDistributedTableName(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::ObtainDistributedTableName start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseDevice(env, argv[0], context));
        CHECK_RETURN(OK == ParseTableName(env, argv[1], context));
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::ObtainDistributedTableName Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        int errCode = E_ERROR;
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        context->tableName =
            obj->GetInstance()->ObtainDistributedTableName(context->device, context->tableName, errCode);
        return errCode;
    };
    auto output = [context](napi_env env, napi_value &result) {
        std::string table = context->tableName;
        napi_status status = napi_create_string_utf8(env, table.c_str(), table.length(), &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
        LOG_DEBUG("RdbStoreProxy::ObtainDistributedTableName end");
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::Sync(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::Sync start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseSyncModeArg(env, argv[0], context));
        CHECK_RETURN(OK == ParsePredicates(env, argv[1], context));
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::Sync Async");
        auto *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        SyncOption option;
        option.mode = static_cast<DistributedRdb::SyncMode>(context->enumArg);
        option.isBlock = true;
        CHECK_RETURN_ERR(context->predicatesProxy != nullptr && context->predicatesProxy->GetPredicates() != nullptr);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        return obj->GetInstance()->Sync(option, *context->predicatesProxy->GetPredicates(),
            [context](const SyncResult &result) { context->syncResult = result; });
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = JSUtils::Convert2JSValue(env, context->syncResult);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
        LOG_DEBUG("RdbStoreProxy::Sync end");
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
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
    LOG_DEBUG("RdbStoreProxy::CloudSync start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = GetCloudSyncInput(context);
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::CloudSync Async");
        auto *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        SyncOption option;
        option.mode = static_cast<DistributedRdb::SyncMode>(context->syncMode);
        option.isBlock = false;
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
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
            context->execCode_ = obj->GetInstance()->Sync(option, context->tablesNames, async);
        } else {
            context->execCode_ = obj->GetInstance()->Sync(option, *(context->rdbPredicates), async);
        }
        return OK;
    };
    auto output = [context](napi_env env, napi_value &result) {
        LOG_DEBUG("RdbStoreProxy::CloudSync output");
        if (context->execCode_ != E_OK && context->asyncHolder != nullptr) {
            napi_delete_reference(env, context->asyncHolder);
        }
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAll(env, info, input, exec, output);
    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::GetModifyTime(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::GetModifyTime start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 3, std::make_shared<ParamNumError>("3 - 4"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseTableName(env, argv[0], context));
        CHECK_RETURN(OK == ParseColumnName(env, argv[1], context));
        CHECK_RETURN(OK == ParsePrimaryKey(env, argv[2], context));
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::GetModifyTime Async");
        auto *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        context->modifyTime = obj->GetInstance()->GetModifyTime(context->tableName, context->columnName, context->keys);
        return context->modifyTime.empty() ? E_ERROR : E_OK;
    };
    auto output = [context](napi_env env, napi_value &result) {
        LOG_DEBUG("RdbStoreProxy::GetModifyTime output");
        result = JSUtils::Convert2JSValue(env, context->modifyTime);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::CleanDirtyData(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::Clean start");
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
        LOG_DEBUG("RdbStoreProxy::CleanDirtyData Async");
        auto *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        return obj->GetInstance()->CleanDirtyData(context->tableName, context->cursor);
    };

    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
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

    bool result = std::any_of(observers_[mode].begin(), observers_[mode].end(), [argv](const auto &observer) {
        return *observer == argv[1];
    });
    if (result) {
        LOG_INFO("duplicate subscribe");
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
    LOG_INFO("subscribe success");
    return nullptr;
}

napi_value RdbStoreProxy::RegisteredObserver(napi_env env, const DistributedRdb::SubscribeOption &option,
    std::map<std::string, std::list<std::shared_ptr<NapiRdbStoreObserver>>> &observers, napi_value callback)
{
    observers.try_emplace(option.event);
    auto &list = observers.find(option.event)->second;
    bool result = std::any_of(list.begin(), list.end(), [callback](const auto &observer) {
        return *observer == callback;
    });
    if (result) {
        LOG_INFO("duplicate subscribe event: %{public}s", option.event.c_str());
        return nullptr;
    }

    auto uvQueue = std::make_shared<UvQueue>(env);
    auto localObserver = std::make_shared<NapiRdbStoreObserver>(callback, uvQueue);
    int errCode = GetInstance()->Subscribe(option, localObserver.get());
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    observers[option.event].push_back(localObserver);
    LOG_INFO("subscribe success event: %{public}s", option.event.c_str());
    return nullptr;
}

napi_value RdbStoreProxy::OnLocal(napi_env env, const DistributedRdb::SubscribeOption &option, napi_value callback)
{
    if (option.mode == SubscribeMode::LOCAL) {
        return RegisteredObserver(env, option, localObservers_, callback);
    }
    return RegisteredObserver(env, option, localSharedObservers_, callback);
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

    bool isNotNull = argc >=2 && !JSUtils::IsNull(env, argv[1]);
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
        LOG_DEBUG("observer unsubscribe success");
    }
    return nullptr;
}

napi_value RdbStoreProxy::UnRegisteredObserver(napi_env env, const DistributedRdb::SubscribeOption &option,
    std::map<std::string, std::list<std::shared_ptr<NapiRdbStoreObserver>>> &observers, napi_value callback)
{
    auto obs = observers.find(option.event);
    if (obs == observers.end()) {
        LOG_INFO("observer not found, event: %{public}s", option.event.c_str());
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
    LOG_INFO("unsubscribe success, event: %{public}s", option.event.c_str());
    return nullptr;
}

napi_value RdbStoreProxy::OffLocal(napi_env env, const DistributedRdb::SubscribeOption &option, napi_value callback)
{
    if (option.mode == SubscribeMode::LOCAL) {
        return UnRegisteredObserver(env, option, localObservers_, callback);
    }
    return UnRegisteredObserver(env, option, localSharedObservers_, callback);
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
    valueBool ? option.mode = SubscribeMode::LOCAL_SHARED : option.mode = SubscribeMode::LOCAL;
    // 'argv[2]' represents a callback function
    return proxy->OnLocal(env, option, argv[2]);
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
    return proxy->OffLocal(env, option, argc == 3 ? argv[2] : nullptr);
}

napi_value RdbStoreProxy::Notify(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1]{};
    napi_value self = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
    RDB_NAPI_ASSERT(env, status == napi_ok && argc == 1, std::make_shared<ParamNumError>("1"));
    auto *proxy = GetNativeInstance(env, self);
    RDB_NAPI_ASSERT(env, proxy != nullptr && proxy->GetInstance() != nullptr,
        std::make_shared<ParamError>("RdbStore", "valid"));
    int errCode = proxy->GetInstance()->Notify(JSUtils::Convert2String(env, argv[0]));
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    return nullptr;
}

napi_value RdbStoreProxy::QuerySharingResource(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::QuerySharingResource start");
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
        LOG_DEBUG("RdbStoreProxy::QuerySharingResource Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        auto status = E_ERROR;
        std::tie(status, context->resultSet) =
            obj->GetInstance()->QuerySharingResource(*(context->rdbPredicates), context->columns);
        LOG_DEBUG("RdbStoreProxy::QuerySharingResource resultSet is nullptr:%{public}d, status:%{public}d",
            context->resultSet == nullptr, status);
        return (status == E_OK && context->resultSet != nullptr) ? E_OK : E_ERROR;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = ResultSetProxy::NewInstance(env, context->resultSet);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
        LOG_DEBUG("RdbStoreProxy::QuerySharingResource end");
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::RegisterSyncCallback(napi_env env, size_t argc, napi_value *argv)
{
    napi_valuetype type = napi_undefined;
    napi_typeof(env, argv[0], &type);
    RDB_NAPI_ASSERT(env, type == napi_function, std::make_shared<ParamError>("progress", "function"));
    bool result = std::any_of(syncObservers_.begin(), syncObservers_.end(), [argv](const auto &observer) {
        return *observer == argv[1];
    });
    if (result) {
        LOG_DEBUG("duplicate subscribe");
        return nullptr;
    }
    auto observer = std::make_shared<SyncObserver>(env, argv[0], queue_);
    int errCode = GetInstance()->RegisterAutoSyncCallback(observer);
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    syncObservers_.push_back(std::move(observer));
    LOG_INFO("progress subscribe success");
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
        if (isNotNull && !(**it == argv[1])) {
            ++it;
            continue;
        }

        int errCode = GetInstance()->UnregisterAutoSyncCallback(*it);
        RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
        it = syncObservers_.erase(it);
        LOG_DEBUG("observer unsubscribe success");
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
    if (env_ != nullptr && callback_ != nullptr) {
        napi_delete_reference(env_, callback_);
    }
}

bool RdbStoreProxy::SyncObserver::operator==(napi_value value)
{
    return JSUtils::Equal(env_, callback_, value);
}

void RdbStoreProxy::SyncObserver::ProgressNotification(const Details &details)
{
    if (queue_ != nullptr) {
        queue_->AsyncCall({ callback_, true },
            [details, obs = shared_from_this()](napi_env env, int &argc, napi_value *argv) -> void {
                argc = 1;
                argv[0] = details.empty() ? nullptr : JSUtils::Convert2JSValue(env, details.begin()->second);
            });
    }
}

napi_value RdbStoreProxy::ModifyLockStatus(napi_env env, napi_callback_info info, bool isLock)
{
    LOG_DEBUG("start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc >= 1, std::make_shared<ParamNumError>("1"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParsePredicates(env, argv[0], context));
    };
    auto exec = [context, isLock]() -> int {
        LOG_DEBUG("Async");
        auto *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        CHECK_RETURN_ERR(context->rdbPredicates != nullptr);
        return obj->GetInstance()->ModifyLockStatus(*(context->rdbPredicates), isLock);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
        LOG_DEBUG("end");
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
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
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        CHECK_RETURN_ERR(obj != nullptr && obj->GetInstance() != nullptr);
        CHECK_RETURN_ERR(context->rdbPredicates != nullptr);

        context->rdbPredicates->BeginWrap()->EqualTo(AbsRdbPredicates::LOCK_STATUS, AbsRdbPredicates::LOCKED)->Or();
        context->rdbPredicates->EqualTo(AbsRdbPredicates::LOCK_STATUS, AbsRdbPredicates::LOCK_CHANGED)->EndWrap();
        context->resultSet = obj->GetInstance()->QueryByStep(*(context->rdbPredicates), context->columns);
        return (context->resultSet != nullptr) ? E_OK : E_ERROR;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = ResultSetProxy::NewInstance(env, context->resultSet);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}
#endif

napi_value RdbStoreProxy::Close(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN(OK == ParserThis(env, self, context));
    };
    ExecuteAction exec;
    RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
    if (obj != nullptr) {
        auto store = obj->GetInstance();
        obj->SetInstance(nullptr);
        exec = [context, store]() mutable -> int {
            store = nullptr;
            return OK;
        };
    }
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}
} // namespace RelationalStoreJsKit
} // namespace OHOS
