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

#include <cinttypes>
#include <string>
#include <vector>

#include "js_logger.h"
#include "js_utils.h"
#include "napi_async_call.h"
#include "napi_rdb_error.h"
#include "napi_rdb_predicates.h"
#include "napi_rdb_store.h"
#include "napi_rdb_trace.h"
#include "napi_result_set.h"
#include "rdb_errno.h"
#include "securec.h"

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
#include "rdb_utils.h"
using namespace OHOS::DataShare;
#endif

using namespace OHOS::NativeRdb;
using namespace OHOS::AppDataMgrJsKit;

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
using OHOS::DistributedRdb::SubscribeMode;
using OHOS::DistributedRdb::SubscribeOption;
using OHOS::DistributedRdb::SyncOption;
using OHOS::DistributedRdb::SyncResult;
#endif

namespace OHOS {
namespace RelationalStoreJsKit {
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
struct PredicatesProxy {
    std::shared_ptr<DataShareAbsPredicates> predicates_;
};
#endif
struct RdbStoreContext : public Context {
    std::string device;
    std::string tableName;
    std::vector<std::string> tablesNames;
    std::string whereClause;
    std::vector<std::string> whereArgs;
    std::vector<std::string> selectionArgs;
    std::string sql;
    RdbPredicatesProxy *predicatesProxy;
    std::vector<std::string> columns;
    ValuesBucket valuesBucket;
    std::vector<ValuesBucket> valuesBuckets;
    std::map<std::string, ValueObject> numberMaps;
    std::vector<ValueObject> bindArgs;
    int64_t int64Output;
    int intOutput;
    std::vector<uint8_t> newKey;
    std::shared_ptr<ResultSet> newResultSet;
    std::unique_ptr<ResultSet> resultSet_value;
    std::string aliasName;
    std::string pathName;
    std::string destName;
    std::string srcName;
    int32_t enumArg;
    NativeRdb::ConflictResolution conflictResolution;
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    DistributedRdb::SyncResult syncResult;
#endif
    std::shared_ptr<RdbPredicates> rdbPredicates = nullptr;

    RdbStoreContext()
        : predicatesProxy(nullptr), int64Output(0), intOutput(0), enumArg(0),
          conflictResolution(NativeRdb::ConflictResolution::ON_CONFLICT_NONE)
    {
    }
    virtual ~RdbStoreContext()
    {
    }
};

static __thread napi_ref constructor_ = nullptr;

RdbStoreProxy::RdbStoreProxy()
{
}

RdbStoreProxy::~RdbStoreProxy()
{
    LOG_DEBUG("RdbStoreProxy destructor");
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
    napi_valuetype type;
    NAPI_CALL_BASE(env, napi_typeof(env, argv[arg], &type), false);
    return type == napi_string;
}

bool IsNapiTypeArray(napi_env env, size_t argc, napi_value *argv, size_t arg)
{
    if (arg >= argc) {
        return false;
    }
    bool isArray = false;
    NAPI_CALL_BASE(env, napi_is_array(env, argv[arg], &isArray), false);
    return isArray;
}

bool IsNapiTypeNumber(napi_env env,  size_t argc, napi_value *argv, size_t arg)
{
    if (arg >= argc) {
        return false;
    }
    napi_valuetype type;
    NAPI_CALL_BASE(env, napi_typeof(env, argv[arg], &type), false);
    return type == napi_number;
}

void RdbStoreProxy::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor descriptors[] = {
        DECLARE_NAPI_FUNCTION("delete", Delete),
        DECLARE_NAPI_FUNCTION("update", Update),
        DECLARE_NAPI_FUNCTION("insert", Insert),
        DECLARE_NAPI_FUNCTION("batchInsert", BatchInsert),
        DECLARE_NAPI_FUNCTION("querySql", QuerySql),
        DECLARE_NAPI_FUNCTION("query", Query),
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
        DECLARE_NAPI_FUNCTION("remoteQuery", RemoteQuery),
#endif
        DECLARE_NAPI_FUNCTION("executeSql", ExecuteSql),
        DECLARE_NAPI_FUNCTION("replace", Replace),
        DECLARE_NAPI_FUNCTION("backup", Backup),
        DECLARE_NAPI_FUNCTION("count", Count),
        DECLARE_NAPI_FUNCTION("addAttach", Attach),
        DECLARE_NAPI_FUNCTION("beginTransaction", BeginTransaction),
        DECLARE_NAPI_FUNCTION("rollBack", RollBack),
        DECLARE_NAPI_FUNCTION("commit", Commit),
        DECLARE_NAPI_FUNCTION("queryByStep", QueryByStep),
        DECLARE_NAPI_FUNCTION("restore", Restore),
        DECLARE_NAPI_GETTER_SETTER("version", GetVersion, SetVersion),
        DECLARE_NAPI_GETTER("isInTransaction", IsInTransaction),
        DECLARE_NAPI_GETTER("isOpen", IsOpen),
        DECLARE_NAPI_GETTER("path", GetPath),
        DECLARE_NAPI_GETTER("isHoldingConnection", IsHoldingConnection),
        DECLARE_NAPI_GETTER("isReadOnly", IsReadOnly),
        DECLARE_NAPI_GETTER("isMemoryRdb", IsMemoryRdb),
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
        DECLARE_NAPI_FUNCTION("setDistributedTables", SetDistributedTables),
        DECLARE_NAPI_FUNCTION("obtainDistributedTableName", ObtainDistributedTableName),
        DECLARE_NAPI_FUNCTION("sync", Sync),
        DECLARE_NAPI_FUNCTION("on", OnEvent),
        DECLARE_NAPI_FUNCTION("off", OffEvent),
#endif
    };
    napi_value cons = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_define_class(env, "RdbStore", NAPI_AUTO_LENGTH, Initialize, nullptr,
                                   sizeof(descriptors) / sizeof(napi_property_descriptor), descriptors, &cons));
    NAPI_CALL_RETURN_VOID(env, napi_create_reference(env, cons, 1, &constructor_));

    LOG_DEBUG("Init RdbStoreProxy end");
}

napi_value RdbStoreProxy::Initialize(napi_env env, napi_callback_info info)
{
    napi_value self;
    NAPI_CALL(env, napi_get_cb_info(env, info, NULL, NULL, &self, nullptr));
    auto finalize = [](napi_env env, void *data, void *hint) {
        RdbStoreProxy *proxy = reinterpret_cast<RdbStoreProxy *>(data);
        delete proxy;
    };
    auto *proxy = new (std::nothrow) RdbStoreProxy();
    if (proxy == nullptr) {
        return nullptr;
    }
    napi_status status = napi_wrap(env, self, proxy, finalize, nullptr, nullptr);
    if (status != napi_ok) {
        LOG_ERROR("RdbStoreProxy::Initialize napi_wrap failed! code:%{public}d!", status);
        finalize(env, proxy, nullptr);
        return nullptr;
    }
    return self;
}

napi_value RdbStoreProxy::NewInstance(napi_env env, std::shared_ptr<NativeRdb::RdbStore> value, bool isSystemAppCalled)
{
    NAPI_ASSERT_BASE(env, value != nullptr, "RdbStoreProxy::NewInstance get native rdb is null.", nullptr);
    napi_value cons;
    napi_status status = napi_get_reference_value(env, constructor_, &cons);
    if (status != napi_ok) {
        LOG_ERROR("RdbStoreProxy::NewInstance get constructor failed! code:%{public}d!", status);
        return nullptr;
    }

    napi_value instance = nullptr;
    status = napi_new_instance(env, cons, 0, nullptr, &instance);
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
    proxy->rdbStore_ = std::move(value);
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

int ParserThis(const napi_env &env, const napi_value &self, std::shared_ptr<RdbStoreContext> context)
{
    RdbStoreProxy *obj = GetNativeInstance(env, self);
    CHECK_RETURN_SET(obj && obj->rdbStore_, std::make_shared<ParamError>("RdbStore", "nullptr."));
    context->boundObj = obj;
    LOG_DEBUG("ParserThis RdbStoreProxy end");
    return OK;
}

int ParseTableName(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    context->tableName = JSUtils::Convert2String(env, arg);
    CHECK_RETURN_SET(!context->tableName.empty(), std::make_shared<ParamError>("table", "not empty"));

    LOG_DEBUG("ParseTableName end");
    return OK;
}

int ParseDevice(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    context->device = JSUtils::Convert2String(env, arg);
    CHECK_RETURN_SET(!context->device.empty(), std::make_shared<ParamError>("device", "not empty"));

    LOG_DEBUG("ParseDevice end");
    return OK;
}

int ParseTablesName(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    context->tablesNames = JSUtils::Convert2StrVector(env, arg);
    return OK;
}

int ParseSyncModeArg(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    napi_get_value_int32(env, arg, &context->enumArg);
    bool checked = context->enumArg == 0 || context->enumArg == 1;
    CHECK_RETURN_SET(checked, std::make_shared<ParamError>("mode", "a SyncMode."));

    LOG_DEBUG("ParseSyncModeArg end");
    return OK;
}

int ParsePredicates(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    napi_unwrap(env, arg, reinterpret_cast<void **>(&context->predicatesProxy));
    CHECK_RETURN_SET(context->predicatesProxy != nullptr,
        std::make_shared<ParamError>("predicates", "an RdbPredicates."));
    context->tableName = context->predicatesProxy->GetPredicates()->GetTableName();
    context->rdbPredicates = context->predicatesProxy->GetPredicates();
    return OK;
}

int ParseDataSharePredicates(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
    CHECK_RETURN_SET(obj->IsSystemAppCalled(), std::make_shared<NonSystemError>());
    PredicatesProxy *proxy = nullptr;
    napi_status status = napi_unwrap(env, arg, reinterpret_cast<void **>(&proxy));
    bool checked = (status == napi_ok) && (proxy != nullptr) && (proxy->predicates_ != nullptr);
    CHECK_RETURN_SET(checked, std::make_shared<ParamError>("predicates", "an DataShare Predicates."));

    std::shared_ptr<DataShareAbsPredicates> dsPredicates = proxy->predicates_;
    RdbPredicates rdbPredicates = RdbDataShareAdapter::RdbUtils::ToPredicates(*dsPredicates, context->tableName);
    context->rdbPredicates = std::make_shared<RdbPredicates>(rdbPredicates);
    LOG_DEBUG("Parse DSPredicates end");
#endif
    return OK;
}

int ParseNewKey(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    context->newKey = JSUtils::Convert2U8Vector(env, arg);
    LOG_DEBUG("ParseNewKey end");
    return OK;
}

int ParseSrcName(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    context->srcName = JSUtils::Convert2String(env, arg);
    CHECK_RETURN_SET(!context->srcName.empty(), std::make_shared<ParamError>("srcName", "not empty"));
    return OK;
}

int ParseColumns(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    context->columns = JSUtils::Convert2StrVector(env, arg);
    return OK;
}

int ParseAlias(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    context->aliasName = JSUtils::Convert2String(env, arg);
    CHECK_RETURN_SET(!context->aliasName.empty(), std::make_shared<ParamError>("aliasName", "not empty"));

    LOG_DEBUG("ParseAlias end");
    return OK;
}

int ParsePath(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    context->pathName = JSUtils::Convert2String(env, arg);
    CHECK_RETURN_SET(!context->pathName.empty(), std::make_shared<ParamError>("pathName", "not empty"));

    LOG_DEBUG("ParsePath end");
    return OK;
}

int ParseSelectionArgs(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    context->selectionArgs = JSUtils::Convert2StrVector(env, arg);
    LOG_DEBUG("ParseSelectionArgs end");
    return OK;
}

int ParseSql(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    context->sql = JSUtils::Convert2String(env, arg, false);
    CHECK_RETURN_SET(!context->sql.empty(), std::make_shared<ParamError>("sql", "not empty"));

    LOG_DEBUG("ParseSql end");
    return OK;
}

int ParseValuesBucket(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    napi_value keys = 0;
    napi_get_property_names(env, arg, &keys);
    uint32_t arrLen = 0;
    napi_status status = napi_get_array_length(env, keys, &arrLen);
    CHECK_RETURN_SET(status == napi_ok, std::make_shared<ParamError>("values", "a ValuesBucket."));

    for (size_t i = 0; i < arrLen; ++i) {
        napi_value key;
        status = napi_get_element(env, keys, i, &key);
        CHECK_RETURN_SET(status == napi_ok, std::make_shared<ParamError>("values", "a ValuesBucket."));

        std::string keyStr = JSUtils::Convert2String(env, key);
        napi_value value;
        napi_get_property(env, arg, key, &value);
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, value, &valueType);
        if (valueType == napi_string) {
            std::string valueString = JSUtils::Convert2String(env, value, false);
            context->valuesBucket.PutString(keyStr, valueString);
        } else if (valueType == napi_number) {
            double valueNumber;
            napi_get_value_double(env, value, &valueNumber);
            context->valuesBucket.PutDouble(keyStr, valueNumber);
        } else if (valueType == napi_boolean) {
            bool valueBool = false;
            napi_get_value_bool(env, value, &valueBool);
            context->valuesBucket.PutBool(keyStr, valueBool);
        } else if (valueType == napi_null) {
            context->valuesBucket.PutNull(keyStr);
        } else if (valueType == napi_object) {
            context->valuesBucket.PutBlob(keyStr, JSUtils::Convert2U8Vector(env, value));
        } else {
            LOG_WARN("bad value type of key %{public}s", keyStr.c_str());
        }
    }
    LOG_DEBUG("ParseValuesBucket end");
    return OK;
}

int ParseValuesBuckets(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    bool isArray = false;
    napi_is_array(env, arg, &isArray);
    CHECK_RETURN_SET(isArray, std::make_shared<ParamError>("values", "a ValuesBucket array."));

    uint32_t arrLen = 0;
    napi_status status = napi_get_array_length(env, arg, &arrLen);
    CHECK_RETURN_SET(status == napi_ok, std::make_shared<ParamError>("values", "get array length."));

    for (uint32_t i = 0; i < arrLen; ++i) {
        napi_value obj = nullptr;
        status = napi_get_element(env, arg, i, &obj);
        CHECK_RETURN_SET(status == napi_ok, std::make_shared<ParamError>("values", "get element."));

        ParseValuesBucket(env, obj, context);
        context->valuesBuckets.push_back(context->valuesBucket);
        context->valuesBucket.Clear();
    }
    return OK;
}

int ParseConflictResolution(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    int32_t conflictResolution = 0;
    napi_get_value_int32(env, arg, &conflictResolution);
    int min = static_cast<int32_t>(NativeRdb::ConflictResolution::ON_CONFLICT_NONE);
    int max = static_cast<int32_t>(NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    bool checked = (conflictResolution >= min) && (conflictResolution <= max);
    CHECK_RETURN_SET(checked, std::make_shared<ParamError>("conflictResolution", "a ConflictResolution."));
    context->conflictResolution = static_cast<NativeRdb::ConflictResolution>(conflictResolution);
    LOG_DEBUG("ParseConflictResolution end");
    return OK;
}

napi_value RdbStoreProxy::Insert(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    LOG_DEBUG("RdbStoreProxy::Insert start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc >= 2 && argc <= 4, std::make_shared<ParamNumError>("2 to 4"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseTableName(env, argv[0], context));
        CHECK_RETURN(OK == ParseValuesBucket(env, argv[1], context));
        if (IsNapiTypeNumber(env, argc, argv, 2)) {
            CHECK_RETURN(OK == ParseConflictResolution(env, argv[2], context));
        }
    };
    auto exec = [context]() -> int {
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        return obj->rdbStore_->InsertWithConflictResolution(context->int64Output, context->tableName,
            context->valuesBucket, context->conflictResolution);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->int64Output, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
        LOG_DEBUG("RdbStoreProxy::Insert end");
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::BatchInsert(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    LOG_DEBUG("RdbStoreProxy::BatchInsert start.");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 2 || argc == 3, std::make_shared<ParamNumError>("2 or 3"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseTableName(env, argv[0], context));
        CHECK_RETURN(OK == ParseValuesBuckets(env, argv[1], context));
    };
    auto exec = [context]() -> int {
        LOG_INFO("RdbStoreProxy::BatchInsert Async.");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        return obj->rdbStore_->BatchInsert(context->int64Output, context->tableName, context->valuesBuckets);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->int64Output, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
        LOG_DEBUG("RdbStoreProxy::BatchInsert end.");
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::Delete(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::Delete start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN(OK == ParserThis(env, self, context));
        if (IsNapiTypeString(env, argc, argv, 0)) {
            CHECK_RETURN_SET_E(argc == 2 || argc == 3, std::make_shared<ParamNumError>("1 to 3"));
            CHECK_RETURN(OK == ParseTableName(env, argv[0], context));
            CHECK_RETURN(OK == ParseDataSharePredicates(env, argv[1], context));
        } else {
            CHECK_RETURN_SET_E(argc == 1 || argc == 2, std::make_shared<ParamNumError>("1 to 3"));
            CHECK_RETURN(OK == ParsePredicates(env, argv[0], context));
        }
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::Delete Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        return obj->rdbStore_->Delete(context->intOutput, *(context->rdbPredicates));
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->intOutput, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
        LOG_DEBUG("RdbStoreProxy::Delete end");
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::Update(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    LOG_DEBUG("RdbStoreProxy::Update start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN(OK == ParserThis(env, self, context));
        if (IsNapiTypeString(env, argc, argv, 0)) {
            CHECK_RETURN_SET_E(argc == 3 || argc == 4, std::make_shared<ParamNumError>("2 to 4"));
            CHECK_RETURN(OK == ParseTableName(env, argv[0], context));
            CHECK_RETURN(OK == ParseValuesBucket(env, argv[1], context));
            CHECK_RETURN(OK == ParseDataSharePredicates(env, argv[2], context));
        } else {
            CHECK_RETURN_SET_E(argc >= 2 && argc <= 4, std::make_shared<ParamNumError>("2 to 4"));
            CHECK_RETURN(OK == ParseValuesBucket(env, argv[0], context));
            CHECK_RETURN(OK == ParsePredicates(env, argv[1], context));
            if (IsNapiTypeNumber(env, argc, argv, 2)) {
                CHECK_RETURN(OK == ParseConflictResolution(env, argv[2], context));
            }
        }
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::Update Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        return obj->rdbStore_->UpdateWithConflictResolution(context->intOutput, context->tableName,
            context->valuesBucket, context->rdbPredicates->GetWhereClause(), context->rdbPredicates->GetWhereArgs(),
            context->conflictResolution);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->intOutput, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
        LOG_DEBUG("RdbStoreProxy::Update end");
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::Query(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN(OK == ParserThis(env, self, context));
        if (IsNapiTypeString(env, argc, argv, 0)) {
            CHECK_RETURN_SET_E(argc >= 1 && argc <= 3, std::make_shared<ParamNumError>("1 to 3"));
            CHECK_RETURN(OK == ParseTableName(env, argv[0], context));
            CHECK_RETURN(OK == ParseDataSharePredicates(env, argv[1], context));
            if (IsNapiTypeArray(env, argc, argv, 2)) {
                CHECK_RETURN(OK == ParseColumns(env, argv[2], context));
            }
        } else {
            CHECK_RETURN_SET_E(argc == 1 || argc == 2, std::make_shared<ParamNumError>("1 to 3"));
            CHECK_RETURN(OK == ParsePredicates(env, argv[0], context));
            if (IsNapiTypeArray(env, argc, argv, 1)) {
                CHECK_RETURN(OK == ParseColumns(env, argv[1], context));
            }
        }
    };
    auto exec = [context]() -> int {
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        context->resultSet_value = obj->rdbStore_->Query(*(context->rdbPredicates), context->columns);
        LOG_DEBUG("RdbStoreProxy::Query result is nullptr ? %{public}d", (context->resultSet_value == nullptr));
        return (context->resultSet_value != nullptr) ? E_OK : E_ERROR;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = ResultSetProxy::NewInstance(env, std::shared_ptr<ResultSet>(context->resultSet_value.release()));
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
napi_value RdbStoreProxy::RemoteQuery(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::RemoteQuery start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 4 || argc == 5, std::make_shared<ParamNumError>("4 or 5"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseDevice(env, argv[0], context));
        CHECK_RETURN(OK == ParseTableName(env, argv[1], context));
        CHECK_RETURN(OK == ParsePredicates(env, argv[2], context));
        CHECK_RETURN(OK == ParseColumns(env, argv[3], context));
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::RemoteQuery Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        context->newResultSet =
            obj->rdbStore_->RemoteQuery(context->device, *(context->rdbPredicates), context->columns);
        LOG_DEBUG("RdbStoreProxy::RemoteQuery result is nullptr ? %{public}d", (context->newResultSet == nullptr));
        return (context->newResultSet != nullptr) ? E_OK : E_ERROR;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = ResultSetProxy::NewInstance(env, context->newResultSet);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
        LOG_DEBUG("RdbStoreProxy::RemoteQuery end");
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
        CHECK_RETURN_SET_E(argc >= 1 && argc <= 3, std::make_shared<ParamNumError>("1 to 3"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseSql(env, argv[0], context));
        if (argc > 1) {
#if defined(WINDOWS_PLATFORM) || defined(MAC_PLATFORM)
            CHECK_RETURN(OK == ParseColumns(env, argv[1], context));
#else
            CHECK_RETURN(OK == ParseSelectionArgs(env, argv[1], context));
#endif
        }
    };
    auto exec = [context]() -> int {
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
#if defined(WINDOWS_PLATFORM) || defined(MAC_PLATFORM)
        context->resultSet_value = obj->rdbStore_->QueryByStep(context->sql, context->columns);
        LOG_ERROR("RdbStoreProxy::QuerySql is nullptr ? %{public}d ", context->resultSet_value == nullptr);
#else
        std::string selectionArgs = ",";
        for (size_t i = 0; i < context->selectionArgs.size(); i++) {
            selectionArgs += context->selectionArgs[i];
        }
        context->resultSet_value = obj->rdbStore_->QuerySql(context->sql, context->selectionArgs);
#endif
        return (context->resultSet_value != nullptr) ? E_OK : E_ERROR;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = ResultSetProxy::NewInstance(env, std::shared_ptr<ResultSet>(context->resultSet_value.release()));
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

int ParseBindArgs(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    context->bindArgs.clear();
    napi_valuetype type;
    napi_typeof(env, arg, &type);
    if (type == napi_undefined || type == napi_null) {
        return OK;
    }
    bool isArray = false;
    napi_status status = napi_is_array(env, arg, &isArray);
    CHECK_RETURN_SET(status == napi_ok && isArray, std::make_shared<ParamError>("values", "a BindArgs array."));

    uint32_t arrLen = 0;
    status = napi_get_array_length(env, arg, &arrLen);
    CHECK_RETURN_SET(status == napi_ok && arrLen >= 0, std::make_shared<ParamError>("values", "not empty."));
    for (size_t i = 0; i < arrLen; ++i) {
        napi_value element;
        napi_get_element(env, arg, i, &element);
        napi_valuetype type;
        napi_typeof(env, element, &type);
        switch (type) {
            case napi_boolean: {
                bool value = false;
                int32_t ret = JSUtils::Convert2Bool(env, element, value);
                CHECK_RETURN_SET(ret == OK, std::make_shared<ParamError>(std::to_string(i), "a correct boolean"));
                context->bindArgs.push_back(ValueObject(value));
            } break;
            case napi_number: {
                double value;
                int32_t ret = JSUtils::Convert2Double(env, element, value);
                CHECK_RETURN_SET(ret == OK, std::make_shared<ParamError>(std::to_string(i), "a correct number"));
                context->bindArgs.push_back(ValueObject(value));
            } break;
            case napi_null: {
                context->bindArgs.push_back(ValueObject());
            } break;
            case napi_string: {
                context->bindArgs.push_back(ValueObject(JSUtils::Convert2String(env, element, false)));
            } break;
            case napi_object: {
                std::vector<uint8_t> value;
                int32_t ret = JSUtils::Convert2U8Vector(env, element, value);
                CHECK_RETURN_SET(ret == OK, std::make_shared<ParamError>(std::to_string(i), "Uint8Array"));
                context->bindArgs.push_back(ValueObject(value));
            } break;
            default: {
                CHECK_RETURN_SET(false, std::make_shared<ParamError>(std::to_string(i), "a valid ValueType"));
            } break;
        }
    }
    return OK;
}

napi_value RdbStoreProxy::ExecuteSql(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::ExecuteSql start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc >= 1 && argc <= 3, std::make_shared<ParamNumError>("1 to 3"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseSql(env, argv[0], context));
        if (argc > 1) {
            CHECK_RETURN(OK == ParseBindArgs(env, argv[1], context));
        }
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::ExecuteSql Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        return obj->rdbStore_->ExecuteSql(context->sql, context->bindArgs);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
        LOG_DEBUG("RdbStoreProxy::ExecuteSql end");
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::Count(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::Count start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 1 || argc == 2, std::make_shared<ParamNumError>("1 or 2"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParsePredicates(env, argv[0], context));
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::Count Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        return obj->rdbStore_->Count(context->int64Output, *(context->predicatesProxy->GetPredicates()));
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->int64Output, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
        LOG_DEBUG("RdbStoreProxy::Count end");
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::Replace(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    LOG_DEBUG("RdbStoreProxy::Replace start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 2 || argc == 3, std::make_shared<ParamNumError>("2 or 3"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseTableName(env, argv[0], context));
        CHECK_RETURN(OK == ParseValuesBucket(env, argv[1], context));
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::Replace Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        return obj->rdbStore_->Replace(context->int64Output, context->tableName, context->valuesBucket);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->int64Output, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
        LOG_DEBUG("RdbStoreProxy::Replace end");
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::Backup(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::Backup start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 1 || argc == 2, std::make_shared<ParamNumError>("1 or 2"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseTableName(env, argv[0], context));
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::Backup Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        return obj->rdbStore_->Backup(context->tableName, context->newKey);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
        LOG_DEBUG("RdbStoreProxy::Backup end");
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::Attach(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::Attach start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 3 || argc == 4, std::make_shared<ParamNumError>("3 or 4"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseAlias(env, argv[0], context));
        CHECK_RETURN(OK == ParsePath(env, argv[1], context));
        CHECK_RETURN(OK == ParseNewKey(env, argv[2], context));
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::Attach Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        return obj->rdbStore_->Attach(context->aliasName, context->pathName, context->newKey);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
        LOG_DEBUG("RdbStoreProxy::Attach end");
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::IsHoldingConnection(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(env, rdbStoreProxy && rdbStoreProxy->rdbStore_, std::make_shared<ParamError>("RdbStore", "valid"));
    bool out = rdbStoreProxy->rdbStore_->IsHoldingConnection();
    LOG_DEBUG("RdbStoreProxy::IsHoldingConnection out is : %{public}d", out);
    return JSUtils::Convert2JSValue(env, out);
}

napi_value RdbStoreProxy::IsReadOnly(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(env, rdbStoreProxy && rdbStoreProxy->rdbStore_, std::make_shared<ParamError>("RdbStore", "valid"));
    bool out = rdbStoreProxy->rdbStore_->IsReadOnly();
    LOG_DEBUG("RdbStoreProxy::IsReadOnly out is : %{public}d", out);
    return JSUtils::Convert2JSValue(env, out);
}

napi_value RdbStoreProxy::IsMemoryRdb(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(env, rdbStoreProxy && rdbStoreProxy->rdbStore_, std::make_shared<ParamError>("RdbStore", "valid"));
    bool out = rdbStoreProxy->rdbStore_->IsMemoryRdb();
    LOG_DEBUG("RdbStoreProxy::IsMemoryRdb out is : %{public}d", out);
    return JSUtils::Convert2JSValue(env, out);
}

napi_value RdbStoreProxy::GetPath(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(env, rdbStoreProxy && rdbStoreProxy->rdbStore_, std::make_shared<ParamError>("RdbStore", "valid"));
    std::string path = rdbStoreProxy->rdbStore_->GetPath();
    LOG_DEBUG("RdbStoreProxy::GetPath path is empty ? %{public}d", path.empty());
    return JSUtils::Convert2JSValue(env, path);
}

napi_value RdbStoreProxy::BeginTransaction(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr));
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(env, rdbStoreProxy && rdbStoreProxy->rdbStore_, std::make_shared<ParamError>("RdbStore", "valid"));
    int errCode = rdbStoreProxy->rdbStore_->BeginTransaction();
    RDB_NAPI_ASSERT(env, errCode == E_OK, std::make_shared<InnerError>(errCode));
    LOG_DEBUG("RdbStoreProxy::BeginTransaction end, errCode is:%{public}d", errCode);
    return nullptr;
}

napi_value RdbStoreProxy::RollBack(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr));
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(env, rdbStoreProxy && rdbStoreProxy->rdbStore_, std::make_shared<ParamError>("RdbStore", "valid"));
    int errCode = rdbStoreProxy->rdbStore_->RollBack();
    NAPI_ASSERT(env, errCode == E_OK, "call RollBack failed");
    LOG_DEBUG("RdbStoreProxy::RollBack end, errCode is:%{public}d", errCode);
    return nullptr;
}

napi_value RdbStoreProxy::Commit(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr));
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(env, rdbStoreProxy && rdbStoreProxy->rdbStore_, std::make_shared<ParamError>("RdbStore", "valid"));
    int errCode = rdbStoreProxy->rdbStore_->Commit();
    NAPI_ASSERT(env, errCode == E_OK, "call Commit failed");
    LOG_DEBUG("RdbStoreProxy::Commit end, errCode is:%{public}d", errCode);
    return nullptr;
}

napi_value RdbStoreProxy::QueryByStep(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    LOG_DEBUG("RdbStoreProxy::QueryByStep start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 2 || argc == 3, std::make_shared<ParamNumError>("2 or 3"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseSql(env, argv[0], context));
        CHECK_RETURN(OK == ParseColumns(env, argv[1], context));
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::QueryByStep Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        context->resultSet_value = obj->rdbStore_->QueryByStep(context->sql, context->columns);
        LOG_ERROR("RdbStoreProxy::QueryByStep is nullptr ? %{public}d ", context->resultSet_value == nullptr);
        return (context->resultSet_value != nullptr) ? E_OK : E_ERROR;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = ResultSetProxy::NewInstance(env, std::shared_ptr<ResultSet>(context->resultSet_value.release()));
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
        LOG_DEBUG("RdbStoreProxy::QueryByStep end");
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
    RDB_NAPI_ASSERT(env, rdbStoreProxy && rdbStoreProxy->rdbStore_, std::make_shared<ParamError>("RdbStore", "valid"));
    bool out = rdbStoreProxy->rdbStore_->IsInTransaction();
    LOG_DEBUG("RdbStoreProxy::IsInTransaction out is : %{public}d", out);
    return JSUtils::Convert2JSValue(env, out);
}

napi_value RdbStoreProxy::IsOpen(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(env, rdbStoreProxy && rdbStoreProxy->rdbStore_, std::make_shared<ParamError>("RdbStore", "valid"));
    bool out = rdbStoreProxy->rdbStore_->IsOpen();
    LOG_DEBUG("RdbStoreProxy::IsOpen out is : %{public}d", out);
    return JSUtils::Convert2JSValue(env, out);
}

napi_value RdbStoreProxy::GetVersion(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    RDB_NAPI_ASSERT(env, rdbStoreProxy && rdbStoreProxy->rdbStore_, std::make_shared<ParamError>("RdbStore", "valid"));
    int32_t version = 0;
    int out = rdbStoreProxy->rdbStore_->GetVersion(version);
    LOG_DEBUG("RdbStoreProxy::GetVersion out is : %{public}d", out);
    return JSUtils::Convert2JSValue(env, version);
}

napi_value RdbStoreProxy::SetVersion(napi_env env, napi_callback_info info)
{
    napi_value thiz;
    size_t argc = 1;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, &thiz, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thiz);
    RDB_NAPI_ASSERT(env, rdbStoreProxy && rdbStoreProxy->rdbStore_, std::make_shared<ParamError>("RdbStore", "valid"));
    int32_t version = 0;
    napi_get_value_int32(env, args[0], &version);
    RDB_NAPI_ASSERT(env, version > 0, std::make_shared<ParamError>("version", "> 0"));
    int out = rdbStoreProxy->rdbStore_->SetVersion(version);
    LOG_DEBUG("RdbStoreProxy::SetVersion out is : %{public}d", out);
    return nullptr;
}

napi_value RdbStoreProxy::Restore(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::Restore start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 1 || argc == 2, std::make_shared<ParamNumError>("1 or 2"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseSrcName(env, argv[0], context));
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::Restore Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        return obj->rdbStore_->Restore(context->srcName, context->newKey);
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

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
napi_value RdbStoreProxy::SetDistributedTables(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::SetDistributedTables start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 1 || argc == 2, std::make_shared<ParamNumError>("1 or 2"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseTablesName(env, argv[0], context));
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::SetDistributedTables Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        int res = obj->rdbStore_->SetDistributedTables(context->tablesNames);
        LOG_INFO("RdbStoreProxy::SetDistributedTables res is : %{public}d", res);
        if (res == OHOS::NativeRdb::E_NOT_SUP) {
            RDB_NAPI_ASSERT(env, res == E_OK, std::make_shared<DeviceNotSupportedError>());
        }
        return res;
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
        CHECK_RETURN_SET_E(argc == 2 || argc == 3, std::make_shared<ParamNumError>("2 or 3"));
        CHECK_RETURN(OK == ParserThis(env, self, context));
        CHECK_RETURN(OK == ParseDevice(env, argv[0], context));
        CHECK_RETURN(OK == ParseTableName(env, argv[1], context));
    };
    auto exec = [context]() -> int {
        LOG_DEBUG("RdbStoreProxy::ObtainDistributedTableName Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        context->tableName = obj->rdbStore_->ObtainDistributedTableName(context->device, context->tableName);
        return context->tableName.empty() ? E_OK : E_ERROR;
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
        CHECK_RETURN_SET_E(argc == 2 || argc == 3, std::make_shared<ParamNumError>("2 or 3"));
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
        int res = obj->rdbStore_->Sync(option, *context->predicatesProxy->GetPredicates(),
            [context](const SyncResult &result) { context->syncResult = result; });
        LOG_INFO("RdbStoreProxy::Sync res is : %{public}d", res);
        if (res == OHOS::NativeRdb::E_NOT_SUP) {
            RDB_NAPI_ASSERT(env, res == E_OK, std::make_shared<DeviceNotSupportedError>());
        }
        return res;
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

int RdbStoreProxy::OnDataChangeEvent(napi_env env, size_t argc, napi_value *argv)
{
    napi_valuetype type;
    napi_typeof(env, argv[0], &type);
    if (type != napi_number) {
        LOG_ERROR("RdbStoreProxy::OnDataChangeEvent: first argument is not number");
        return E_ERROR;
    }
    int32_t mode = SubscribeMode::SUBSCRIBE_MODE_MAX;
    napi_get_value_int32(env, argv[0], &mode);
    if (mode < 0 || mode >= SubscribeMode::SUBSCRIBE_MODE_MAX) {
        LOG_ERROR("RdbStoreProxy::OnDataChangeEvent: first argument value is invalid");
        return E_ERROR;
    }
    LOG_INFO("RdbStoreProxy::OnDataChangeEvent: mode=%{public}d", mode);

    napi_typeof(env, argv[1], &type);
    if (type != napi_function) {
        LOG_ERROR("RdbStoreProxy::OnDataChangeEvent: second argument is not function");
        return E_ERROR;
    }

    std::lock_guard<std::mutex> lockGuard(mutex_);
    bool result = std::any_of(observers_[mode].begin(), observers_[mode].end(), [argv](const auto &observer) {
        return *observer == argv[1];
    });
    if (result) {
        LOG_ERROR("RdbStoreProxy::OnDataChangeEvent: duplicate subscribe");
        return E_ERROR;
    }
    SubscribeOption option;
    option.mode = static_cast<SubscribeMode>(mode);
    auto observer = std::make_shared<NapiRdbStoreObserver>(env, argv[1]);
    int errCode = rdbStore_->Subscribe(option, observer.get());
    if (errCode != E_OK) {
        LOG_ERROR("RdbStoreProxy::OnDataChangeEvent: subscribe failed");
        return errCode;
    }
    observers_[mode].push_back(observer);
    LOG_ERROR("RdbStoreProxy::OnDataChangeEvent: subscribe success");
    return E_OK;
}

int RdbStoreProxy::OffDataChangeEvent(napi_env env, size_t argc, napi_value *argv)
{
    napi_valuetype type;
    napi_typeof(env, argv[0], &type);
    if (type != napi_number) {
        LOG_ERROR("RdbStoreProxy::OffDataChangeEvent: first argument is not number");
        return E_ERROR;
    }
    int32_t mode = SubscribeMode::SUBSCRIBE_MODE_MAX;
    napi_get_value_int32(env, argv[0], &mode);
    if (mode < 0 || mode >= SubscribeMode::SUBSCRIBE_MODE_MAX) {
        LOG_ERROR("RdbStoreProxy::OffDataChangeEvent: first argument value is invalid");
        return E_ERROR;
    }
    LOG_INFO("RdbStoreProxy::OffDataChangeEvent: mode=%{public}d", mode);

    napi_typeof(env, argv[1], &type);
    if (type != napi_function) {
        LOG_ERROR("RdbStoreProxy::OffDataChangeEvent: second argument is not function");
        return E_ERROR;
    }

    SubscribeOption option;
    option.mode = static_cast<SubscribeMode>(mode);
    std::lock_guard<std::mutex> lockGuard(mutex_);
    for (auto it = observers_[mode].begin(); it != observers_[mode].end(); it++) {
        if (**it == argv[1]) {
            int errCode = rdbStore_->UnSubscribe(option, it->get());
            observers_[mode].erase(it);
            LOG_INFO("RdbStoreProxy::OffDataChangeEvent: unsubscribe success");
            return errCode;
        }
    }
    LOG_INFO("RdbStoreProxy::OffDataChangeEvent: not found");
    return E_ERROR;
}

napi_value RdbStoreProxy::OnEvent(napi_env env, napi_callback_info info)
{
    size_t argc = MAX_ON_EVENT_ARG_NUM;
    napi_value argv[MAX_ON_EVENT_ARG_NUM]{};
    napi_value self = nullptr;
    if (napi_get_cb_info(env, info, &argc, argv, &self, nullptr) != napi_ok) {
        LOG_ERROR("RdbStoreProxy::OnEvent: get args failed");
        return nullptr;
    }
    bool invalid_condition = argc < MIN_ON_EVENT_ARG_NUM || argc > MAX_ON_EVENT_ARG_NUM || self == nullptr;
    NAPI_ASSERT(env, !invalid_condition, "RdbStoreProxy::OnEvent: invalid args");

    auto proxy = GetNativeInstance(env, self);
    RDB_NAPI_ASSERT(env, proxy != nullptr, std::make_shared<ParamError>("RdbStore", "valid"));

    std::string event = JSUtils::Convert2String(env, argv[0]);
    if (event == "dataChange") {
        int res = proxy->OnDataChangeEvent(env, argc - 1, argv + 1);
        if (res == OHOS::NativeRdb::E_NOT_SUP) {
            RDB_NAPI_ASSERT(env, res == E_OK, std::make_shared<DeviceNotSupportedError>());
        }
    }

    LOG_INFO("RdbStoreProxy::OnEvent end");
    return nullptr;
}

napi_value RdbStoreProxy::OffEvent(napi_env env, napi_callback_info info)
{
    size_t argc = MAX_ON_EVENT_ARG_NUM;
    napi_value argv[MAX_ON_EVENT_ARG_NUM]{};
    napi_value self = nullptr;
    if (napi_get_cb_info(env, info, &argc, argv, &self, nullptr) != napi_ok) {
        LOG_ERROR("RdbStoreProxy::OffEvent: get args failed");
        return nullptr;
    }
    bool invalid_condition = argc < MIN_ON_EVENT_ARG_NUM || argc > MAX_ON_EVENT_ARG_NUM || self == nullptr;
    NAPI_ASSERT(env, !invalid_condition, "RdbStoreProxy::OffEvent: invalid args");

    auto proxy = GetNativeInstance(env, self);
    RDB_NAPI_ASSERT(env, proxy != nullptr, std::make_shared<ParamError>("RdbStore", "valid"));

    std::string event = JSUtils::Convert2String(env, argv[0]);
    if (event == "dataChange") {
        int res = proxy->OffDataChangeEvent(env, argc - 1, argv + 1);
        if (res == OHOS::NativeRdb::E_NOT_SUP) {
            RDB_NAPI_ASSERT(env, res == E_OK, std::make_shared<DeviceNotSupportedError>());
        }
    }

    LOG_INFO("RdbStoreProxy::OffEvent end");
    return nullptr;
}
#endif
} // namespace RelationalStoreJsKit
} // namespace OHOS
