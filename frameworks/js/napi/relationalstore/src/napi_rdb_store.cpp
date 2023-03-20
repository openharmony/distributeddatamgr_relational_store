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
    bool isNapiString = false;
    int BindArgs(napi_env env, napi_value arg);
    std::string device;
    std::string tableName;
    std::vector<std::string> tablesName;
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
    uint64_t rowId;
    uint64_t insertNum;
    std::vector<uint8_t> newKey;
    std::shared_ptr<ResultSet> newResultSet;
    std::unique_ptr<ResultSet> resultSet_value;
    std::string aliasName;
    std::string pathName;
    std::string destName;
    std::string srcName;
    int32_t enumArg;
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    DistributedRdb::SyncResult syncResult;
#endif
    std::shared_ptr<RdbPredicates> rdbPredicates = nullptr;

    RdbStoreContext() : predicatesProxy(nullptr), rowId(0), insertNum(0), enumArg(-1) {}
    virtual ~RdbStoreContext() {}
};

static __thread napi_ref constructor_ = nullptr;

int RdbStoreContext::BindArgs(napi_env env, napi_value arg)
{
    bindArgs.clear();
    uint32_t arrLen = 0;
    napi_get_array_length(env, arg, &arrLen);
    if (arrLen == 0) {
        return OK;
    }
    for (size_t i = 0; i < arrLen; ++i) {
        napi_value element;
        napi_get_element(env, arg, i, &element);
        napi_valuetype type;
        napi_typeof(env, element, &type);
        switch (type) {
            case napi_boolean: {
                bool value = false;
                napi_status status = napi_get_value_bool(env, element, &value);
                if (status == napi_ok) {
                    bindArgs.push_back(ValueObject(value));
                }
            } break;
            case napi_number: {
                double value;
                napi_status status = napi_get_value_double(env, element, &value);
                if (status == napi_ok) {
                    bindArgs.push_back(ValueObject(value));
                }
            } break;
            case napi_null:
                bindArgs.push_back(ValueObject());
                break;
            case napi_string:
                bindArgs.push_back(ValueObject(JSUtils::Convert2String(env, element, false)));
                break;
            case napi_object:
                bindArgs.push_back(ValueObject(JSUtils::Convert2U8Vector(env, element)));
                break;
            default:
                break;
        }
    }
    return OK;
}

RdbStoreProxy::RdbStoreProxy()
{
}

RdbStoreProxy::~RdbStoreProxy()
{
    LOG_DEBUG("RdbStoreProxy destructor");
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
        DECLARE_NAPI_FUNCTION("getVersion", GetVersion),
        DECLARE_NAPI_FUNCTION("setVersion", SetVersion),
        DECLARE_NAPI_FUNCTION("restore", Restore),
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

napi_value RdbStoreProxy::NewInstance(napi_env env, std::shared_ptr<OHOS::NativeRdb::RdbStore> value)
{
    if (value == nullptr) {
        LOG_ERROR("RdbStoreProxy::NewInstance get native rdb is null.");
        return nullptr;
    }
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
    return instance;
}

RdbStoreProxy *RdbStoreProxy::GetNativeInstance(napi_env env, napi_value self)
{
    RdbStoreProxy *proxy = nullptr;
    napi_status status = napi_unwrap(env, self, reinterpret_cast<void **>(&proxy));
    if (proxy == nullptr) {
        LOG_ERROR("RdbStoreProxy::GetNativePredicates native instance is nullptr! code:%{public}d!", status);
        return nullptr;
    }
    return proxy;
}

void ParserThis(const napi_env &env, const napi_value &self, std::shared_ptr<RdbStoreContext> context)
{
    RdbStoreProxy *obj = RdbStoreProxy::GetNativeInstance(env, self);
    context->boundObj = obj;
    LOG_DEBUG("ParserThis RdbStoreProxy end");
}

int ParseTableName(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    context->tableName = JSUtils::Convert2String(env, arg);
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("table", "a non empty string.");
    RDB_CHECK_RETURN_CALL_RESULT(!context->tableName.empty(), context->SetError(paramError));

    LOG_DEBUG("ParseTableName end");
    return OK;
}

int ParseDevice(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    context->device = JSUtils::Convert2String(env, arg);
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("device", "a non empty string.");
    RDB_CHECK_RETURN_CALL_RESULT(!context->device.empty(), context->SetError(paramError));

    LOG_DEBUG("ParseDevice end");
    return OK;
}

int ParseTablesName(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    uint32_t arrLen = 0;
    napi_get_array_length(env, arg, &arrLen);
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("tables", "a string array.");
    RDB_CHECK_RETURN_CALL_RESULT(arrLen >= 0, context->SetError(paramError));

    for (uint32_t i = 0; i < arrLen; ++i) {
        napi_value element;
        napi_get_element(env, arg, i, &element);
        napi_valuetype type;
        napi_typeof(env, element, &type);
        if (type == napi_string) {
            std::string table = JSUtils::Convert2String(env, element);
            context->tablesName.push_back(table);
        }
    }
    LOG_DEBUG("ParseTablesName end");
    return OK;
}

int ParseSyncModeArg(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    napi_valuetype type = napi_undefined;
    napi_typeof(env, arg, &type);
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("mode", "a SyncMode Type.");
    RDB_CHECK_RETURN_CALL_RESULT(type == napi_number, context->SetError(paramError));
    napi_status status = napi_get_value_int32(env, arg, &context->enumArg);
    RDB_CHECK_RETURN_CALL_RESULT(status == napi_ok, context->SetError(paramError));
    paramError = std::make_shared<ParamTypeError>("mode", "a SyncMode.");
    RDB_CHECK_RETURN_CALL_RESULT(context->enumArg == 0 || context->enumArg == 1, context->SetError(paramError));

    LOG_DEBUG("ParseSyncModeArg end");
    return OK;
}

int ParsePredicates(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    LOG_DEBUG("ParsePredicates start");
    napi_unwrap(env, arg, reinterpret_cast<void **>(&context->predicatesProxy));
    auto paramError = std::make_shared<ParamTypeError>("predicates", "an RdbPredicates.");
    RDB_CHECK_RETURN_CALL_RESULT(context->predicatesProxy != nullptr, context->SetError(paramError));
    context->tableName = context->predicatesProxy->GetPredicates()->GetTableName();
    context->rdbPredicates = context->predicatesProxy->GetPredicates();
    LOG_DEBUG("ParseRDBPredicates end");
    return OK;
}

int ParseDataSharePredicates(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    auto paramError = std::make_shared<ParamTypeError>("predicates", "an RdbPredicates or DataShare Predicates.");
    PredicatesProxy *proxy = nullptr;
    napi_unwrap(env, arg, reinterpret_cast<void **>(&proxy));
    // proxy is nullptr, it isn't rdb predicates or datashare predicates
    RDB_CHECK_RETURN_CALL_RESULT(proxy != nullptr, context->SetError(paramError));
    // proxy is not nullptr, it's a datashare predicates.
    LOG_DEBUG("Parse DataShare Predicates");
    paramError = std::make_shared<ParamTypeError>("predicates", "an DataShare Predicates.");
    LOG_ERROR("dsPredicates is null ? %{public}d", (proxy->predicates_ == nullptr));
    RDB_CHECK_RETURN_CALL_RESULT(proxy->predicates_ != nullptr, context->SetError(paramError));
    std::shared_ptr<DataShareAbsPredicates> dsPredicates = proxy->predicates_;
    context->rdbPredicates = std::make_shared<RdbPredicates>(
        RdbDataShareAdapter::RdbUtils::ToPredicates(*dsPredicates, context->tableName));
    LOG_DEBUG("ParsePredicates end");
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
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("srcName", "a non empty string.");
    RDB_CHECK_RETURN_CALL_RESULT(!context->srcName.empty(), context->SetError(paramError));

    LOG_DEBUG("ParseSrcName end");
    return OK;
}

int ParseColumns(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    context->columns = JSUtils::Convert2StrVector(env, arg);
    LOG_DEBUG("ParseColumns end");
    return OK;
}

int ParseWhereClause(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    context->whereClause = JSUtils::Convert2String(env, arg);
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("whereClause", "a non empty string.");
    RDB_CHECK_RETURN_CALL_RESULT(!context->whereClause.empty(), context->SetError(paramError));

    LOG_DEBUG("ParseWhereClause end");
    return OK;
}

int ParseAlias(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    context->aliasName = JSUtils::Convert2String(env, arg);
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("aliasName", "a non empty string.");
    RDB_CHECK_RETURN_CALL_RESULT(!context->aliasName.empty(), context->SetError(paramError));

    LOG_DEBUG("ParseAlias end");
    return OK;
}

int ParsePath(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    context->pathName = JSUtils::Convert2String(env, arg);
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("pathName", "a non empty string.");
    RDB_CHECK_RETURN_CALL_RESULT(!context->pathName.empty(), context->SetError(paramError));

    LOG_DEBUG("ParsePath end");
    return OK;
}

int ParseWhereArgs(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    context->whereArgs = JSUtils::Convert2StrVector(env, arg);
    LOG_DEBUG("ParseWhereArgs end");
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
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("sql", "a non empty string.");
    RDB_CHECK_RETURN_CALL_RESULT(!context->sql.empty(), context->SetError(paramError));

    LOG_DEBUG("ParseSql end");
    return OK;
}

int ParseValuesBucket(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    napi_value keys = 0;
    napi_get_property_names(env, arg, &keys);
    uint32_t arrLen = 0;
    napi_status status = napi_get_array_length(env, keys, &arrLen);
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("values", "a ValuesBucket.");
    RDB_CHECK_RETURN_CALL_RESULT(status == napi_ok, context->SetError(paramError));

    for (size_t i = 0; i < arrLen; ++i) {
        napi_value key;
        status = napi_get_element(env, keys, i, &key);
        RDB_CHECK_RETURN_CALL_RESULT(status == napi_ok, context->SetError(paramError));

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
    std::shared_ptr<Error> paramError = std::make_shared<ParamTypeError>("values", "a ValuesBucket array.");
    if (!isArray) {
        context->insertNum = -1;
        RDB_CHECK_RETURN_CALL_RESULT(isArray, context->SetError(paramError));
    }
    uint32_t arrLen = 0;
    napi_status status = napi_get_array_length(env, arg, &arrLen);
    RDB_CHECK_RETURN_CALL_RESULT(status == napi_ok || arrLen >= 0, context->SetError(paramError));

    for (uint32_t i = 0; i < arrLen; ++i) {
        napi_value obj = nullptr;
        status = napi_get_element(env, arg, i, &obj);
        RDB_CHECK_RETURN_CALL_RESULT(status == napi_ok || arrLen >= 0, context->SetError(paramError));

        ParseValuesBucket(env, obj, context);
        context->valuesBuckets.push_back(context->valuesBucket);
        context->valuesBucket.Clear();
    }
    return OK;
}

bool IsNapiString(napi_env env, napi_callback_info info)
{
    constexpr size_t MIN_ARGC = 1;
    size_t argc = MIN_ARGC;
    napi_value args[1] = { 0 };
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc < MIN_ARGC) {
        return false;
    }
    napi_valuetype type;
    napi_typeof(env, args[0], &type);
    if (type == napi_string) {
        return true;
    }
    return false;
}

napi_value RdbStoreProxy::Insert(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    LOG_DEBUG("RdbStoreProxy::Insert start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("2 or 3");
        RDB_CHECK_RETURN_CALL_RESULT(argc == 2 || argc == 3, context->SetError(paramNumError));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseTableName(env, argv[0], context));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseValuesBucket(env, argv[1], context));
        ParserThis(env, self, context);
        return OK;
    };
    auto exec = [context]() {
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        int64_t rowId = 0;
        LOG_DEBUG("RdbStoreProxy::Insert Async");
        int errCode = obj->rdbStore_->Insert(rowId, context->tableName, context->valuesBucket);
        context->rowId = rowId;
        LOG_DEBUG("RdbStoreProxy::Insert errCode is: %{public}d", errCode);
        return (errCode == E_OK) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_create_int64(env, context->rowId, &result);
        LOG_DEBUG("RdbStoreProxy::Insert end");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);

    RDB_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::BatchInsert(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    LOG_DEBUG("RdbStoreProxy::BatchInsert start.");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("2 or 3");
        RDB_CHECK_RETURN_CALL_RESULT(argc == 2 || argc == 3, context->SetError(paramNumError));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseTableName(env, argv[0], context));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseValuesBuckets(env, argv[1], context));
        ParserThis(env, self, context);
        return OK;
    };
    auto exec = [context]() {
        LOG_INFO("RdbStoreProxy::BatchInsert Async.");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        if (context->insertNum == -1UL) {
            return E_OK;
        }
        int64_t outInsertNum = 0;
        int errCode = obj->rdbStore_->BatchInsert(outInsertNum, context->tableName, context->valuesBuckets);
        context->insertNum = outInsertNum;
        return (errCode == E_OK) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_create_int64(env, context->insertNum, &result);
        LOG_DEBUG("RdbStoreProxy::BatchInsert end.");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);

    RDB_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::Delete(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::Delete start");
    auto context = std::make_shared<RdbStoreContext>();
    context->isNapiString = IsNapiString(env, info);
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        if (context->isNapiString) {
            std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("2 or 3");
            RDB_CHECK_RETURN_CALL_RESULT(argc == 2 || argc == 3, context->SetError(paramNumError));
            RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseTableName(env, argv[0], context));
            RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseDataSharePredicates(env, argv[1], context));
        } else {
            std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("1 or 2");
            RDB_CHECK_RETURN_CALL_RESULT(argc == 1 || argc == 2, context->SetError(paramNumError));
            RDB_ASYNC_PARAM_CHECK_FUNCTION(ParsePredicates(env, argv[0], context));
        }
        ParserThis(env, self, context);
        return OK;
    };
    auto exec = [context]() {
        LOG_DEBUG("RdbStoreProxy::Delete Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        int deletedRows = 0;
        int errCode = obj->rdbStore_->Delete(deletedRows, *(context->rdbPredicates));
        context->rowId = deletedRows;
        LOG_DEBUG("RdbStoreProxy::Delete errCode is: %{public}d", errCode);
        return (errCode == E_OK) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_create_int64(env, context->rowId, &result);
        LOG_DEBUG("RdbStoreProxy::Delete end");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);

    RDB_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::Update(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    LOG_DEBUG("RdbStoreProxy::Update start");
    auto context = std::make_shared<RdbStoreContext>();
    context->isNapiString = IsNapiString(env, info);
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        if (context->isNapiString) {
            std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("3 or 4");
            RDB_CHECK_RETURN_CALL_RESULT(argc == 3 || argc == 4, context->SetError(paramNumError));
            RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseTableName(env, argv[0], context));
            RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseValuesBucket(env, argv[1], context));
            RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseDataSharePredicates(env, argv[2], context));
        } else {
            std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("2 or 3");
            RDB_CHECK_RETURN_CALL_RESULT(argc == 2 || argc == 3, context->SetError(paramNumError));
            RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseValuesBucket(env, argv[0], context));
            RDB_ASYNC_PARAM_CHECK_FUNCTION(ParsePredicates(env, argv[1], context));
        }
        ParserThis(env, self, context);
        return OK;
    };
    auto exec = [context]() {
        LOG_DEBUG("RdbStoreProxy::Update Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        int changedRows = 0;
        int errCode = obj->rdbStore_->Update(changedRows, context->valuesBucket, *(context->rdbPredicates));
        context->rowId = changedRows;
        LOG_DEBUG("RdbStoreProxy::Update errCode is: %{public}d", errCode);
        return (errCode == E_OK) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_create_int64(env, context->rowId, &result);
        LOG_DEBUG("RdbStoreProxy::Update end");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);

    RDB_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::Query(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto context = std::make_shared<RdbStoreContext>();
    context->isNapiString = IsNapiString(env, info);
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        if (context->isNapiString) {
            std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("1, 2 or 3");
            RDB_CHECK_RETURN_CALL_RESULT(argc == 1 || argc == 2 || argc == 3, context->SetError(paramNumError));
            RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseTableName(env, argv[0], context));
            RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseDataSharePredicates(env, argv[1], context));
            if (argc > 2) {
                RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseColumns(env, argv[2], context));
            }
        } else {
            std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("1 or 2");
            RDB_CHECK_RETURN_CALL_RESULT(argc == 1 || argc == 2, context->SetError(paramNumError));
            RDB_ASYNC_PARAM_CHECK_FUNCTION(ParsePredicates(env, argv[0], context));
            if (argc > 1) {
                RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseColumns(env, argv[1], context));
            }
        }
        ParserThis(env, self, context);
        return OK;
    };
    auto exec = [context]() {
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        context->resultSet_value = obj->rdbStore_->Query(*(context->rdbPredicates), context->columns);
        LOG_DEBUG("RdbStoreProxy::Query result is nullptr ? %{public}d", (context->resultSet_value == nullptr));
        return (context->resultSet_value != nullptr) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        result = ResultSetProxy::NewInstance(env, std::shared_ptr<ResultSet>(context->resultSet_value.release()));
        return (result != nullptr) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);

    RDB_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
napi_value RdbStoreProxy::RemoteQuery(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::RemoteQuery start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("4 or 5");
        RDB_CHECK_RETURN_CALL_RESULT(argc == 4 || argc == 5, context->SetError(paramNumError));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseDevice(env, argv[0], context));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseTableName(env, argv[1], context));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParsePredicates(env, argv[2], context));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseColumns(env, argv[3], context));
        ParserThis(env, self, context);
        return OK;
    };
    auto exec = [context]() {
        LOG_DEBUG("RdbStoreProxy::RemoteQuery Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        int errCode = E_ERROR;
        context->newResultSet =
            obj->rdbStore_->RemoteQuery(context->device, *(context->rdbPredicates), context->columns, errCode);
        LOG_DEBUG("RemoteQuery ret is %{public}d.", errCode);
        std::shared_ptr<Error> notSupportError = std::make_shared<NotSupportError>();
        RDB_CHECK_RETURN_CALL_RESULT(errCode != E_NOT_SUPPORTED, context->SetError(notSupportError));
        return errCode == E_OK ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        if (context->newResultSet == nullptr) {
            LOG_DEBUG("RdbStoreProxy::RemoteQuery result is nullptr");
            return ERR;
        }
        result = ResultSetProxy::NewInstance(env, context->newResultSet);
        LOG_DEBUG("RdbStoreProxy::RemoteQuery end");
        return (result != nullptr) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);

    RDB_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}
#endif

napi_value RdbStoreProxy::QuerySql(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("1, 2 or 3");
        RDB_CHECK_RETURN_CALL_RESULT(argc == 1 || argc == 2 || argc == 3, context->SetError(paramNumError));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseSql(env, argv[0], context));
        if (argc > 1) {
#if defined(WINDOWS_PLATFORM) || defined(MAC_PLATFORM)
            RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseColumns(env, argv[1], context));
#else
            RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseSelectionArgs(env, argv[1], context));
#endif
        }
        ParserThis(env, self, context);
        return OK;
    };
    auto exec = [context]() {
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
#if defined(WINDOWS_PLATFORM) || defined(MAC_PLATFORM)
        context->resultSet_value = obj->rdbStore_->QueryByStep(context->sql, context->columns);
        LOG_ERROR("RdbStoreProxy::QuerySql is nullptr ? %{public}d ", context->resultSet_value == nullptr);
        return (context->resultSet_value != nullptr) ? OK : ERR;
#else
        std::string selectionArgs = ",";
        for (size_t i = 0; i < context->selectionArgs.size(); i++) {
            selectionArgs += context->selectionArgs[i];
        }
        context->resultSet_value = obj->rdbStore_->QuerySql(context->sql, context->selectionArgs);
        return (context->resultSet_value != nullptr) ? OK : ERR;
#endif
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        result = ResultSetProxy::NewInstance(env, std::shared_ptr<ResultSet>(context->resultSet_value.release()));
        return (result != nullptr) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);

    RDB_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

int ParseBindArgs(const napi_env &env, const napi_value &arg, std::shared_ptr<RdbStoreContext> context)
{
    context->BindArgs(env, arg);
    return OK;
}

napi_value RdbStoreProxy::ExecuteSql(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::ExecuteSql start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("1, 2 or 3");
        RDB_CHECK_RETURN_CALL_RESULT(argc == 1 || argc == 2 || argc == 3, context->SetError(paramNumError));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseSql(env, argv[0], context));
        if (argc > 1) {
            RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseBindArgs(env, argv[1], context));
        }
        ParserThis(env, self, context);
        return OK;
    };
    auto exec = [context]() {
        LOG_DEBUG("RdbStoreProxy::ExecuteSql Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        int errCode = obj->rdbStore_->ExecuteSql(context->sql, context->bindArgs);
        LOG_DEBUG("RdbStoreProxy::ExecuteSql errCode is: %{public}d", errCode);
        return (errCode == E_OK) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_get_undefined(env, &result);
        LOG_DEBUG("RdbStoreProxy::ExecuteSql end");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);

    RDB_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::Count(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::Count start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("1 or 2");
        RDB_CHECK_RETURN_CALL_RESULT(argc == 1 || argc == 2, context->SetError(paramNumError));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParsePredicates(env, argv[0], context));
        ParserThis(env, self, context);
        return OK;
    };
    auto exec = [context]() {
        LOG_DEBUG("RdbStoreProxy::Count Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        std::int64_t temp = 0;
        int errCode = obj->rdbStore_->Count(temp, *(context->predicatesProxy->GetPredicates()));
        context->rowId = temp;
        LOG_DEBUG("RdbStoreProxy::Count errCode is: %{public}d", errCode);
        return (errCode == E_OK) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_create_int64(env, context->rowId, &result);
        LOG_DEBUG("RdbStoreProxy::Count end");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);

    RDB_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::Replace(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    LOG_DEBUG("RdbStoreProxy::Replace start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("2 or 3");
        RDB_CHECK_RETURN_CALL_RESULT(argc == 2 || argc == 3, context->SetError(paramNumError));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseTableName(env, argv[0], context));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseValuesBucket(env, argv[1], context));
        ParserThis(env, self, context);
        return OK;
    };
    auto exec = [context]() {
        LOG_DEBUG("RdbStoreProxy::Replace Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        int64_t rowId = 0;
        int errCode = obj->rdbStore_->Replace(rowId, context->tableName, context->valuesBucket);
        context->rowId = rowId;
        LOG_DEBUG("RdbStoreProxy::Replace errCode is:%{public}d", errCode);
        return (errCode == E_OK) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_create_int64(env, context->rowId, &result);
        LOG_DEBUG("RdbStoreProxy::Replace end");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);

    RDB_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::Backup(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::Backup start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("1 or 2");
        RDB_CHECK_RETURN_CALL_RESULT(argc == 1 || argc == 2, context->SetError(paramNumError));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseTableName(env, argv[0], context));
        ParserThis(env, self, context);
        return OK;
    };
    auto exec = [context]() {
        LOG_DEBUG("RdbStoreProxy::Backup Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        int errCode = obj->rdbStore_->Backup(context->tableName, context->newKey);
        LOG_DEBUG("RdbStoreProxy::Backup errCode is: %{public}d", errCode);
        return (errCode == E_OK) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_get_undefined(env, &result);
        LOG_DEBUG("RdbStoreProxy::Backup end");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);

    RDB_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::Attach(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::Attach start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("3 or 4");
        RDB_CHECK_RETURN_CALL_RESULT(argc == 3 || argc == 4, context->SetError(paramNumError));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseAlias(env, argv[0], context));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParsePath(env, argv[1], context));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseNewKey(env, argv[2], context));
        ParserThis(env, self, context);
        return OK;
    };
    auto exec = [context]() {
        LOG_DEBUG("RdbStoreProxy::Attach Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        int errCode = obj->rdbStore_->Attach(context->aliasName, context->pathName, context->newKey);
        LOG_ERROR("RdbStoreProxy::Attach errCode is:%{public}d ", errCode);
        return (errCode != E_OK) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_get_undefined(env, &result);
        LOG_DEBUG("RdbStoreProxy::Attach end");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);

    RDB_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::IsHoldingConnection(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    NAPI_ASSERT(env, rdbStoreProxy != nullptr, "RdbStoreProxy is nullptr");
    bool out = rdbStoreProxy->rdbStore_->IsHoldingConnection();
    LOG_DEBUG("RdbStoreProxy::IsHoldingConnection out is : %{public}d", out);
    return JSUtils::Convert2JSValue(env, out);
}

napi_value RdbStoreProxy::IsReadOnly(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    NAPI_ASSERT(env, rdbStoreProxy != nullptr, "RdbStoreProxy is nullptr");
    bool out = rdbStoreProxy->rdbStore_->IsReadOnly();
    LOG_DEBUG("RdbStoreProxy::IsReadOnly out is : %{public}d", out);
    return JSUtils::Convert2JSValue(env, out);
}

napi_value RdbStoreProxy::IsMemoryRdb(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    NAPI_ASSERT(env, rdbStoreProxy != nullptr, "RdbStoreProxy is nullptr");
    bool out = rdbStoreProxy->rdbStore_->IsMemoryRdb();
    LOG_DEBUG("RdbStoreProxy::IsMemoryRdb out is : %{public}d", out);
    return JSUtils::Convert2JSValue(env, out);
}

napi_value RdbStoreProxy::GetPath(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    NAPI_ASSERT(env, rdbStoreProxy != nullptr, "RdbStoreProxy is nullptr");
    std::string path = rdbStoreProxy->rdbStore_->GetPath();
    LOG_DEBUG("RdbStoreProxy::GetPath path is empty ? %{public}d", path.empty());
    return JSUtils::Convert2JSValue(env, path);
}

napi_value RdbStoreProxy::BeginTransaction(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr));
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    NAPI_ASSERT(env, rdbStoreProxy != nullptr, "RdbStoreProxy is nullptr");
    int errCode = rdbStoreProxy->rdbStore_->BeginTransaction();
    NAPI_ASSERT(env, errCode == E_OK, "call BeginTransaction failed");
    LOG_DEBUG("RdbStoreProxy::BeginTransaction end, errCode is:%{public}d", errCode);
    return nullptr;
}

napi_value RdbStoreProxy::RollBack(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr));
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    NAPI_ASSERT(env, rdbStoreProxy != nullptr, "RdbStoreProxy is nullptr");
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
    NAPI_ASSERT(env, rdbStoreProxy != nullptr, "RdbStoreProxy is nullptr");
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
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("2 or 3");
        RDB_CHECK_RETURN_CALL_RESULT(argc == 2 || argc == 3, context->SetError(paramNumError));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseSql(env, argv[0], context));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseColumns(env, argv[1], context));
        ParserThis(env, self, context);
        return OK;
    };
    auto exec = [context]() {
        LOG_DEBUG("RdbStoreProxy::QueryByStep Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        context->resultSet_value = obj->rdbStore_->QueryByStep(context->sql, context->columns);
        LOG_ERROR("RdbStoreProxy::QueryByStep is nullptr ? %{public}d ", context->resultSet_value == nullptr);
        return (context->resultSet_value != nullptr) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        if (context->resultSet_value != nullptr) {
            result = ResultSetProxy::NewInstance(env, std::shared_ptr<ResultSet>(context->resultSet_value.release()));
        }
        LOG_DEBUG("RdbStoreProxy::QueryByStep end");
        return (result != nullptr) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);

    RDB_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::IsInTransaction(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    NAPI_ASSERT(env, rdbStoreProxy != nullptr, "RdbStoreProxy is nullptr");
    bool out = rdbStoreProxy->rdbStore_->IsInTransaction();
    LOG_DEBUG("RdbStoreProxy::IsInTransaction out is : %{public}d", out);
    return JSUtils::Convert2JSValue(env, out);
}

napi_value RdbStoreProxy::IsOpen(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    NAPI_ASSERT(env, rdbStoreProxy != nullptr, "RdbStoreProxy is nullptr");
    bool out = rdbStoreProxy->rdbStore_->IsOpen();
    LOG_DEBUG("RdbStoreProxy::IsOpen out is : %{public}d", out);
    return JSUtils::Convert2JSValue(env, out);
}

napi_value RdbStoreProxy::GetVersion(napi_env env, napi_callback_info info)
{
    napi_value thisObj = nullptr;
    napi_get_cb_info(env, info, nullptr, nullptr, &thisObj, nullptr);
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thisObj);
    NAPI_ASSERT(env, rdbStoreProxy != nullptr, "RdbStoreProxy is nullptr");
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
    NAPI_ASSERT(env, argc == 1, "RdbStoreProxy::SetVersion Invalid argvs!");
    RdbStoreProxy *rdbStoreProxy = GetNativeInstance(env, thiz);
    NAPI_ASSERT(env, rdbStoreProxy != nullptr, "RdbStoreProxy is nullptr");
    int32_t version = 0;
    napi_get_value_int32(env, args[0], &version);
    int out = rdbStoreProxy->rdbStore_->SetVersion(version);
    LOG_DEBUG("RdbStoreProxy::SetVersion out is : %{public}d", out);
    return nullptr;
}

napi_value RdbStoreProxy::Restore(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::Restore start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("1 or 2");
        RDB_CHECK_RETURN_CALL_RESULT(argc == 1 || argc == 2, context->SetError(paramNumError));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseSrcName(env, argv[0], context));
        ParserThis(env, self, context);
        return OK;
    };
    auto exec = [context]() {
        LOG_DEBUG("RdbStoreProxy::Restore Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        int errCode = 0;
        errCode = obj->rdbStore_->Restore(context->srcName, context->newKey);
        LOG_DEBUG("RdbStoreProxy::Restore errCode is : %{public}d", errCode);
        return (errCode == E_OK) ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_get_undefined(env, &result);
        LOG_DEBUG("RdbStoreProxy::Restore end");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);

    RDB_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
napi_value RdbStoreProxy::SetDistributedTables(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::SetDistributedTables start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("1 or 2");
        RDB_CHECK_RETURN_CALL_RESULT(argc == 1 || argc == 2, context->SetError(paramNumError));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseTablesName(env, argv[0], context));
        ParserThis(env, self, context);
        return OK;
    };
    auto exec = [context]() {
        LOG_DEBUG("RdbStoreProxy::SetDistributedTables Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        int res = obj->rdbStore_->SetDistributedTables(context->tablesName);
        LOG_DEBUG("RdbStoreProxy::SetDistributedTables res is : %{public}d", res);
        std::shared_ptr<Error> notSupportError = std::make_shared<NotSupportError>();
        RDB_CHECK_RETURN_CALL_RESULT(res != E_NOT_SUPPORTED, context->SetError(notSupportError));
        return res == E_OK ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status = napi_get_undefined(env, &result);
        LOG_DEBUG("RdbStoreProxy::SetDistributedTables end");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);

    RDB_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::ObtainDistributedTableName(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::ObtainDistributedTableName start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("2 or 3");
        RDB_CHECK_RETURN_CALL_RESULT(argc == 2 || argc == 3, context->SetError(paramNumError));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseDevice(env, argv[0], context));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseTableName(env, argv[1], context));
        ParserThis(env, self, context);
        return OK;
    };
    auto exec = [context]() {
        LOG_DEBUG("RdbStoreProxy::ObtainDistributedTableName Async");
        RdbStoreProxy *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        int errCode = E_ERROR;
        context->tableName = obj->rdbStore_->ObtainDistributedTableName(context->device, context->tableName, errCode);
        LOG_INFO("ObtainDistributedTableName ret is %{public}d.", errCode);
        std::shared_ptr<Error> notSupportError = std::make_shared<NotSupportError>();
        RDB_CHECK_RETURN_CALL_RESULT(errCode != E_NOT_SUPPORTED, context->SetError(notSupportError));
        return errCode == E_OK ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        napi_status status =
            napi_create_string_utf8(env, context->tableName.c_str(), context->tableName.length(), &result);
        LOG_DEBUG("RdbStoreProxy::ObtainDistributedTableName end");
        return (status == napi_ok) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);

    RDB_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

napi_value RdbStoreProxy::Sync(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("RdbStoreProxy::Sync start");
    auto context = std::make_shared<RdbStoreContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) -> int {
        std::shared_ptr<Error> paramNumError = std::make_shared<ParamNumError>("2 or 3");
        RDB_CHECK_RETURN_CALL_RESULT(argc == 2 || argc == 3, context->SetError(paramNumError));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParseSyncModeArg(env, argv[0], context));
        RDB_ASYNC_PARAM_CHECK_FUNCTION(ParsePredicates(env, argv[1], context));
        ParserThis(env, self, context);
        return OK;
    };
    auto exec = [context]() {
        LOG_DEBUG("RdbStoreProxy::Sync Async");
        auto *obj = reinterpret_cast<RdbStoreProxy *>(context->boundObj);
        SyncOption option;
        option.mode = static_cast<DistributedRdb::SyncMode>(context->enumArg);
        option.isBlock = true;
        int res = obj->rdbStore_->Sync(option, *context->predicatesProxy->GetPredicates(),
            [context](const SyncResult &result) { context->syncResult = result; });
        LOG_INFO("RdbStoreProxy::Sync res is : %{public}d", res);
        std::shared_ptr<Error> notSupportError = std::make_shared<NotSupportError>();
        RDB_CHECK_RETURN_CALL_RESULT(res != E_NOT_SUPPORTED, context->SetError(notSupportError));
        return res == E_OK ? OK : ERR;
    };
    auto output = [context](napi_env env, napi_value &result) -> int {
        result = JSUtils::Convert2JSValue(env, context->syncResult);
        LOG_DEBUG("RdbStoreProxy::Sync end");
        return (result != nullptr) ? OK : ERR;
    };
    context->SetAction(env, info, input, exec, output);

    RDB_CHECK_RETURN_NULLPTR(context->error == nullptr || context->error->GetCode() == OK);
    return AsyncCall::Call(env, context);
}

int RdbStoreProxy::OnDataChangeEvent(napi_env env, size_t argc, napi_value *argv)
{
    napi_valuetype type;
    napi_typeof(env, argv[0], &type);
    if (type != napi_number) {
        LOG_ERROR("RdbStoreProxy::OnDataChangeEvent: first argument is not number");
        return ERR;
    }
    int32_t mode = SubscribeMode::SUBSCRIBE_MODE_MAX;
    napi_get_value_int32(env, argv[0], &mode);
    if (mode < 0 || mode >= SubscribeMode::SUBSCRIBE_MODE_MAX) {
        LOG_ERROR("RdbStoreProxy::OnDataChangeEvent: first argument value is invalid");
        return ERR;
    }
    LOG_INFO("RdbStoreProxy::OnDataChangeEvent: mode=%{public}d", mode);

    napi_typeof(env, argv[1], &type);
    if (type != napi_function) {
        LOG_ERROR("RdbStoreProxy::OnDataChangeEvent: second argument is not function");
        return ERR;
    }

    std::lock_guard<std::mutex> lockGuard(mutex_);
    for (const auto &observer : observers_[mode]) {
        if (*observer == argv[1]) {
            LOG_ERROR("RdbStoreProxy::OnDataChangeEvent: duplicate subscribe");
            return ERR;
        }
    }
    SubscribeOption option;
    option.mode = static_cast<SubscribeMode>(mode);
    auto observer = std::make_shared<NapiRdbStoreObserver>(env, argv[1]);
    int errCode = rdbStore_->Subscribe(option, observer.get());
    LOG_DEBUG("Subscribe ret is %{public}d.", errCode);
    RDB_NAPI_ASSERT_BASE(env, errCode != E_NOT_SUPPORTED, std::make_shared<NotSupportError>(), ERR);
    observers_[mode].push_back(observer);
    LOG_ERROR("RdbStoreProxy::OnDataChangeEvent: subscribe success");
    return OK;
}

int RdbStoreProxy::OffDataChangeEvent(napi_env env, size_t argc, napi_value *argv)
{
    napi_valuetype type;
    napi_typeof(env, argv[0], &type);
    if (type != napi_number) {
        LOG_ERROR("RdbStoreProxy::OffDataChangeEvent: first argument is not number");
        return ERR;
    }
    int32_t mode = SubscribeMode::SUBSCRIBE_MODE_MAX;
    napi_get_value_int32(env, argv[0], &mode);
    if (mode < 0 || mode >= SubscribeMode::SUBSCRIBE_MODE_MAX) {
        LOG_ERROR("RdbStoreProxy::OffDataChangeEvent: first argument value is invalid");
        return ERR;
    }
    LOG_INFO("RdbStoreProxy::OffDataChangeEvent: mode=%{public}d", mode);

    napi_typeof(env, argv[1], &type);
    if (type != napi_function) {
        LOG_ERROR("RdbStoreProxy::OffDataChangeEvent: second argument is not function");
        return ERR;
    }

    SubscribeOption option;
    option.mode = static_cast<SubscribeMode>(mode);
    std::lock_guard<std::mutex> lockGuard(mutex_);
    for (auto it = observers_[mode].begin(); it != observers_[mode].end(); it++) {
        if (**it == argv[1]) {
            int errCode = rdbStore_->UnSubscribe(option, it->get());
            observers_[mode].erase(it);
            LOG_INFO("Unsubscribe err is %{public}d.", errCode);
            RDB_NAPI_ASSERT_BASE(env, errCode != E_NOT_SUPPORTED, std::make_shared<NotSupportError>(), ERR);
            return OK;
        }
    }
    LOG_INFO("RdbStoreProxy::OffDataChangeEvent: not found");
    return ERR;
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

    auto proxy = RdbStoreProxy::GetNativeInstance(env, self);
    NAPI_ASSERT(env, proxy != nullptr, "RdbStoreProxy::OnEvent: invalid args");

    std::string event = JSUtils::Convert2String(env, argv[0]);
    if (event == "dataChange") {
        if (proxy->OnDataChangeEvent(env, argc - 1, argv + 1) != OK) {
            return nullptr;
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

    auto proxy = RdbStoreProxy::GetNativeInstance(env, self);
    NAPI_ASSERT(env, proxy != nullptr, "RdbStoreProxy::OffEvent: invalid args");

    std::string event = JSUtils::Convert2String(env, argv[0]);
    if (event == "dataChange") {
        if (proxy->OffDataChangeEvent(env, argc - 1, argv + 1) != OK) {
            return nullptr;
        }
    }

    LOG_INFO("RdbStoreProxy::OffEvent end");
    return nullptr;
}
#endif
} // namespace RelationalStoreJsKit
} // namespace OHOS
