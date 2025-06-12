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

#define LOG_TAG "TransactionProxy"
#include "napi_transaction.h"

#include "js_df_manager.h"
#include "js_utils.h"
#include "napi_async_call.h"
#include "napi_rdb_error.h"
#include "napi_rdb_js_utils.h"
#include "napi_rdb_predicates.h"
#include "napi_result_set.h"
#include "rdb_common.h"
#include "rdb_errno.h"
using namespace OHOS::Rdb;
using namespace OHOS::NativeRdb;
using namespace OHOS::AppDataMgrJsKit;
namespace OHOS::RelationalStoreJsKit {
#define ASSERT_RETURN_SET_ERROR(assertion, paramError) \
    CHECK_RETURN_CORE(assertion, SetError(paramError), ERR)

struct TransactionContext : public ContextBase {
    void GetInstance(napi_value self)
    {
        auto status = napi_unwrap(env_, self, reinterpret_cast<void **>(&boundObj));
        if (status != napi_ok || boundObj == nullptr) {
            LOG_ERROR("TransactionProxy native instance is nullptr! code:%{public}d!", status);
            return;
        }
        transaction_ = reinterpret_cast<TransactionProxy *>(boundObj)->GetInstance();
    }
    std::shared_ptr<NativeRdb::Transaction> StealTransaction()
    {
        auto trans = std::move(transaction_);
        transaction_ = nullptr;
        return trans;
    }
    int32_t ParseRdbPredicatesProxy(napi_env env, napi_value arg, std::shared_ptr<RdbPredicates> &predicates);
    int32_t ParseSendableValuesBucket(napi_env env, napi_value arg, ValuesBucket &valuesBucket);
    int32_t ParseValuesBucket(napi_env env, napi_value arg, ValuesBucket &valuesBucket);
    int32_t ParseValuesBuckets(napi_env env, napi_value arg, std::vector<ValuesBucket> &valuesBuckets);
    int32_t ParseValuesBuckets(napi_env env, napi_value arg, ValuesBuckets &valuesBuckets);
    int32_t ParseConflictResolution(napi_env env, napi_value arg, NativeRdb::ConflictResolution &conflictResolution);
    std::shared_ptr<NativeRdb::Transaction> transaction_ = nullptr;
    static constexpr int32_t KEY_INDEX = 0;
    static constexpr int32_t VALUE_INDEX = 1;
};

int32_t TransactionContext::ParseRdbPredicatesProxy(
    napi_env env, napi_value arg, std::shared_ptr<RdbPredicates> &predicates)
{
    RdbPredicatesProxy *predicatesProxy = nullptr;
    auto status = napi_unwrap(env, arg, reinterpret_cast<void **>(&predicatesProxy));
    ASSERT_RETURN_SET_ERROR(status == napi_ok && predicatesProxy != nullptr,
        std::make_shared<ParamError>("predicates", "an RdbPredicates."));
    predicates = predicatesProxy->GetInstance();
    ASSERT_RETURN_SET_ERROR(predicates != nullptr, std::make_shared<ParamError>("predicates", "an RdbPredicates."));
    return OK;
}

int32_t TransactionContext::ParseSendableValuesBucket(
    const napi_env env, const napi_value map, ValuesBucket &valuesBucket)
{
    uint32_t length = 0;
    napi_status status = napi_map_get_size(env, map, &length);
    auto error = std::make_shared<ParamError>("ValuesBucket is invalid.");
    ASSERT_RETURN_SET_ERROR(status == napi_ok && length > 0, error);
    napi_value entries = nullptr;
    status = napi_map_get_entries(env, map, &entries);
    ASSERT_RETURN_SET_ERROR(status == napi_ok, std::make_shared<InnerError>("napi_map_get_entries failed."));
    for (uint32_t i = 0; i < length; ++i) {
        napi_value iter = nullptr;
        status = napi_map_iterator_get_next(env, entries, &iter);
        ASSERT_RETURN_SET_ERROR(status == napi_ok, std::make_shared<InnerError>("napi_map_iterator_get_next failed."));
        napi_value values = nullptr;
        status = napi_get_named_property(env, iter, "value", &values);
        ASSERT_RETURN_SET_ERROR(
            status == napi_ok, std::make_shared<InnerError>("napi_get_named_property value failed."));
        napi_value key = nullptr;
        status = napi_get_element(env, values, KEY_INDEX, &key);
        ASSERT_RETURN_SET_ERROR(status == napi_ok, std::make_shared<InnerError>("napi_get_element key failed."));
        std::string keyStr = JSUtils::Convert2String(env, key);
        napi_value value = nullptr;
        status = napi_get_element(env, values, VALUE_INDEX, &value);
        ASSERT_RETURN_SET_ERROR(status == napi_ok, std::make_shared<InnerError>("napi_get_element value failed."));
        ValueObject valueObject;
        int32_t ret = JSUtils::Convert2Value(env, value, valueObject.value);
        if (ret == napi_ok) {
            valuesBucket.values_.insert_or_assign(std::move(keyStr), std::move(valueObject));
        } else if (ret != napi_generic_failure) {
            ASSERT_RETURN_SET_ERROR(false, std::make_shared<ParamError>("The value type of " + keyStr, "invalid."));
        }
    }
    return OK;
}

int32_t TransactionContext::ParseValuesBucket(napi_env env, napi_value arg, ValuesBucket &valuesBucket)
{
    bool isMap = false;
    napi_status status = napi_is_map(env, arg, &isMap);
    ASSERT_RETURN_SET_ERROR(
        status == napi_ok, std::make_shared<InnerError>("call napi_is_map failed" + std::to_string(status)));
    if (isMap) {
        return ParseSendableValuesBucket(env, arg, valuesBucket);
    }
    napi_value keys = nullptr;
    napi_get_all_property_names(env, arg, napi_key_own_only,
        static_cast<napi_key_filter>(napi_key_enumerable | napi_key_skip_symbols), napi_key_numbers_to_strings, &keys);
    uint32_t arrLen = 0;
    status = napi_get_array_length(env, keys, &arrLen);
    ASSERT_RETURN_SET_ERROR(status == napi_ok && arrLen > 0, std::make_shared<ParamError>("ValuesBucket is invalid"));

    for (size_t i = 0; i < arrLen; ++i) {
        napi_value key = nullptr;
        status = napi_get_element(env, keys, i, &key);
        ASSERT_RETURN_SET_ERROR(status == napi_ok, std::make_shared<ParamError>("ValuesBucket is invalid."));
        std::string keyStr = JSUtils::Convert2String(env, key);
        napi_value value = nullptr;
        napi_get_property(env, arg, key, &value);
        ValueObject valueObject;
        int32_t ret = JSUtils::Convert2Value(env, value, valueObject.value);
        if (ret == napi_ok) {
            valuesBucket.values_.insert_or_assign(std::move(keyStr), std::move(valueObject));
        } else if (ret != napi_generic_failure) {
            ASSERT_RETURN_SET_ERROR(false, std::make_shared<ParamError>("The value type of " + keyStr, "invalid."));
        }
    }
    return OK;
}

int32_t TransactionContext::ParseValuesBuckets(napi_env env, napi_value arg, std::vector<ValuesBucket> &valuesBuckets)
{
    bool isArray = false;
    auto status = napi_is_array(env, arg, &isArray);
    ASSERT_RETURN_SET_ERROR(status == napi_ok && isArray, std::make_shared<ParamError>("ValuesBucket is invalid."));

    uint32_t arrLen = 0;
    status = napi_get_array_length(env, arg, &arrLen);
    ASSERT_RETURN_SET_ERROR(status == napi_ok && arrLen > 0, std::make_shared<ParamError>("ValuesBucket is invalid."));

    for (uint32_t i = 0; i < arrLen; ++i) {
        napi_value obj = nullptr;
        status = napi_get_element(env, arg, i, &obj);
        ASSERT_RETURN_SET_ERROR(status == napi_ok, std::make_shared<InnerError>("napi_get_element failed."));
        ValuesBucket valuesBucket;
        ASSERT_RETURN_SET_ERROR(
            ParseValuesBucket(env, obj, valuesBucket) == OK, std::make_shared<ParamError>("ValuesBucket is invalid."));
        valuesBuckets.push_back(std::move(valuesBucket));
    }
    return OK;
}

int32_t TransactionContext::ParseValuesBuckets(napi_env env, napi_value arg, ValuesBuckets &valuesBuckets)
{
    bool isArray = false;
    auto status = napi_is_array(env, arg, &isArray);
    ASSERT_RETURN_SET_ERROR(status == napi_ok && isArray, std::make_shared<ParamError>("ValuesBucket is invalid."));

    uint32_t arrLen = 0;
    status = napi_get_array_length(env, arg, &arrLen);
    ASSERT_RETURN_SET_ERROR(status == napi_ok && arrLen > 0, std::make_shared<ParamError>("ValuesBucket is invalid."));

    for (uint32_t i = 0; i < arrLen; ++i) {
        napi_value obj = nullptr;
        status = napi_get_element(env, arg, i, &obj);
        ASSERT_RETURN_SET_ERROR(status == napi_ok, std::make_shared<InnerError>("napi_get_element failed."));
        ValuesBucket valuesBucket;
        ASSERT_RETURN_SET_ERROR(
            ParseValuesBucket(env, obj, valuesBucket) == OK, std::make_shared<ParamError>("ValuesBucket is invalid."));
        valuesBuckets.Put(std::move(valuesBucket));
    }
    return OK;
}

int32_t TransactionContext::ParseConflictResolution(
    const napi_env env, const napi_value arg, NativeRdb::ConflictResolution &conflictResolution)
{
    int32_t input = 0;
    auto status = napi_get_value_int32(env, arg, &input);
    int32_t min = static_cast<int32_t>(NativeRdb::ConflictResolution::ON_CONFLICT_NONE);
    int32_t max = static_cast<int32_t>(NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    bool checked = status == napi_ok && (input >= min) && (input <= max);
    ASSERT_RETURN_SET_ERROR(checked, std::make_shared<ParamError>("conflictResolution", "a ConflictResolution."));
    conflictResolution = static_cast<NativeRdb::ConflictResolution>(input);
    return OK;
}

napi_value TransactionProxy::NewInstance(napi_env env, std::shared_ptr<NativeRdb::Transaction> transaction)
{
    napi_value cons = JSUtils::GetClass(env, "ohos.data.relationalStore", "Transaction");
    if (cons == nullptr) {
        LOG_ERROR("Constructor of Transaction is nullptr!");
        return nullptr;
    }
    napi_value instance = nullptr;
    auto status = napi_new_instance(env, cons, 0, nullptr, &instance);
    if (status != napi_ok) {
        LOG_ERROR("NewInstance napi_new_instance failed! code:%{public}d!", status);
        return nullptr;
    }

    TransactionProxy *proxy = nullptr;
    status = napi_unwrap(env, instance, reinterpret_cast<void **>(&proxy));
    if (status != napi_ok || proxy == nullptr) {
        LOG_ERROR("NewInstance native instance is nullptr! code:%{public}d!", status);
        return nullptr;
    }
    proxy->SetInstance(std::move(transaction));
    return instance;
}

void TransactionProxy::Init(napi_env env, napi_value exports)
{
    auto lambda = []() -> std::vector<napi_property_descriptor> {
        std::vector<napi_property_descriptor> properties = {
            DECLARE_NAPI_FUNCTION("rollback", Rollback),
            DECLARE_NAPI_FUNCTION("commit", Commit),
            DECLARE_NAPI_FUNCTION_WITH_DATA("delete", Delete, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("update", Update, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("insert", Insert, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("batchInsert", BatchInsert, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA(
                "batchInsertWithConflictResolution", BatchInsertWithConflictResolution, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("query", Query, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("querySql", QuerySql, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("execute", Execute, ASYNC),
        };
        AddSyncFunctions(properties);
        return properties;
    };
    auto jsCtor = JSUtils::DefineClass(env, "ohos.data.relationalStore", "Transaction", lambda, Initialize);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, exports, "Transaction", jsCtor));

    LOG_DEBUG("TransactionProxy::Init end.");
}

void TransactionProxy::AddSyncFunctions(std::vector<napi_property_descriptor> &properties)
{
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("deleteSync", Delete, SYNC));
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("updateSync", Update, SYNC));
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("insertSync", Insert, SYNC));
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("batchInsertSync", BatchInsert, SYNC));
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("batchInsertWithConflictResolutionSync",
        BatchInsertWithConflictResolution, SYNC));
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("querySync", Query, SYNC));
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("querySqlSync", QuerySql, SYNC));
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("executeSync", Execute, SYNC));
}

TransactionProxy::~TransactionProxy()
{
}

TransactionProxy::TransactionProxy(std::shared_ptr<NativeRdb::Transaction> transaction)
{
    if (GetInstance() == transaction) {
        return;
    }
    SetInstance(std::move(transaction));
}

napi_value TransactionProxy::Initialize(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &self, nullptr));
    auto *proxy = new (std::nothrow) TransactionProxy();
    if (proxy == nullptr) {
        LOG_ERROR("No memory, new TransactionProxy failed!");
        return nullptr;
    }
    auto finalize = [](napi_env env, void *data, void *hint) {
        auto tid = JSDFManager::GetInstance().GetFreedTid(data);
        if (tid != 0) {
            LOG_ERROR("(T:%{public}d) freed! data:0x%016" PRIXPTR, tid, uintptr_t(data) & LOWER_24_BITS_MASK);
        }
        if (data != hint) {
            LOG_ERROR("Memory corrupted! data:0x%016" PRIXPTR "hint:0x%016" PRIXPTR,
                uintptr_t(data) & LOWER_24_BITS_MASK, uintptr_t(hint) & LOWER_24_BITS_MASK);
            return;
        }
        TransactionProxy *proxy = reinterpret_cast<TransactionProxy *>(data);
        proxy->SetInstance(nullptr);
        delete proxy;
    };
    napi_status status = napi_wrap(env, self, proxy, finalize, proxy, nullptr);
    if (status != napi_ok) {
        LOG_ERROR("napi_wrap failed! code:%{public}d!", status);
        finalize(env, proxy, proxy);
        return nullptr;
    }
    JSDFManager::GetInstance().AddNewInfo(proxy);
    return self;
}

struct CommitContext : public TransactionContext {
    int32_t Parse(napi_env env, size_t argc, napi_value *argv, napi_value self)
    {
        GetInstance(self);
        ASSERT_RETURN_SET_ERROR(transaction_ != nullptr, std::make_shared<ParamError>("transaction", "a transaction."));
        return OK;
    }
};
/*
 * [JS API Prototype]
 * [Promise]
 *      commit(): Promise<void>;
 */
napi_value TransactionProxy::Commit(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<CommitContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        context->Parse(env, argc, argv, self);
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->transaction_ != nullptr);
        return context->StealTransaction()->Commit();
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

struct RollbackContext : public TransactionContext {
    int32_t Parse(napi_env env, size_t argc, napi_value *argv, napi_value self)
    {
        GetInstance(self);
        ASSERT_RETURN_SET_ERROR(transaction_ != nullptr, std::make_shared<ParamError>("transaction", "a transaction."));
        return OK;
    }
};

/*
 * [JS API Prototype]
 * [Promise]
 *      rollback(): Promise<void>;
 */
napi_value TransactionProxy::Rollback(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<RollbackContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        context->Parse(env, argc, argv, self);
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->transaction_ != nullptr);
        return context->StealTransaction()->Rollback();
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_get_undefined(env, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

struct DeleteContext : public TransactionContext {
    int32_t Parse(napi_env env, size_t argc, napi_value *argv, napi_value self)
    {
        ASSERT_RETURN_SET_ERROR(argc == 1, std::make_shared<ParamNumError>("1"));
        GetInstance(self);
        ASSERT_RETURN_SET_ERROR(transaction_ != nullptr, std::make_shared<ParamError>("transaction", "a transaction."));
        CHECK_RETURN_ERR(ParseRdbPredicatesProxy(env, argv[0], rdbPredicates) == OK);
        return OK;
    }
    std::shared_ptr<RdbPredicates> rdbPredicates = nullptr;

    int64_t deleteRows = -1;
};

/*
 * [JS API Prototype]
 * [Promise]
 *      delete(predicates: RdbPredicates): Promise<number>;
 */
napi_value TransactionProxy::Delete(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<DeleteContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        context->Parse(env, argc, argv, self);
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->transaction_ != nullptr && context->rdbPredicates != nullptr);
        auto [code, deleteRows] = context->StealTransaction()->Delete(*(context->rdbPredicates));
        context->deleteRows = deleteRows;
        return code;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->deleteRows, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

struct UpdateContext : public TransactionContext {
    int32_t Parse(napi_env env, size_t argc, napi_value *argv, napi_value self)
    {
        ASSERT_RETURN_SET_ERROR(argc == 2 || argc == 3, std::make_shared<ParamNumError>("2 to 3"));
        GetInstance(self);
        ASSERT_RETURN_SET_ERROR(transaction_ != nullptr, std::make_shared<ParamError>("transaction", "a transaction."));
        CHECK_RETURN_ERR(ParseValuesBucket(env, argv[0], valuesBucket) == OK);
        CHECK_RETURN_ERR(ParseRdbPredicatesProxy(env, argv[1], rdbPredicates) == OK);
        // 'argv[2]' is an optional parameter
        if (argc > 2 && !JSUtils::IsNull(env, argv[2])) {
            // 'argv[2]' represents a ConflictResolution parameter
            CHECK_RETURN_ERR(ParseConflictResolution(env, argv[2], conflictResolution));
        }
        return OK;
    }
    ValuesBucket valuesBucket;
    std::shared_ptr<RdbPredicates> rdbPredicates = nullptr;
    NativeRdb::ConflictResolution conflictResolution = ConflictResolution::ON_CONFLICT_NONE;

    int64_t updateRows = -1;
};

/*
 * [JS API Prototype]
 * [Promise]
 *      update(values: ValuesBucket, predicates: RdbPredicates, conflict?: ConflictResolution): Promise<number>;
 */
napi_value TransactionProxy::Update(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<UpdateContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        context->Parse(env, argc, argv, self);
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->transaction_ != nullptr && context->rdbPredicates != nullptr);
        auto [code, updateRows] = context->StealTransaction()->Update(
            context->valuesBucket, *context->rdbPredicates, context->conflictResolution);
        context->updateRows = updateRows;
        return code;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->updateRows, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

struct InsertContext : public TransactionContext {
    int32_t Parse(napi_env env, size_t argc, napi_value *argv, napi_value self)
    {
        ASSERT_RETURN_SET_ERROR(argc == 2 || argc == 3, std::make_shared<ParamNumError>("2 to 3"));
        GetInstance(self);
        ASSERT_RETURN_SET_ERROR(transaction_ != nullptr, std::make_shared<ParamError>("transaction", "a transaction."));
        CHECK_RETURN_ERR(JSUtils::Convert2Value(env, argv[0], tableName) == OK);
        CHECK_RETURN_ERR(ParseValuesBucket(env, argv[1], valuesBucket) == OK);
        // 'argv[2]' is an optional parameter
        if (argc > 2 && !JSUtils::IsNull(env, argv[2])) {
            // 'argv[2]' represents a ConflictResolution parameter
            CHECK_RETURN_ERR(ParseConflictResolution(env, argv[2], conflictResolution));
        }
        return OK;
    }
    std::string tableName;
    ValuesBucket valuesBucket;
    NativeRdb::ConflictResolution conflictResolution = ConflictResolution::ON_CONFLICT_NONE;

    int64_t insertRows = -1;
};

/*
 * [JS API Prototype]
 * [Promise]
 *      insert(table: string, values: ValuesBucket, conflict?: ConflictResolution): Promise<number>;
 */
napi_value TransactionProxy::Insert(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<InsertContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        context->Parse(env, argc, argv, self);
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->transaction_ != nullptr);
        auto [code, insertRows] = context->StealTransaction()->Insert(
            context->tableName, context->valuesBucket, context->conflictResolution);
        context->insertRows = insertRows;
        return code;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->insertRows, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

struct BatchInsertContext : public TransactionContext {
    int32_t Parse(napi_env env, size_t argc, napi_value *argv, napi_value self)
    {
        ASSERT_RETURN_SET_ERROR(argc == 2, std::make_shared<ParamNumError>("2"));
        GetInstance(self);
        ASSERT_RETURN_SET_ERROR(transaction_ != nullptr, std::make_shared<ParamError>("transaction", "a transaction."));
        ASSERT_RETURN_SET_ERROR(
            JSUtils::Convert2Value(env, argv[0], tableName) == OK, std::make_shared<ParamError>("table", "a string."));
        CHECK_RETURN_ERR(ParseValuesBuckets(env, argv[1], valuesBuckets) == OK);
        ASSERT_RETURN_SET_ERROR(!JSUtils::HasDuplicateAssets(valuesBuckets),
            std::make_shared<ParamError>("Duplicate assets are not allowed"));
        return OK;
    }
    std::string tableName;
    std::vector<ValuesBucket> valuesBuckets;

    int64_t insertRows = -1;
};

/*
 * [JS API Prototype]
 * [Promise]
 *      batchInsert(table: string, values: Array<ValuesBucket>): Promise<number>;
 */
napi_value TransactionProxy::BatchInsert(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<BatchInsertContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        context->Parse(env, argc, argv, self);
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->transaction_ != nullptr);
        auto [code, insertRows] = context->StealTransaction()->BatchInsert(context->tableName, context->valuesBuckets);
        context->insertRows = insertRows;
        return code;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->insertRows, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

struct BatchInsertWithConflictResolutionContext : public TransactionContext {
    int32_t Parse(napi_env env, size_t argc, napi_value *argv, napi_value self)
    {
        ASSERT_RETURN_SET_ERROR(argc == 3, std::make_shared<ParamNumError>("3"));
        GetInstance(self);
        ASSERT_RETURN_SET_ERROR(transaction_ != nullptr, std::make_shared<ParamError>("transaction", "a transaction."));
        ASSERT_RETURN_SET_ERROR(
            JSUtils::Convert2Value(env, argv[0], tableName) == OK, std::make_shared<ParamError>("table", "a string."));
        CHECK_RETURN_ERR(ParseValuesBuckets(env, argv[1], valuesBuckets) == OK);
        ASSERT_RETURN_SET_ERROR(!JSUtils::HasDuplicateAssets(valuesBuckets),
            std::make_shared<ParamError>("Duplicate assets are not allowed"));
        // 'argv[2]' represents a ConflictResolution
        ASSERT_RETURN_SET_ERROR(!JSUtils::IsNull(env, argv[2]), std::make_shared<ParamError>("conflict", "not null"));
        // 'argv[2]' represents a ConflictResolution
        CHECK_RETURN_ERR(ParseConflictResolution(env, argv[2], conflictResolution) == OK);
        return OK;
    }
    std::string tableName;
    ValuesBuckets valuesBuckets;
    ConflictResolution conflictResolution;

    int64_t insertRows = -1;
};

/*
 * [JS API Prototype]
 * [Promise]
 *      batchInsertWithConflictResolution(table: string, values: Array<ValuesBucket>, conflict: ConflictResolution):
 *      Promise<number>;
 */
napi_value TransactionProxy::BatchInsertWithConflictResolution(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<BatchInsertWithConflictResolutionContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        context->Parse(env, argc, argv, self);
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->transaction_ != nullptr);
        auto [code, insertRows] = context->StealTransaction()->BatchInsert(
            context->tableName, context->valuesBuckets, context->conflictResolution);
        context->insertRows = insertRows;
        return code;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, context->insertRows, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

struct QueryContext : public TransactionContext {
    int32_t Parse(napi_env env, size_t argc, napi_value *argv, napi_value self)
    {
        ASSERT_RETURN_SET_ERROR(argc == 1 || argc == 2, std::make_shared<ParamNumError>("1 to 2"));
        GetInstance(self);
        ASSERT_RETURN_SET_ERROR(transaction_ != nullptr, std::make_shared<ParamError>("transaction", "a transaction."));
        CHECK_RETURN_ERR(ParseRdbPredicatesProxy(env, argv[0], rdbPredicates) == OK);
        if (argc > 1 && !JSUtils::IsNull(env, argv[1])) {
            ASSERT_RETURN_SET_ERROR(JSUtils::Convert2Value(env, argv[1], columns) == OK,
                std::make_shared<ParamError>("columns", "a Array<string>."));
        }
        return OK;
    }
    std::shared_ptr<RdbPredicates> rdbPredicates = nullptr;
    std::vector<std::string> columns;

    std::shared_ptr<ResultSet> resultSet;
};

/*
 * [JS API Prototype]
 * [Promise]
 *      query(predicates: RdbPredicates, columns?: Array<string>): Promise<ResultSet>;
 */
napi_value TransactionProxy::Query(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<QueryContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        context->Parse(env, argc, argv, self);
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->transaction_ != nullptr && context->rdbPredicates != nullptr);
        context->resultSet = context->StealTransaction()->QueryByStep(*(context->rdbPredicates), context->columns);
        return (context->resultSet != nullptr) ? E_OK : E_ALREADY_CLOSED;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = ResultSetProxy::NewInstance(env, context->resultSet);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

struct QuerySqlContext : public TransactionContext {
    int32_t Parse(napi_env env, size_t argc, napi_value *argv, napi_value self)
    {
        ASSERT_RETURN_SET_ERROR(argc == 1 || argc == 2, std::make_shared<ParamNumError>("1 to 2"));
        GetInstance(self);
        ASSERT_RETURN_SET_ERROR(transaction_ != nullptr, std::make_shared<ParamError>("transaction", "a transaction."));
        ASSERT_RETURN_SET_ERROR(
            JSUtils::Convert2Value(env, argv[0], sql) == OK, std::make_shared<ParamError>("sql", "a string."));
        if (argc > 1 && !JSUtils::IsNull(env, argv[1])) {
            ASSERT_RETURN_SET_ERROR(JSUtils::Convert2Value(env, argv[1], bindArgs) == OK,
                std::make_shared<ParamError>("bindArgs", "a Array<ValueType>."));
        }
        return OK;
    }
    std::string sql;
    std::vector<ValueObject> bindArgs;

    std::shared_ptr<ResultSet> resultSet;
};

/*
 * [JS API Prototype]
 * [Promise]
 *      querySql(sql: string, bindArgs?: Array<ValueType>): Promise<ResultSet>;
 */
napi_value TransactionProxy::QuerySql(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<QuerySqlContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        context->Parse(env, argc, argv, self);
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->transaction_ != nullptr);
        context->resultSet = context->StealTransaction()->QueryByStep(context->sql, context->bindArgs);
        return (context->resultSet != nullptr) ? E_OK : E_ALREADY_CLOSED;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = ResultSetProxy::NewInstance(env, context->resultSet);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

struct ExecuteContext : public TransactionContext {
    int32_t Parse(napi_env env, size_t argc, napi_value *argv, napi_value self)
    {
        ASSERT_RETURN_SET_ERROR(argc == 1 || argc == 2, std::make_shared<ParamNumError>("1 to 2"));
        GetInstance(self);
        ASSERT_RETURN_SET_ERROR(transaction_ != nullptr, std::make_shared<ParamError>("transaction", "a transaction."));
        CHECK_RETURN_ERR(JSUtils::Convert2Value(env, argv[0], sql) == OK);
        if (argc > 1 && !JSUtils::IsNull(env, argv[1])) {
            CHECK_RETURN_ERR(JSUtils::Convert2Value(env, argv[1], bindArgs) == OK);
        }
        return OK;
    }
    std::string sql;
    std::vector<ValueObject> bindArgs;

    ValueObject output;
};

/*
 * [JS API Prototype]
 * [Promise]
 *      execute(sql: string, args?: Array<ValueType>): Promise<ValueType>;
 */
napi_value TransactionProxy::Execute(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<ExecuteContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        context->Parse(env, argc, argv, self);
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->transaction_ != nullptr);
        auto status = E_ERROR;
        std::tie(status, context->output) = context->StealTransaction()->Execute(context->sql, context->bindArgs);
        return status;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = JSUtils::Convert2JSValue(env, context->output);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}
} // namespace OHOS::RelationalStoreJsKit