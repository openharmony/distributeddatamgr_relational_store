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
#include "napi_lite_result_set.h"
#include "napi_rdb_context.h"
#include "napi_rdb_error.h"
#include "napi_rdb_js_utils.h"
#include "napi_rdb_predicates.h"
#include "napi_result_set.h"
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_types.h"
using namespace OHOS::Rdb;
using namespace OHOS::NativeRdb;
using namespace OHOS::AppDataMgrJsKit;
namespace OHOS::RelationalStoreJsKit {
#define ASSERT_RETURN_SET_ERROR(assertion, paramError) \
    CHECK_RETURN_CORE(assertion, SetError(paramError), ERR)

struct TransactionContext : public ContextBase {
    void ParsedInstance(napi_value self)
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
    int32_t ParseValuesBucket(napi_env env, napi_value arg, ValuesBucket &valuesBucket);
    int32_t ParseValuesBuckets(napi_env env, napi_value arg, ValuesBuckets &valuesBuckets);
    int32_t ParseConflictResolution(napi_env env, napi_value arg, NativeRdb::ConflictResolution &conflictResolution);
    std::shared_ptr<NativeRdb::Transaction> transaction_ = nullptr;
};

int32_t TransactionContext::ParseRdbPredicatesProxy(
    napi_env env, napi_value arg, std::shared_ptr<RdbPredicates> &predicates)
{
    auto err = RelationalStoreJsKit::ParseRdbPredicatesProxy(env, arg, predicates);
    ASSERT_RETURN_SET_ERROR(!err, err);
    return OK;
}

#define CHECK_RETURN_SET_PARAM_ERROR(oriErr, newErr)                                                     \
    ASSERT_RETURN_SET_ERROR(!(oriErr), (oriErr)->GetNativeCode() == NativeRdb::E_INVALID_ARGS_NEW        \
                               ? (newErr)                                                                \
                               : (oriErr))                                                               \

int32_t TransactionContext::ParseValuesBucket(napi_env env, napi_value arg, ValuesBucket &valuesBucket)
{
    auto err = RelationalStoreJsKit::ParseValuesBucket(env, arg, valuesBucket);
    CHECK_RETURN_SET_PARAM_ERROR(err, std::make_shared<ParamError>("ValuesBucket is invalid."));
    return OK;
}

int32_t TransactionContext::ParseValuesBuckets(napi_env env, napi_value arg, ValuesBuckets &valuesBuckets)
{
    auto err = RelationalStoreJsKit::ParseValuesBuckets(env, arg, valuesBuckets);
    CHECK_RETURN_SET_PARAM_ERROR(err, std::make_shared<ParamError>("ValuesBuckets is invalid."));
    return OK;
}

int32_t TransactionContext::ParseConflictResolution(
    const napi_env env, const napi_value arg, NativeRdb::ConflictResolution &conflictResolution)
{
    auto err = RelationalStoreJsKit::ParseConflictResolution(env, arg, conflictResolution);
    ASSERT_RETURN_SET_ERROR(!err, err);
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
            DECLARE_NAPI_FUNCTION_WITH_DATA("queryWithoutRowCount", QueryWithoutRowCount, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("querySqlWithoutRowCount", QuerySqlWithoutRowCount, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("querySql", QuerySql, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("execute", Execute, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("batchInsertWithReturning", BatchInsertWithReturning, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("updateWithReturning", UpdateWithReturning, ASYNC),
            DECLARE_NAPI_FUNCTION_WITH_DATA("deleteWithReturning", DeleteWithReturning, ASYNC),
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
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("queryWithoutRowCountSync", QueryWithoutRowCount, SYNC));
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("querySqlWithoutRowCountSync", QuerySqlWithoutRowCount, SYNC));
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("querySqlSync", QuerySql, SYNC));
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("executeSync", Execute, SYNC));
    properties.push_back(
        DECLARE_NAPI_FUNCTION_WITH_DATA("batchInsertWithReturningSync", BatchInsertWithReturning, SYNC));
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("updateWithReturningSync", UpdateWithReturning, SYNC));
    properties.push_back(DECLARE_NAPI_FUNCTION_WITH_DATA("deleteWithReturningSync", DeleteWithReturning, SYNC));
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
        if (data == nullptr) {
            LOG_ERROR("data is nullptr.");
            return;
        }
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
        ParsedInstance(self);
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
        ParsedInstance(self);
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
        ParsedInstance(self);
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
        ParsedInstance(self);
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
        ParsedInstance(self);
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
        ParsedInstance(self);
        ASSERT_RETURN_SET_ERROR(transaction_ != nullptr, std::make_shared<ParamError>("transaction", "a transaction."));
        ASSERT_RETURN_SET_ERROR(
            JSUtils::Convert2Value(env, argv[0], tableName) == OK, std::make_shared<ParamError>("table", "a string."));
        CHECK_RETURN_ERR(ParseValuesBuckets(env, argv[1], valuesBuckets) == OK);
        ASSERT_RETURN_SET_ERROR(!RdbSqlUtils::HasDuplicateAssets(valuesBuckets),
            std::make_shared<ParamError>("Duplicate assets are not allowed"));
        return OK;
    }
    std::string tableName;
    ValuesBuckets valuesBuckets;

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
        ParsedInstance(self);
        ASSERT_RETURN_SET_ERROR(transaction_ != nullptr, std::make_shared<ParamError>("transaction", "a transaction."));
        ASSERT_RETURN_SET_ERROR(
            JSUtils::Convert2Value(env, argv[0], tableName) == OK, std::make_shared<ParamError>("table", "a string."));
        CHECK_RETURN_ERR(ParseValuesBuckets(env, argv[1], valuesBuckets) == OK);
        ASSERT_RETURN_SET_ERROR(!RdbSqlUtils::HasDuplicateAssets(valuesBuckets),
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
        ParsedInstance(self);
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
        result = ResultSetProxy::NewInstance(env, std::move(context->resultSet));
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

/*
 * [JS API Prototype]
 * [Promise]
 *      queryWithoutRowCount(predicates: RdbPredicates, columns?: Array<string>): Promise<LiteResultSet>;
 */
napi_value TransactionProxy::QueryWithoutRowCount(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<QueryContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        context->Parse(env, argc, argv, self);
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->transaction_ != nullptr && context->rdbPredicates != nullptr);
        DistributedRdb::QueryOptions options{.preCount = false, .isGotoNextRowReturnLastError = true};
        context->resultSet =
            context->StealTransaction()->QueryByStep(*(context->rdbPredicates), context->columns, options);
        return (context->resultSet != nullptr) ? E_OK : E_ALREADY_CLOSED;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = LiteResultSetProxy::NewInstance(env, std::move(context->resultSet));
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerErrorExt>(E_ERROR));
    };
    context->InitAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

struct QuerySqlContext : public TransactionContext {
    int32_t Parse(napi_env env, size_t argc, napi_value *argv, napi_value self)
    {
        ASSERT_RETURN_SET_ERROR(argc == 1 || argc == 2, std::make_shared<ParamNumError>("1 to 2"));
        ParsedInstance(self);
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
        result = ResultSetProxy::NewInstance(env, std::move(context->resultSet));
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

/*
 * [JS API Prototype]
 * [Promise]
 *      querySqlWithoutRowCount(sql: string, bindArgs?: Array<ValueType>): Promise<LiteResultSet>;
 */
napi_value TransactionProxy::QuerySqlWithoutRowCount(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<QuerySqlContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN(context->Parse(env, argc, argv, self) == OK);
        // ParamError is reported only when the parameter type is incorrect.
        CHECK_RETURN_SET_E(!context->sql.empty(),
            std::make_shared<InnerErrorExt>(NativeRdb::E_INVALID_ARGS_NEW, "sql cannot be empty"));
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->transaction_ != nullptr);
        DistributedRdb::QueryOptions options{.preCount = false, .isGotoNextRowReturnLastError = true};
        context->resultSet = context->StealTransaction()->QueryByStep(context->sql, context->bindArgs, options);
        return (context->resultSet != nullptr) ? E_OK : E_ALREADY_CLOSED;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = LiteResultSetProxy::NewInstance(env, std::move(context->resultSet));
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerErrorExt>(E_ERROR));
    };
    context->InitAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

struct ExecuteContext : public TransactionContext {
    int32_t Parse(napi_env env, size_t argc, napi_value *argv, napi_value self)
    {
        ASSERT_RETURN_SET_ERROR(argc == 1 || argc == 2, std::make_shared<ParamNumError>("1 to 2"));
        ParsedInstance(self);
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
struct TransBatchInsertWithReturningContext : public TransactionContext {
    int32_t Parse(napi_env env, size_t argc, napi_value *argv, napi_value self)
    {
        // the parameters are either 3 or 4.
        ASSERT_RETURN_SET_ERROR(argc == 3 || argc == 4, std::make_shared<ParamNumError>("3 or 4"));
        ParsedInstance(self);
        ASSERT_RETURN_SET_ERROR(transaction_ != nullptr, std::make_shared<InnerError>(NativeRdb::E_ALREADY_CLOSED));
        ASSERT_RETURN_SET_ERROR(
            JSUtils::Convert2Value(env, argv[0], tableName) == OK, std::make_shared<ParamError>("table", "a string."));
        ASSERT_RETURN_SET_ERROR(RdbSqlUtils::IsValidTableName(tableName),
            std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Illegal table name"));
        std::shared_ptr<Error> err = RelationalStoreJsKit::ParseValuesBuckets(env, argv[1], valuesBuckets);
        ASSERT_RETURN_SET_ERROR(!err, err);
        ASSERT_RETURN_SET_ERROR(!RdbSqlUtils::HasDuplicateAssets(valuesBuckets),
            std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Duplicate assets are not allowed"));
        auto errCode = JSUtils::Convert2Value(env, argv[2], config);
        ASSERT_RETURN_SET_ERROR(errCode == E_OK,
            std::make_shared<ParamError>("Illegal ReturningConfig."));
        config.columns = RdbSqlUtils::BatchTrim(config.columns);
        ASSERT_RETURN_SET_ERROR(RdbSqlUtils::IsValidFields(config.columns),
            std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Illegal columns."));
        ASSERT_RETURN_SET_ERROR(RdbSqlUtils::IsValidReturningMaxCount(config.maxReturningCount),
            std::make_shared<InnerError>(
                NativeRdb::E_INVALID_ARGS_NEW, "MaxReturningcount is not within the valid range."));
        // 4 is the number of parameters, 3 is the index.
        if (argc == 4 && !JSUtils::IsNull(env, argv[3])) {
            // 3 is the index of conflict.
            CHECK_RETURN_ERR(ParseConflictResolution(env, argv[3], conflictResolution));
        }
        return OK;
    }
    std::string tableName;
    ValuesBuckets valuesBuckets;
    Results result;
    ReturningConfig config;
    NativeRdb::ConflictResolution conflictResolution = NativeRdb::ConflictResolution::ON_CONFLICT_NONE;
};

/*
 * [JS API Prototype]
 * [Promise]
 *      batchInsertWithReturning(table: string, values: Array<ValuesBucket>, config: ReturningConfig,
 *          conflict?: ConflictResolution): Promise<ResultSet>;
 * [sync]
 *      batchInsertWithReturningSync(table: string, values: Array<ValuesBucket>, config: ReturningConfig,
 *          conflict?: ConflictResolution): ResultSet;
 */
napi_value TransactionProxy::BatchInsertWithReturning(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<TransBatchInsertWithReturningContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        context->Parse(env, argc, argv, self);
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->transaction_ != nullptr);
        auto result = context->StealTransaction()->BatchInsert(context->tableName, context->valuesBuckets,
            context->config, context->conflictResolution);
        context->result = result.second;
        return result.first;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_value resultSet = LiteResultSetProxy::NewInstance(env, std::move(context->result.results));
        CHECK_RETURN_SET_E(resultSet != nullptr, std::make_shared<InnerErrorExt>(E_ERROR));
        JSUtils::ReturningResult tsResults = {context->result.changed, resultSet};
        result = JSUtils::Convert2JSValue(env, tsResults);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerErrorExt>(E_ERROR));
    };
    context->InitAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

struct TransUpdateWithReturningContext : public TransactionContext {
    int32_t Parse(napi_env env, size_t argc, napi_value *argv, napi_value self)
    {
        // the parameters are either 3 or 4.
        ASSERT_RETURN_SET_ERROR(argc == 3 || argc == 4, std::make_shared<ParamNumError>("3 to 4"));
        ParsedInstance(self);
        ASSERT_RETURN_SET_ERROR(transaction_ != nullptr, std::make_shared<InnerError>(NativeRdb::E_ALREADY_CLOSED));
        auto err = RelationalStoreJsKit::ParseValuesBucket(env, argv[0], valuesBucket);
        ASSERT_RETURN_SET_ERROR(!err, err);
        ASSERT_RETURN_SET_ERROR(!RdbSqlUtils::HasDuplicateAssets(valuesBucket),
            std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Duplicate assets are not allowed"));
        CHECK_RETURN_ERR(ParseRdbPredicatesProxy(env, argv[1], rdbPredicates) == OK);
        ASSERT_RETURN_SET_ERROR(RdbSqlUtils::IsValidTableName(rdbPredicates->GetTableName()),
            std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Illegal table name"));
        auto errCode = JSUtils::Convert2Value(env, argv[2], config);
        ASSERT_RETURN_SET_ERROR(errCode == E_OK,
            std::make_shared<ParamError>("Illegal ReturningConfig."));
        config.columns = RdbSqlUtils::BatchTrim(config.columns);
        ASSERT_RETURN_SET_ERROR(RdbSqlUtils::IsValidFields(config.columns),
            std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Illegal columns."));
        ASSERT_RETURN_SET_ERROR(RdbSqlUtils::IsValidReturningMaxCount(config.maxReturningCount),
            std::make_shared<InnerError>(
                NativeRdb::E_INVALID_ARGS_NEW, "MaxReturningcount is not within the valid range."));
        // 4 is the number of parameters, 3 is the index.
        if (argc == 4 && !JSUtils::IsNull(env, argv[3])) {
            // 3 is the index of conflict.
            CHECK_RETURN_ERR(OK == ParseConflictResolution(env, argv[3], conflictResolution));
        }
        return OK;
    }
    ValuesBucket valuesBucket;
    std::shared_ptr<RdbPredicates> rdbPredicates = nullptr;
    NativeRdb::ConflictResolution conflictResolution = ConflictResolution::ON_CONFLICT_NONE;
    Results result;
    ReturningConfig config;
};

/*
 * [JS API Prototype]
 * [Promise]
 *      updateWithReturning(values: ValuesBucket, predicates: RdbPredicates, config: ReturningConfig,
 *          conflict?: ConflictResolution): Promise<ResultSet>;
 * [sync]
 *      updateWithReturningSync(values: ValuesBucket, predicates: RdbPredicates, config: ReturningConfig,
 *          conflict?: ConflictResolution): ResultSet;
 */
napi_value TransactionProxy::UpdateWithReturning(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<TransUpdateWithReturningContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        context->Parse(env, argc, argv, self);
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->transaction_ != nullptr && context->rdbPredicates != nullptr);
        auto result = context->StealTransaction()->Update(
            context->valuesBucket, *context->rdbPredicates, context->config, context->conflictResolution);
        context->result = result.second;
        return result.first;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_value resultSet = LiteResultSetProxy::NewInstance(env, std::move(context->result.results));
        CHECK_RETURN_SET_E(resultSet != nullptr, std::make_shared<InnerErrorExt>(E_ERROR));
        JSUtils::ReturningResult tsResults = {context->result.changed, resultSet};
        result = JSUtils::Convert2JSValue(env, tsResults);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerErrorExt>(E_ERROR));
    };
    context->InitAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

struct TransDeleteWithReturningContext : public TransactionContext {
    int32_t Parse(napi_env env, size_t argc, napi_value *argv, napi_value self)
    {
        ASSERT_RETURN_SET_ERROR(argc == 2, std::make_shared<ParamNumError>("2"));
        ParsedInstance(self);
        ASSERT_RETURN_SET_ERROR(transaction_ != nullptr, std::make_shared<InnerError>(NativeRdb::E_ALREADY_CLOSED));
        CHECK_RETURN_ERR(ParseRdbPredicatesProxy(env, argv[0], rdbPredicates) == OK);
        ASSERT_RETURN_SET_ERROR(RdbSqlUtils::IsValidTableName(rdbPredicates->GetTableName()),
            std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Illegal table name"));
        auto errCode = JSUtils::Convert2Value(env, argv[1], config);
        ASSERT_RETURN_SET_ERROR(errCode == E_OK,
            std::make_shared<ParamError>("Illegal ReturningConfig."));
        config.columns = RdbSqlUtils::BatchTrim(config.columns);
        ASSERT_RETURN_SET_ERROR(RdbSqlUtils::IsValidFields(config.columns),
            std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Illegal columns."));
        ASSERT_RETURN_SET_ERROR(RdbSqlUtils::IsValidReturningMaxCount(config.maxReturningCount),
            std::make_shared<InnerError>(
                NativeRdb::E_INVALID_ARGS_NEW, "MaxReturningcount is not within the valid range."));
        return OK;
    }
    std::shared_ptr<RdbPredicates> rdbPredicates = nullptr;
    Results result;
    ReturningConfig config;
};

/*
 * [JS API Prototype]
 * [Promise]
 *      deleteWithReturning(predicates: RdbPredicates, config: ReturningConfig): Promise<ResultSet>;
 * [sync]
 *      deleteWithReturningSync(predicates: RdbPredicates, config: ReturningConfig): ResultSet;
 */
napi_value TransactionProxy::DeleteWithReturning(napi_env env, napi_callback_info info)
{
    auto context = std::make_shared<TransDeleteWithReturningContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        context->Parse(env, argc, argv, self);
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->transaction_ != nullptr && context->rdbPredicates != nullptr);
        auto result = context->StealTransaction()->Delete(*(context->rdbPredicates), context->config);
        context->result = result.second;
        return result.first;
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_value resultSet = LiteResultSetProxy::NewInstance(env, std::move(context->result.results));
        CHECK_RETURN_SET_E(resultSet != nullptr, std::make_shared<InnerErrorExt>(E_ERROR));
        JSUtils::ReturningResult tsResults = {context->result.changed, resultSet};
        result = JSUtils::Convert2JSValue(env, tsResults);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerErrorExt>(E_ERROR));
    };
    context->InitAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}
} // namespace OHOS::RelationalStoreJsKit