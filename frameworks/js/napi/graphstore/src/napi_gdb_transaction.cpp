/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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
#define LOG_TAG "GdbTransactionProxy"
#include "napi_gdb_transaction.h"

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <vector>

#include "db_trace.h"
#include "js_utils.h"
#include "logger.h"
#include "js_df_manager.h"
#include "napi_gdb_context.h"
#include "napi_gdb_error.h"
#include "napi_gdb_js_utils.h"

namespace OHOS::GraphStoreJsKit {
#define ASSERT_RETURN_SET_ERROR(assertion, paramError) \
    CHECK_RETURN_CORE(assertion, SetError(paramError), ERR)

constexpr int32_t MAX_GQL_LEN = 1024 * 1024;

constexpr const char *SPACE_NAME = "ohos.data.graphStore";
constexpr const char *CLASS_NAME = "Transaction";

struct TransactionContext : public ContextBase {
    void GetInstance(napi_value self)
    {
        auto status = napi_unwrap(env_, self, reinterpret_cast<void **>(&boundObj));
        if (status != napi_ok || boundObj == nullptr) {
            LOG_ERROR("GdbTransactionProxy native instance is nullptr! code:%{public}d!", status);
            return;
        }
        transaction_ = reinterpret_cast<GdbTransactionProxy *>(boundObj)->GetInstance();
    }
    std::shared_ptr<Transaction> StealTransaction()
    {
        auto trans = std::move(transaction_);
        transaction_ = nullptr;
        return trans;
    }
    std::shared_ptr<Transaction> transaction_ = nullptr;
};

GdbTransactionProxy::~GdbTransactionProxy()
{
}

GdbTransactionProxy::GdbTransactionProxy(std::shared_ptr<Transaction> gdbTransaction)
{
    if (GetInstance() == gdbTransaction) {
        return;
    }
    SetInstance(std::move(gdbTransaction));
}

napi_value GdbTransactionProxy::Initialize(napi_env env, napi_callback_info info)
{
    napi_value self = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, NULL, NULL, &self, nullptr));
    auto *proxy = new (std::nothrow) GdbTransactionProxy();
    if (proxy == nullptr) {
        return nullptr;
    }
    auto finalize = [](napi_env env, void *data, void *hint) {
        if (data != hint) {
            LOG_ERROR("memory corrupted! data:0x%016" PRIXPTR "hint:0x%016" PRIXPTR,
                uintptr_t(data) & LOWER_24_BITS_MASK, uintptr_t(hint) & LOWER_24_BITS_MASK);
            return;
        }
        GdbTransactionProxy *proxy = reinterpret_cast<GdbTransactionProxy *>(data);
        proxy->SetInstance(nullptr);
        delete proxy;
    };
    napi_status status = napi_wrap(env, self, proxy, finalize, proxy, nullptr);
    if (status != napi_ok) {
        LOG_ERROR("napi_wrap failed! code:%{public}d!", status);
        finalize(env, proxy, proxy);
        return nullptr;
    }
    return self;
}

void GdbTransactionProxy::Init(napi_env env, napi_value exports)
{
    auto lambda = []() -> std::vector<napi_property_descriptor> {
        std::vector<napi_property_descriptor> properties = {
            DECLARE_NAPI_FUNCTION("read", Read),
            DECLARE_NAPI_FUNCTION("write", Write),
            DECLARE_NAPI_FUNCTION("commit", Commit),
            DECLARE_NAPI_FUNCTION("rollback", Rollback),
        };
        return properties;
    };
    auto jsCtor = AppDataMgrJsKit::JSUtils::DefineClass(env, SPACE_NAME, CLASS_NAME, lambda, Initialize);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, exports, CLASS_NAME, jsCtor));
}

napi_value GdbTransactionProxy::NewInstance(napi_env env, std::shared_ptr<Transaction> value)
{
    if (value == nullptr) {
        LOG_ERROR("value is nullptr");
        return nullptr;
    }
    napi_value cons = AppDataMgrJsKit::JSUtils::GetClass(env, SPACE_NAME, CLASS_NAME);
    if (cons == nullptr) {
        LOG_ERROR("Constructor of Transaction is nullptr!");
        return nullptr;
    }

    napi_value instance = nullptr;
    auto status = napi_new_instance(env, cons, 0, nullptr, &instance);
    if (status != napi_ok) {
        LOG_ERROR("create new instance failed! code:%{public}d!", status);
        return nullptr;
    }

    GdbTransactionProxy *proxy = nullptr;
    status = napi_unwrap(env, instance, reinterpret_cast<void **>(&proxy));
    if (status != napi_ok || proxy == nullptr) {
        LOG_ERROR("native instance is nullptr! code:%{public}d!", status);
        return instance;
    }
    proxy->SetInstance(std::move(value));
    return instance;
}

struct ReadWriteContext : public TransactionContext {
    int32_t Parse(napi_env env, size_t argc, napi_value *argv, napi_value self)
    {
        ASSERT_RETURN_SET_ERROR(argc == 1, std::make_shared<ParamNumError>(" 1 "));
        GetInstance(self);
        ASSERT_RETURN_SET_ERROR(transaction_ != nullptr, std::make_shared<ParamError>("transaction", "not nullptr."));
        gql = AppDataMgrJsKit::JSUtils::Convert2String(env, argv[0]);
        ASSERT_RETURN_SET_ERROR(!gql.empty(), std::make_shared<ParamError>("gql", "not empty"));
        ASSERT_RETURN_SET_ERROR(gql.size() <= MAX_GQL_LEN,
            std::make_shared<ParamError>("gql", "too long"));
        return OK;
    }
    std::string gql;
    std::shared_ptr<Result> result;
    int32_t errCode;
};

napi_value GdbTransactionProxy::Read(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto context = std::make_shared<ReadWriteContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        context->Parse(env, argc, argv, self);
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->transaction_ != nullptr);
        std::tie(context->errCode, context->result) = context->StealTransaction()->Query(context->gql);
        return context->errCode;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = AppDataMgrJsKit::JSUtils::Convert2JSValue(env, context->result);
        CHECK_RETURN_SET_E(context->errCode == OK, std::make_shared<InnerError>(context->errCode));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value GdbTransactionProxy::Write(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto context = std::make_shared<ReadWriteContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        context->Parse(env, argc, argv, self);
    };
    auto exec = [context]() -> int {
        CHECK_RETURN_ERR(context->transaction_ != nullptr);
        std::tie(context->errCode, context->result) = context->StealTransaction()->Execute(context->gql);
        return context->errCode;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = AppDataMgrJsKit::JSUtils::Convert2JSValue(env, context->result);
        CHECK_RETURN_SET_E(context->errCode == OK, std::make_shared<InnerError>(context->errCode));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

struct CommitRollbackContext : public TransactionContext {
    int32_t Parse(napi_env env, size_t argc, napi_value *argv, napi_value self)
    {
        GetInstance(self);
        ASSERT_RETURN_SET_ERROR(transaction_ != nullptr, std::make_shared<ParamError>("transaction", "a transaction."));
        return OK;
    }
};

napi_value GdbTransactionProxy::Commit(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto context = std::make_shared<CommitRollbackContext>();
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

napi_value GdbTransactionProxy::Rollback(napi_env env, napi_callback_info info)
{
    DISTRIBUTED_DATA_HITRACE(std::string(__FUNCTION__));
    auto context = std::make_shared<CommitRollbackContext>();
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
} // namespace OHOS::GraphStoreJsKit
