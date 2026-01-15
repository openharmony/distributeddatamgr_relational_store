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
#define LOG_TAG "NapiRdbStoreHelper"
#include "napi_rdb_store_helper.h"

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "logger.h"
#include "napi_async_call.h"
#include "napi_rdb_context.h"
#include "napi_rdb_error.h"
#include "napi_rdb_js_utils.h"
#include "napi_rdb_store.h"
#include "napi_rdb_trace.h"
#include "rdb_errno.h"
#include "rdb_open_callback.h"
#include "rdb_store_config.h"
#include "rdb_sql_utils.h"
#include "sqlite_sql_builder.h"
#include "unistd.h"

using namespace OHOS::Rdb;
using namespace OHOS::NativeRdb;
using namespace OHOS::AppDataMgrJsKit;
using namespace OHOS::AppDataMgrJsKit::JSUtils;

namespace OHOS {
namespace RelationalStoreJsKit {
constexpr int32_t PARAM_LENGTH_MAX = 256;
constexpr int32_t VALUESBUCKET_LENGTH_MAX = 1000;
using ContextParam = AppDataMgrJsKit::JSUtils::ContextParam;

const std::map<int, std::string> ERR_STRING_MAP = {
    { E_EMPTY_TABLE_NAME, "The table must be not empty string." },
    { E_EMPTY_VALUES_BUCKET, "Bucket must not be empty." },
    { E_INVALID_CONFLICT_FLAG, "Conflict flag is not correct." },
    { E_INVALID_ARGS, "The ValueBucket contains Assets and conflictResolution is REPLACE." },
};

class DefaultOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &rdbStore) override
    {
        return E_OK;
    }
    int OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion) override
    {
        return E_OK;
    }
};

napi_value GetRdbStoreCommon(napi_env env, napi_callback_info info, std::shared_ptr<DeleteContext> context)
{
    auto input = [context, info](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        int errCode = Convert2Value(env, argv[0], context->param);
        CHECK_RETURN_SET_E(OK == errCode, std::make_shared<ParamError>("Illegal context."));

        errCode = Convert2Value(env, argv[1], context->config);
        CHECK_RETURN_SET_E(OK == errCode, std::make_shared<ParamError>("Illegal StoreConfig or name."));

        CHECK_RETURN_SET_E(context->config.cryptoParam.IsValid(), std::make_shared<ParamError>("Illegal CryptoParam."));
        CHECK_RETURN_SET_E(context->config.tokenizer >= NONE_TOKENIZER && context->config.tokenizer < TOKENIZER_END,
            std::make_shared<ParamError>("Illegal tokenizer."));
        CHECK_RETURN_SET_E(RdbHelper::IsSupportedTokenizer(context->config.tokenizer),
            std::make_shared<InnerError>(NativeRdb::E_NOT_SUPPORT));
        if (!context->config.persist) {
            CHECK_RETURN_SET_E(context->config.rootDir.empty(),
                std::make_shared<InnerError>(NativeRdb::E_NOT_SUPPORT));
            return;
        }
        auto [code, err] = GetRealPath(env, argv[0], context->config, context->param);
        if (!context->config.rootDir.empty()) {
            context->config.isReadOnly = true;
        }
        CHECK_RETURN_SET_E(OK == code, err);
    };
    auto exec = [context]() -> int {
        int errCode = OK;
        DefaultOpenCallback callback;
        context->proxy =
            RdbHelper::GetRdbStore(GetRdbStoreConfig(context->config, context->param), -1, callback, errCode);
        // If the API version is less than 14, throw E_INVALID_ARGS.
        if (errCode == E_INVALID_SECRET_KEY && JSUtils::GetHapVersion() < 14) {
            errCode = E_INVALID_ARGS;
        }
        return errCode;
    };
    auto output = [context](napi_env env, napi_value &result) {
        result = RdbStoreProxy::NewInstance(env, context->proxy, context->param.isSystemApp);
        CHECK_RETURN_SET_E(result != nullptr, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value GetRdbStore(napi_env env, napi_callback_info info) 
{
    struct DeleteContext : public ContextBase {
        ContextParam param;
        RdbConfig config;
        std::shared_ptr<RdbStore> proxy;
    };
    auto context = std::make_shared<DeleteContext>();
    context.config.version = 23;
    return GetRdbStoreCommon(env, info, context);
}

napi_value GetRdbStoreSync(napi_env env, napi_callback_info info)
{
    struct DeleteContext : public ContextBase {
        ContextParam param;
        RdbConfig config;
        std::shared_ptr<RdbStore> proxy;
    };
    auto context = std::make_shared<DeleteContext>();
    context.config.version = 24;
    return GetRdbStoreCommon(env, info, context);
}

napi_value DeleteRdbStore(napi_env env, napi_callback_info info)
{
    struct DeleteContext : public ContextBase {
        ContextParam param;
        RdbConfig config;
        bool onlyPath = false;
    };
    auto context = std::make_shared<DeleteContext>();
    auto input = [context](napi_env env, size_t argc, napi_value *argv, napi_value self) {
        CHECK_RETURN_SET_E(argc == 2, std::make_shared<ParamNumError>("2 or 3"));
        int errCode = Convert2Value(env, argv[0], context->param);
        CHECK_RETURN_SET_E(OK == errCode, std::make_shared<ParamError>("Illegal context."));

        if (IsNapiString(env, argv[1])) {
            context->onlyPath = true;
            errCode = Convert2Value(env, argv[1], context->config.name);
            CHECK_RETURN_SET_E(OK == errCode, std::make_shared<ParamError>("Illegal path."));
        } else {
            errCode = Convert2Value(env, argv[1], context->config);
            CHECK_RETURN_SET_E(OK == errCode, std::make_shared<ParamError>("Illegal StoreConfig or name."));
        }

        auto [code, err] = GetRealPath(env, argv[0], context->config, context->param);
        if (!context->config.rootDir.empty()) {
            context->config.isReadOnly = true;
        }
        CHECK_RETURN_SET_E(OK == code, err);
    };
    auto exec = [context]() -> int {
        RdbStoreConfig storeConfig = GetRdbStoreConfig(context->config, context->param);
        if (context->onlyPath) {
            storeConfig.SetDBType(DB_SQLITE);
            int errCodeSqlite = RdbHelper::DeleteRdbStore(storeConfig, false);
            storeConfig.SetDBType(DB_VECTOR);
            int errCodeVector = RdbHelper::DeleteRdbStore(storeConfig, false);
            return (errCodeSqlite == E_OK && errCodeVector == E_OK) ? E_OK : E_REMOVE_FILE;
        }
        return RdbHelper::DeleteRdbStore(storeConfig, false);
    };
    auto output = [context](napi_env env, napi_value &result) {
        napi_status status = napi_create_int64(env, OK, &result);
        CHECK_RETURN_SET_E(status == napi_ok, std::make_shared<InnerError>(E_ERROR));
    };
    context->SetAction(env, info, input, exec, output);

    CHECK_RETURN_NULL(context->error == nullptr || context->error->GetCode() == OK);
    return ASYNC_CALL(env, context);
}

napi_value IsVectorSupported(napi_env env, napi_callback_info info)
{
    bool result = RdbHelper::IsSupportArkDataDb();
    return JSUtils::Convert2JSValue(env, result);
}

napi_value IsTokenizerSupported(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1]{};
    napi_value self = nullptr;
    int32_t status = napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
    RDB_NAPI_ASSERT(env, argc == 1, std::make_shared<ParamNumError>("1"));
    int32_t tokenizer = static_cast<int32_t>(Tokenizer::NONE_TOKENIZER);
    status = Convert2ValueExt(env, argv[0], tokenizer);
    RDB_NAPI_ASSERT(env, status == napi_ok && tokenizer >= NONE_TOKENIZER && tokenizer < TOKENIZER_END,
        std::make_shared<ParamError>("tokenizer", "a TOKENIZER."));
    bool result = RdbHelper::IsSupportedTokenizer(static_cast<Tokenizer>(tokenizer));
    return JSUtils::Convert2JSValue(env, result);
}

static std::string GetErrorString(int errcode)
{
    if (ERR_STRING_MAP.find(errcode) != ERR_STRING_MAP.end()) {
        return ERR_STRING_MAP.at(errcode);
    }
    return std::string();
}

int CheckTableName(const std::string &tableName)
{
    if (tableName.size() > PARAM_LENGTH_MAX) {
        return ERR;
    }
    return OK;
}

int CheckPredicatesWhereClause(const std::string &whereClause)
{
    if (whereClause.size() > PARAM_LENGTH_MAX) {
        return ERR;
    }
    return OK;
}

int CheckValuesBucket(const ValuesBucket &valuesBucket)
{
    if (valuesBucket.values_.size() > VALUESBUCKET_LENGTH_MAX) {
        return ERR;
    }
    for (const auto &[key, val] : valuesBucket.values_) {
        if (key.size() > PARAM_LENGTH_MAX) {
            return ERR;
        }
    }
    return OK;
}

int CheckColumns(const std::vector<std::string> &columns)
{
    if (columns.size() > VALUESBUCKET_LENGTH_MAX) {
        return ERR;
    }
    for (const auto &key : columns) {
        if (key.size() > PARAM_LENGTH_MAX) {
            return ERR;
        }
    }
    return OK;
}

napi_value GetInsertSqlInfo(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("GetInsertSqlInfo begin");
    size_t argc = 3;
    napi_value argv[3]{};
    napi_value self = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
    //2 or 3 is number of input parameters. If no, an error is reported.
    RDB_NAPI_ASSERT(env, (argc == 2 || argc == 3), std::make_shared<ParamNumError>("2 or 3"));
    auto context = std::make_shared<RdbStoreContext>();
    RDB_NAPI_ASSERT(env,
        (OK == ParseTableName(env, argv[0], context)),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "The table must be not empty string."));
    RDB_NAPI_ASSERT(env,
        (OK == ParseValuesBucket(env, argv[1], context)),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Bucket must not be empty."));
    RDB_NAPI_ASSERT(
        env, (OK == CheckTableName(context->tableName)),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Table is too long."));
    RDB_NAPI_ASSERT(env,
        (OK == CheckValuesBucket(context->valuesBucket)),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "ValuesBucket is too long."));
    ConflictResolution conflict = ConflictResolution::ON_CONFLICT_NONE;
    //3 is number of input parameters, Third parameter is ConflictResolution
    if (argc == 3) {
        //2 is indicates the third input parameter.
        auto status = ParseConflictResolution(env, argv[2], context);
        RDB_NAPI_ASSERT(env,
            (OK == status),
            std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "ConflictResolution is invalid."));
        conflict = context->conflictResolution;
    }

    auto [errcode, sqlInfo] = RdbSqlUtils::GetInsertSqlInfo(context->tableName, context->valuesBucket, conflict);
    RDB_NAPI_ASSERT(
        env, errcode == E_OK, std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, GetErrorString(errcode)));
    LOG_DEBUG("GetInsertSqlInfo end");
    return Convert2JSValue(env, sqlInfo);
}

napi_value GetUpdateSqlInfo(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("GetUpdateSqlInfo Begin.");
    size_t argc = 3;
    napi_value argv[3]{};
    napi_value self = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
    //2 or 3 is number of input parameters. If no, an error is reported.
    RDB_NAPI_ASSERT(env, (argc == 2 || argc == 3), std::make_shared<ParamNumError>("2 or 3"));
    auto context = std::make_shared<RdbStoreContext>();
    RDB_NAPI_ASSERT(env,
        (OK == ParsePredicates(env, argv[0], context)),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Predicates is empty."));
    RDB_NAPI_ASSERT(env,
        (OK == ParseValuesBucket(env, argv[1], context)),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Bucket must not be empty."));
    ConflictResolution conflict = ConflictResolution::ON_CONFLICT_NONE;
    //3 is number of input parameters, Third parameter is ConflictResolution
    if (argc == 3) {
        //2 is indicates the third input parameter.
        auto status = ParseConflictResolution(env, argv[2], context);
        RDB_NAPI_ASSERT(env,
            (OK == status),
            std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "ConflictResolution is invalid."));
        conflict = context->conflictResolution;
    }
    auto predicates = context->rdbPredicates;
    RDB_NAPI_ASSERT(env,
        (!predicates->GetTableName().empty()),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "The table must be not empty string."));
    RDB_NAPI_ASSERT(env,
        (OK == CheckPredicatesWhereClause(predicates->GetWhereClause())),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Columns in predicates is too much."));
    RDB_NAPI_ASSERT(
        env, (OK == CheckTableName(predicates->GetTableName())),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Table is too long."));
    RDB_NAPI_ASSERT(env,
        (OK == CheckValuesBucket(context->valuesBucket)),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "ValuesBucket is too long."));
    auto [errcode, sqlInfo] = RdbSqlUtils::GetUpdateSqlInfo(*predicates, context->valuesBucket, conflict);
    RDB_NAPI_ASSERT(
        env, errcode == E_OK, std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, GetErrorString(errcode)));
    LOG_DEBUG("GetUpdateSqlInfo end.");
    return Convert2JSValue(env, sqlInfo);
}

napi_value GetDeleteSqlInfo(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("GetDeleteSqlInfo start");
    auto context = std::make_shared<RdbStoreContext>();
    size_t argc = 1;
    napi_value argv[1]{};
    napi_value self = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
    RDB_NAPI_ASSERT(env, argc == 1, std::make_shared<ParamNumError>("1"));
    RDB_NAPI_ASSERT(env,
        (OK == ParsePredicates(env, argv[0], context)),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "predicates is empty."));
    auto predicates = context->rdbPredicates;
    RDB_NAPI_ASSERT(env,
        (!predicates->GetTableName().empty()),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "The table must be not empty string."));
    RDB_NAPI_ASSERT(
        env, (OK == CheckTableName(predicates->GetTableName())),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Table is too long."));
    RDB_NAPI_ASSERT(env,
        (OK == CheckPredicatesWhereClause(predicates->GetWhereClause())),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Columns in predicates is too much."));
    auto [errcode, sqlInfo] = RdbSqlUtils::GetDeleteSqlInfo(*predicates);
    RDB_NAPI_ASSERT(
        env, errcode == E_OK, std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, GetErrorString(errcode)));
    LOG_DEBUG("GetDeleteSqlInfo end");
    return Convert2JSValue(env, sqlInfo);
}

napi_value GetQuerySqlInfo(napi_env env, napi_callback_info info)
{
    LOG_DEBUG("GetQuerySqlInfo start");
    auto context = std::make_shared<RdbStoreContext>();
    size_t argc = 2;
    napi_value argv[2]{};
    napi_value self = nullptr;
    napi_get_cb_info(env, info, &argc, argv, &self, nullptr);
    //1 or 2 is number of input parameters. If no, an error is reported.
    RDB_NAPI_ASSERT(env, (argc == 1 || argc == 2), std::make_shared<ParamNumError>("1 or 2"));
    RDB_NAPI_ASSERT(env,
        (OK == ParsePredicates(env, argv[0], context)),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "predicates is empty."));
    //2 is number of input parameters
    if (argc == 2) {
        auto status = ParseColumns(env, argv[1], context);
        RDB_NAPI_ASSERT(env,
            (OK == status),
            std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Columns is not a string array."));
    }
    auto predicates = context->rdbPredicates;
    auto columns = context->columns;
    RDB_NAPI_ASSERT(env,
        (!predicates->GetTableName().empty()),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "The table must be not empty string."));
    RDB_NAPI_ASSERT(env,
        (OK == CheckPredicatesWhereClause(predicates->GetWhereClause())),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Columns in predicates is too much."));
    RDB_NAPI_ASSERT(env,
        (OK == CheckTableName(predicates->GetTableName())),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Table is too long."));
    RDB_NAPI_ASSERT(env, (OK == CheckColumns(columns)),
        std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, "Columns is too long."));
    auto [errcode, sqlInfo] = RdbSqlUtils::GetQuerySqlInfo(*predicates, columns);
    RDB_NAPI_ASSERT(
        env, errcode == E_OK, std::make_shared<InnerError>(NativeRdb::E_INVALID_ARGS_NEW, GetErrorString(errcode)));
    LOG_DEBUG("GetQuerySqlInfo end");
    return Convert2JSValue(env, sqlInfo);
}

napi_value InitRdbHelper(napi_env env, napi_value exports)
{
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION_WITH_DATA("getRdbStore", GetRdbStore, ASYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("getRdbStoreSync", GetRdbStoreSync, SYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("deleteRdbStore", DeleteRdbStore, ASYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("deleteRdbStoreSync", DeleteRdbStore, SYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("isVectorSupported", IsVectorSupported, SYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("isTokenizerSupported", IsTokenizerSupported, SYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("getInsertSqlInfo", GetInsertSqlInfo, SYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("getUpdateSqlInfo", GetUpdateSqlInfo, SYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("getDeleteSqlInfo", GetDeleteSqlInfo, SYNC),
        DECLARE_NAPI_FUNCTION_WITH_DATA("getQuerySqlInfo", GetQuerySqlInfo, SYNC),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(*properties), properties));
    return exports;
}
} // namespace RelationalStoreJsKit
} // namespace OHOS
