/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "relational_store_utils.h"
#include "rdb_open_callback.h"
#include "rdb_store.h"
#include "rdb_helper.h"
#include "rdb_errno.h"
#include "relational_store_impl_rdbstore.h"

using ContextParam = OHOS::AppDataMgrJsKit::JSUtils::ContextParam;
using RdbConfig = OHOS::AppDataMgrJsKit::JSUtils::RdbConfig;

using namespace OHOS::FFI;

namespace OHOS {
namespace Relational {
class DefaultOpenCallback : public NativeRdb::RdbOpenCallback {
public:
    int OnCreate(NativeRdb::RdbStore &rdbStore) override
    {
        return RelationalStoreJsKit::OK;
    }

    int OnUpgrade(NativeRdb::RdbStore &rdbStore, int oldVersion, int newVersion) override
    {
        return RelationalStoreJsKit::OK;
    }
};

int64_t GetRdbStore(OHOS::AbilityRuntime::Context *context, StoreConfig config,
    int32_t *errCode)
{
    if (context == nullptr) {
        *errCode = -1;
        return -1;
    }
    auto abilitycontext = std::make_shared<AppDataMgrJsKit::Context>(context->shared_from_this());
    AppDataMgrJsKit::JSUtils::ContextParam param;
    initContextParam(param, abilitycontext);
    AppDataMgrJsKit::JSUtils::RdbConfig rdbConfig;
    initRdbConfig(rdbConfig, config);

    *errCode = GetRealPath(rdbConfig, param, abilitycontext);
    if (*errCode != NativeRdb::E_OK) {
        return -1;
    }

    DefaultOpenCallback callback;
    auto rdbStore =
        NativeRdb::RdbHelper::GetRdbStore(getRdbStoreConfig(rdbConfig, param), -1, callback, *errCode);
    if (*errCode != 0) {
        return -1;
    }
    auto nativeRdbStore = FFIData::Create<RdbStoreImpl>(rdbStore);
    if (nativeRdbStore == nullptr) {
        *errCode = -1;
        return -1;
    }
    return nativeRdbStore->GetID();
}

int64_t GetRdbStoreEx(OHOS::AbilityRuntime::Context *context, const StoreConfigEx *config,
    int32_t *errCode)
{
    if (context == nullptr || config == nullptr) {
        *errCode = ERROR_VALUE;
        return ERROR_VALUE;
    }
    auto abilitycontext = std::make_shared<AppDataMgrJsKit::Context>(context->shared_from_this());
    AppDataMgrJsKit::JSUtils::ContextParam param;
    initContextParam(param, abilitycontext);
    AppDataMgrJsKit::JSUtils::RdbConfig rdbConfig;
    initRdbConfigEx(rdbConfig, *config);
    if (!rdbConfig.cryptoParam.IsValid()) {
        *errCode = RelationalStoreJsKit::E_PARAM_ERROR;
        return ERROR_VALUE;
    }

    *errCode = GetRealPath(rdbConfig, param, abilitycontext);
    if (*errCode != NativeRdb::E_OK) {
        return ERROR_VALUE;
    }

    DefaultOpenCallback callback;
    auto rdbStore =
        NativeRdb::RdbHelper::GetRdbStore(getRdbStoreConfigEx(rdbConfig, param), -1, callback, *errCode);
    if (*errCode != 0) {
        return ERROR_VALUE;
    }
    auto nativeRdbStore = FFIData::Create<RdbStoreImpl>(rdbStore);
    if (nativeRdbStore == nullptr) {
        *errCode = ERROR_VALUE;
        return ERROR_VALUE;
    }
    return nativeRdbStore->GetID();
}

void DeleteRdbStore(OHOS::AbilityRuntime::Context *context, const char *name,
    int32_t *errCode)
{
    if (context == nullptr || name == nullptr) {
        *errCode = -1;
        return;
    }
    auto abilitycontext = std::make_shared<AppDataMgrJsKit::Context>(context->shared_from_this());
    AppDataMgrJsKit::JSUtils::ContextParam param;
    initContextParam(param, abilitycontext);
    AppDataMgrJsKit::JSUtils::RdbConfig rdbConfig;
    rdbConfig.name = name;

    *errCode = GetRealPath(rdbConfig, param, abilitycontext);
    if (*errCode != NativeRdb::E_OK) {
        return;
    }
    if (!rdbConfig.rootDir.empty()) {
        rdbConfig.isReadOnly = true;
    }
    NativeRdb::RdbStoreConfig storeConfig = getRdbStoreConfig(rdbConfig, param);
    storeConfig.SetDBType(NativeRdb::DB_SQLITE);
    int errCodeSqlite = NativeRdb::RdbHelper::DeleteRdbStore(storeConfig, false);
    storeConfig.SetDBType(NativeRdb::DB_VECTOR);
    int errCodeVector = NativeRdb::RdbHelper::DeleteRdbStore(storeConfig, false);
    *errCode = (errCodeSqlite == NativeRdb::E_OK && errCodeVector == NativeRdb::E_OK) ?
        NativeRdb::E_OK : NativeRdb::E_REMOVE_FILE;
}

void DeleteRdbStoreConfig(OHOS::AbilityRuntime::Context *context, StoreConfig config,
    int32_t *errCode)
{
    if (context == nullptr) {
        *errCode = -1;
        return;
    }
    auto abilitycontext = std::make_shared<AppDataMgrJsKit::Context>(context->shared_from_this());
    AppDataMgrJsKit::JSUtils::ContextParam param;
    initContextParam(param, abilitycontext);
    AppDataMgrJsKit::JSUtils::RdbConfig rdbConfig;
    initRdbConfig(rdbConfig, config);

    *errCode = GetRealPath(rdbConfig, param, abilitycontext);
    if (*errCode != NativeRdb::E_OK) {
        return;
    }
    if (!rdbConfig.rootDir.empty()) {
        rdbConfig.isReadOnly = true;
    }
    NativeRdb::RdbStoreConfig storeConfig = getRdbStoreConfig(rdbConfig, param);
    *errCode = NativeRdb::RdbHelper::DeleteRdbStore(storeConfig, false);
}

void DeleteRdbStoreConfigEx(OHOS::AbilityRuntime::Context *context, const StoreConfigEx *config,
    int32_t *errCode)
{
    if (context == nullptr || config == nullptr) {
        *errCode = ERROR_VALUE;
        return;
    }
    auto abilitycontext = std::make_shared<AppDataMgrJsKit::Context>(context->shared_from_this());
    AppDataMgrJsKit::JSUtils::ContextParam param;
    initContextParam(param, abilitycontext);
    AppDataMgrJsKit::JSUtils::RdbConfig rdbConfig;
    initRdbConfigEx(rdbConfig, *config);

    *errCode = GetRealPath(rdbConfig, param, abilitycontext);
    if (*errCode != NativeRdb::E_OK) {
        return;
    }
    if (!rdbConfig.rootDir.empty()) {
        rdbConfig.isReadOnly = true;
    }
    NativeRdb::RdbStoreConfig storeConfig = getRdbStoreConfigEx(rdbConfig, param);
    *errCode = NativeRdb::RdbHelper::DeleteRdbStore(storeConfig, false);
}
}
}