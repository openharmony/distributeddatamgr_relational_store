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

#include "ffi_remote_data.h"
#include "js_ability.h"
#include "logger.h"
#include "native_log.h"
#include "napi_base_context.h"
#include "napi_rdb_js_utils.h"
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_sql_utils.h"
#include "rdb_store_config.h"
#include "relational_store_impl_rdbstore.h"
#include "relational_store_utils.h"
#include "unistd.h"
#include "value_object.h"

#ifndef PATH_SPLIT
#define PATH_SPLIT '/'
#endif

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

int32_t GetRealPath(AppDataMgrJsKit::JSUtils::RdbConfig &rdbConfig,
    const AppDataMgrJsKit::JSUtils::ContextParam &param,
    std::shared_ptr<OHOS::AppDataMgrJsKit::Context> abilitycontext)
{
    if (rdbConfig.name.find(PATH_SPLIT) != std::string::npos) {
        LOGE("Parameter error. The StoreConfig.name must be a file name without path.");
        return RelationalStoreJsKit::E_PARAM_ERROR;
    }

    if (!rdbConfig.customDir.empty()) {
        if (rdbConfig.customDir.find_first_of(PATH_SPLIT) == 0) {
            LOGE("Parameter error. The customDir must be a relative directory.");
            return RelationalStoreJsKit::E_PARAM_ERROR;
        }
        if (rdbConfig.customDir.length() > MAX_CUSTOM_DIR_LENGTH) {
            LOGE("Parameter error. The customDir length must be less than or equal to 128 bytes.");
            return RelationalStoreJsKit::E_PARAM_ERROR;
        }
    }

    std::string baseDir = param.baseDir;
    if (!rdbConfig.dataGroupId.empty()) {
        if (!param.isStageMode) {
            return RelationalStoreJsKit::E_NOT_STAGE_MODE;
        }
        std::string groupDir;
        int errCode = abilitycontext->GetSystemDatabaseDir(rdbConfig.dataGroupId, groupDir);
        if (errCode != NativeRdb::E_OK && groupDir.empty()) {
            return RelationalStoreJsKit::E_DATA_GROUP_ID_INVALID;
        }
        baseDir = groupDir;
    }

    auto [realPath, errorCode] =
        NativeRdb::RdbSqlUtils::GetDefaultDatabasePath(baseDir, rdbConfig.name, rdbConfig.customDir);
    if (errorCode != NativeRdb::E_OK || realPath.length() > MAX_DATABASE_PATH_LENGTH) {
        LOGE("Parameter error. The database path must be a valid path.");
        return RelationalStoreJsKit::E_PARAM_ERROR;
    }
    rdbConfig.path = realPath;
    return NativeRdb::E_OK;
}

void initContextParam(AppDataMgrJsKit::JSUtils::ContextParam &param,
    std::shared_ptr<OHOS::AppDataMgrJsKit::Context> abilitycontext)
{
    param.bundleName = abilitycontext->GetBundleName();
    param.moduleName = abilitycontext->GetModuleName();
    param.baseDir = abilitycontext->GetDatabaseDir();
    param.area = abilitycontext->GetArea();
    param.isSystemApp = abilitycontext->IsSystemAppCalled();
    param.isStageMode = abilitycontext->IsStageMode();
}

void initRdbConfig(AppDataMgrJsKit::JSUtils::RdbConfig &rdbConfig, StoreConfig &config)
{
    rdbConfig.isEncrypt = config.encrypt;
    rdbConfig.isSearchable = config.isSearchable;
    rdbConfig.isAutoClean = config.autoCleanDirtyData;
    rdbConfig.securityLevel = static_cast<NativeRdb::SecurityLevel>(config.securityLevel);
    rdbConfig.dataGroupId = config.dataGroupId;
    rdbConfig.name = config.name;
    rdbConfig.customDir = config.customDir;
}

void initRdbConfigEx(AppDataMgrJsKit::JSUtils::RdbConfig &rdbConfig, const StoreConfigEx &config)
{
    rdbConfig.isEncrypt = config.encrypt;
    rdbConfig.isSearchable = config.isSearchable;
    rdbConfig.isAutoClean = config.autoCleanDirtyData;
    rdbConfig.securityLevel = static_cast<NativeRdb::SecurityLevel>(config.securityLevel);
    rdbConfig.dataGroupId = config.dataGroupId;
    rdbConfig.name = config.name;
    rdbConfig.customDir = config.customDir;
    rdbConfig.rootDir = config.rootDir;
    rdbConfig.vector = config.vector;
    rdbConfig.allowRebuild = config.allowRebuild;
    rdbConfig.isReadOnly = config.isReadOnly;
    rdbConfig.pluginLibs = CArrStrToVector(config.pluginLibs);
    rdbConfig.cryptoParam = ToCCryptoParam(config.cryptoParam);
    rdbConfig.tokenizer = static_cast<OHOS::NativeRdb::Tokenizer>(config.tokenizer);
    rdbConfig.persist = config.persist;
}

NativeRdb::RdbStoreConfig getRdbStoreConfig(const AppDataMgrJsKit::JSUtils::RdbConfig &rdbConfig,
    const AppDataMgrJsKit::JSUtils::ContextParam &param)
{
    NativeRdb::RdbStoreConfig rdbStoreConfig(rdbConfig.path);
    rdbStoreConfig.SetEncryptStatus(rdbConfig.isEncrypt);
    rdbStoreConfig.SetSearchable(rdbConfig.isSearchable);
    rdbStoreConfig.SetIsVector(rdbConfig.vector);
    rdbStoreConfig.SetAutoClean(rdbConfig.isAutoClean);
    rdbStoreConfig.SetSecurityLevel(rdbConfig.securityLevel);
    rdbStoreConfig.SetDataGroupId(rdbConfig.dataGroupId);
    rdbStoreConfig.SetName(rdbConfig.name);
    rdbStoreConfig.SetCustomDir(rdbConfig.customDir);
    rdbStoreConfig.SetAllowRebuild(rdbConfig.allowRebuild);

    if (!param.bundleName.empty()) {
        rdbStoreConfig.SetBundleName(param.bundleName);
    }
    rdbStoreConfig.SetModuleName(param.moduleName);
    rdbStoreConfig.SetArea(param.area);
    return rdbStoreConfig;
}

NativeRdb::RdbStoreConfig getRdbStoreConfigEx(const AppDataMgrJsKit::JSUtils::RdbConfig &rdbConfig,
    const AppDataMgrJsKit::JSUtils::ContextParam &param)
{
    NativeRdb::RdbStoreConfig rdbStoreConfig(rdbConfig.path);
    rdbStoreConfig.SetEncryptStatus(rdbConfig.isEncrypt);
    rdbStoreConfig.SetSearchable(rdbConfig.isSearchable);
    rdbStoreConfig.SetIsVector(rdbConfig.vector);
    rdbStoreConfig.SetDBType(rdbConfig.vector ? NativeRdb::DB_VECTOR : NativeRdb::DB_SQLITE);
    rdbStoreConfig.SetStorageMode(rdbConfig.persist ? NativeRdb::StorageMode::MODE_DISK :
        NativeRdb::StorageMode::MODE_MEMORY);
    rdbStoreConfig.SetAutoClean(rdbConfig.isAutoClean);
    rdbStoreConfig.SetSecurityLevel(rdbConfig.securityLevel);
    rdbStoreConfig.SetDataGroupId(rdbConfig.dataGroupId);
    rdbStoreConfig.SetName(rdbConfig.name);
    rdbStoreConfig.SetCustomDir(rdbConfig.customDir);
    rdbStoreConfig.SetAllowRebuild(rdbConfig.allowRebuild);
    rdbStoreConfig.SetReadOnly(rdbConfig.isReadOnly);
    rdbStoreConfig.SetIntegrityCheck(NativeRdb::IntegrityCheck::NONE);
    rdbStoreConfig.SetTokenizer(rdbConfig.tokenizer);

    if (!param.bundleName.empty()) {
        rdbStoreConfig.SetBundleName(param.bundleName);
    }
    rdbStoreConfig.SetModuleName(param.moduleName);
    rdbStoreConfig.SetArea(param.area);
    rdbStoreConfig.SetPluginLibs(rdbConfig.pluginLibs);
    rdbStoreConfig.SetHaMode(rdbConfig.haMode);

    rdbStoreConfig.SetCryptoParam(rdbConfig.cryptoParam);
    return rdbStoreConfig;
}

int64_t GetRdbStore(OHOS::AbilityRuntime::Context* context, StoreConfig config,
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

int64_t GetRdbStoreEx(OHOS::AbilityRuntime::Context* context, const StoreConfigEx *config,
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

void DeleteRdbStore(OHOS::AbilityRuntime::Context* context, const char* name,
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

void DeleteRdbStoreConfig(OHOS::AbilityRuntime::Context* context, StoreConfig config,
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

void DeleteRdbStoreConfigEx(OHOS::AbilityRuntime::Context* context, const StoreConfigEx *config,
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