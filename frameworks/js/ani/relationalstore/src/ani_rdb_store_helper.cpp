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

#define LOG_TAG "AniRdbStoreHelper"
#include <ani.h>
#include <iostream>
#include <string>

#include "logger.h"
#include "rdb_errno.h"
#include "ani_utils.h"
#include "ani_result_set.h"
#include "ani_rdb_error.h"
#include "ani_rdb_store_helper.h"
#include "rdb_sql_utils.h"

namespace OHOS {
namespace RelationalStoreAniKit {

using namespace OHOS::NativeRdb;
using namespace OHOS::Rdb;

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

static ani_object GetRdbStoreSync([[maybe_unused]] ani_env *env, ani_object context, ani_object config)
{
    DefaultOpenCallback callback;
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return nullptr;
    }
    int errCode = OK;
    auto proxy = new RdbStoreProxy();
    if (proxy == nullptr) {
        LOG_ERROR("new RdbStoreProxy failed.");
        return nullptr;
    }
    int errorCode = RdbSqlUtils::CreateDirectory("/data/storage/el2/database/rdb");
    if (errorCode != E_OK) {
        delete proxy;
        ThrowBusinessError(env, E_INNER_ERROR, "CreateDirectory failed.");
        return nullptr;
    }
    auto rdbConfig = RdbStoreConfig("/data/storage/el2/database/rdb/test.db");
    proxy->nativeRdb = RdbHelper::GetRdbStore(rdbConfig, -1, callback, errCode);
    if (proxy->nativeRdb == nullptr) {
        delete proxy;
        ThrowBusinessError(env, E_INNER_ERROR, "RdbHelper returned nullptr.");
        return nullptr;
    }
    static const char *namespaceName = "L@ohos/data/relationalStore/relationalStore;";
    static const char *className = "LRdbStoreInner;";
    static const char *initFinalizer = "initFinalizer";
    ani_object obj = AniObjectUtils::Create(env, namespaceName, className);
    if (nullptr == obj) {
        delete proxy;
        LOG_ERROR("[ANI] Failed to create class '%{public}s' obj", className);
        ThrowBusinessError(env, E_INNER_ERROR, "ANI create class.");
        return nullptr;
    }
    ani_status status = AniObjectUtils::Wrap(env, obj, proxy);
    if (ANI_OK != status) {
        delete proxy;
        LOG_ERROR("[ANI] Failed to wrap for class '%{public}s'", className);
        ThrowBusinessError(env, E_INNER_ERROR, "ANI SetField.");
        return nullptr;
    }
    status = AniObjectUtils::CallObjMethod(env, namespaceName, className, initFinalizer, obj);
    if (ANI_OK != status) {
        // After successful wrapping, the proxy's lifecycle is managed by obj and does not require manual release
        LOG_ERROR("[ANI] Failed to initFinalizer for class '%{public}s'.", className);
        ThrowBusinessError(env, E_INNER_ERROR, "init rdbStore finalizer failed.");
        return nullptr;
    }
    return obj;
}

ani_status RdbStoreHelperInit(ani_env *env)
{
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return ANI_ERROR;
    }

    static const char *namespaceName = "L@ohos/data/relationalStore/relationalStore;";
    ani_namespace ns;
    if (ANI_OK != env->FindNamespace(namespaceName, &ns)) {
        LOG_ERROR("Not found '%{public}s'", namespaceName);
        return ANI_ERROR;
    }

    std::array functions = {
        ani_native_function {"getRdbStoreSync", nullptr, reinterpret_cast<void *>(GetRdbStoreSync)},
    };
    if (ANI_OK != env->Namespace_BindNativeFunctions(ns, functions.data(), functions.size())) {
        LOG_ERROR("Cannot bind native functions to '%{public}s'", namespaceName);
        return ANI_ERROR;
    }
    return ANI_OK;
}

} // namespace RelationalStoreAniKit
} // namespace OHOS

