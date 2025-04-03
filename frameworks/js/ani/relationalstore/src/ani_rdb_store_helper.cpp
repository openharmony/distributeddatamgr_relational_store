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
    int errCode = OK;
    auto proxy = new RdbStoreProxy();
    RdbSqlUtils::CreateDirectory("/data/storage/el2/database/rdb");
    auto rdbConfig = RdbStoreConfig("/data/storage/el2/database/rdb/test.db");
    proxy->nativeRdb = RdbHelper::GetRdbStore(rdbConfig, -1, callback, errCode);

    static const char *namespaceName = "L@ohos/data/relationalStore/relationalStore;";
    static const char *className = "LRdbStoreInner;";
    ani_object obj = AniObjectUtils::Create(env, namespaceName, className);
    if (nullptr == obj) {
        std::cerr << "[ANI] Failed to create class obj" << className << std::endl;
        return nullptr;
    }
    ani_status status = AniObjectUtils::Wrap(env, obj, proxy);
    if (ANI_OK != status) {
        std::cerr << "[ANI] Failed to wrap for class " << className << std::endl;
        return nullptr;
    }
    return obj;
}

ani_status RdbStoreHelperInit(ani_env *env)
{
    static const char *namespaceName = "L@ohos/data/relationalStore/relationalStore;";
    ani_namespace ns;
    if (ANI_OK != env->FindNamespace(namespaceName, &ns)) {
        std::cerr << "Not found '" << namespaceName << "'" << std::endl;
        return ANI_ERROR;
    }

    std::array functions = {
        ani_native_function {"getRdbStoreSync", nullptr, reinterpret_cast<void *>(GetRdbStoreSync)},
    };
    if (ANI_OK != env->Namespace_BindNativeFunctions(ns, functions.data(), functions.size())) {
        std::cerr << "Cannot bind native functions to '" << namespaceName << "'" << std::endl;
        return ANI_ERROR;
    }
    return ANI_OK;
}

} // namespace RelationalStoreAniKit
} // namespace OHOS
