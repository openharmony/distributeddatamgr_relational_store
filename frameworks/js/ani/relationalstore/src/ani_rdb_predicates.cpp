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

#define LOG_TAG "AniRdbPredicates"
#include <ani.h>
#include <iostream>
#include <string>

#include "logger.h"
#include "rdb_errno.h"
#include "ani_utils.h"
#include "ani_rdb_predicates.h"
#include "ani_rdb_error.h"

namespace OHOS {
namespace RelationalStoreAniKit {

using namespace OHOS::NativeRdb;
using namespace OHOS::Rdb;

void InitNativePredicates(ani_env *env, ani_object object, ani_string tableName)
{
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return;
    }
    auto proxy = new PredicatesProxy();
    auto tname = AniStringUtils::ToStd(env, tableName);
    proxy->predicates = std::make_shared<RdbPredicates>(tname);
    ani_status status = env->Object_SetFieldByName_Long(object, "nativePtr", reinterpret_cast<ani_long>(proxy));
    if (ANI_OK != status) {
        LOG_ERROR("[ANI] Failed to set nativePtr to predicates object.");
    }
}
ani_status PredicatesInit(ani_env *env)
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

    ani_class cls;
    const char *className = "LRdbPredicates;";
    if (ANI_OK != env->Namespace_FindClass(ns, className, &cls)) {
        LOG_ERROR("Not found '%{public}s'", className);
        return ANI_ERROR;
    }

    std::array methods = {
        ani_native_function {"initNativePredicates", nullptr, reinterpret_cast<void *>(InitNativePredicates)},
    };
    if (ANI_OK != env->Class_BindNativeMethods(cls, methods.data(), methods.size())) {
        LOG_ERROR("Cannot bind native methods to '%{public}s'", className);
        return ANI_ERROR;
    }
    return ANI_OK;
}

} // namespace RelationalStoreAniKit
} // namespace OHOS

