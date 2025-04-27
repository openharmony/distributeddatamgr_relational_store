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

#define LOG_TAG "AniResultSet"
#include <ani.h>
#include <iostream>
#include <string>

#include "logger.h"
#include "rdb_errno.h"
#include "ani_utils.h"
#include "ani_result_set.h"
#include "ani_rdb_error.h"

namespace OHOS {
namespace RelationalStoreAniKit {

using namespace OHOS::NativeRdb;
using namespace OHOS::Rdb;

ani_double GetColumnIndex(ani_env *env, ani_object object, ani_string col_name)
{
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return 0;
    }
    auto proxy = AniObjectUtils::Unwrap<ResultSetProxy>(env, object);
    if (proxy == nullptr || proxy->resultset == nullptr) {
        LOG_ERROR("ResultSet should be initialized properly.");
        ThrowBusinessError(env, E_INNER_ERROR, "ResultSet uninitialized.");
        return 0;
    }
    auto name = AniStringUtils::ToStd(env, col_name);
    int index;
    auto status = proxy->resultset->GetColumnIndex(name, index);
    ThrowBusinessError(env, status);
    return index;
}

ani_double GetLong(ani_env *env, ani_object object, ani_double index)
{
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return 0;
    }
    auto proxy = AniObjectUtils::Unwrap<ResultSetProxy>(env, object);
    if (proxy == nullptr || proxy->resultset == nullptr) {
        LOG_ERROR("ResultSet should be initialized properly.");
        ThrowBusinessError(env, E_INNER_ERROR, "ResultSet uninitialized.");
        return 0;
    }
    int64_t ret;
    auto status = proxy->resultset->GetLong(index, ret);
    ThrowBusinessError(env, status);
    return ret;
}

ani_string GetString(ani_env *env, ani_object object, ani_double index)
{
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return nullptr;
    }
    auto proxy = AniObjectUtils::Unwrap<ResultSetProxy>(env, object);
    if (proxy == nullptr || proxy->resultset == nullptr) {
        LOG_ERROR("ResultSet should be initialized properly.");
        ThrowBusinessError(env, E_INNER_ERROR, "ResultSet uninitialized.");
        return nullptr;
    }
    std::string ret;
    auto status = proxy->resultset->GetString(index, ret);
    ThrowBusinessError(env, status);
    ani_string retStr;
    env->String_NewUTF8(ret.c_str(), ret.size(), &retStr);
    return retStr;
}

ani_boolean GoToFirstRow(ani_env *env, ani_object object)
{
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return false;
    }
    auto proxy = AniObjectUtils::Unwrap<ResultSetProxy>(env, object);
    if (proxy == nullptr || proxy->resultset == nullptr) {
        LOG_ERROR("ResultSet should be initialized properly.");
        ThrowBusinessError(env, E_INNER_ERROR, "ResultSet uninitialized.");
        return false;
    }
    auto status = proxy->resultset->GoToFirstRow();
    return (status == ANI_OK);
}

ani_status ResultSetInit(ani_env *env)
{
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return ANI_ERROR;
    }
    static const char *namespaceName = "L@ohos/data/relationalStore/relationalStore;";
    ani_namespace ns;
    if (ANI_OK != env->FindNamespace(namespaceName, &ns)) {
        LOG_ERROR("Not found '%{public}s", namespaceName);
        return ANI_ERROR;
    }

    ani_class cls;
    const char *className = "LResultSetInner;";
    if (ANI_OK != env->Namespace_FindClass(ns, className, &cls)) {
        LOG_ERROR("Not found '%{public}s", className);
        return ANI_ERROR;
    }

    std::array methods = {
        ani_native_function {"getColumnIndex", nullptr, reinterpret_cast<void *>(GetColumnIndex)},
        ani_native_function {"getLong", nullptr, reinterpret_cast<void *>(GetLong)},
        ani_native_function {"getString", nullptr, reinterpret_cast<void *>(GetString)},
        ani_native_function {"goToFirstRow", nullptr, reinterpret_cast<void *>(GoToFirstRow)},
    };
    if (ANI_OK != env->Class_BindNativeMethods(cls, methods.data(), methods.size())) {
        LOG_ERROR("Cannot bind native methods to '%{public}s", className);
        return ANI_ERROR;
    }
    return ANI_OK;
}

} // namespace RelationalStoreAniKit
} // namespace OHOS

