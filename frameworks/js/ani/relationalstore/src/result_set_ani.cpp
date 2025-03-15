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

#include <ani.h>
#include <iostream>
#include <string>

#include "logger.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "ani_utils.h"
#include "result_set_ani.h"

ani_double GetColumnIndex([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_string col_name)
{
    auto context = AniObjectUtils::Unwrap<ResultSetContext>(env, object);
    if (nullptr == context) {
        std::cerr << "ResultSet should  be initialized properly." << std::endl;
        return 0;
    }
    auto name = AniStringUtils::ToStd(env, col_name);
    int index;
    context->resultset->GetColumnIndex(name, index);
    return index;
}

ani_double GetLong([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_double index)
{
    auto context = AniObjectUtils::Unwrap<ResultSetContext>(env, object);
    if (nullptr == context) {
        std::cerr << "ResultSet should  be initialized properly." << std::endl;
        return 0;
    }
    int64_t ret;
    context->resultset->GetLong(index, ret);
    return ret;
}

ani_string GetString([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_double index)
{
    auto context = AniObjectUtils::Unwrap<ResultSetContext>(env, object);
    if (nullptr == context) {
        std::cerr << "ResultSet should  be initialized properly." << std::endl;
        return nullptr;
    }
    std::string ret;
    context->resultset->GetString(index, ret);
    ani_string retStr;
    env->String_NewUTF8(ret.c_str(), ret.size(), &retStr);
    return retStr;
}

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        std::cerr << "Unsupported ANI_VERSION_1" << std::endl;
        return ANI_ERROR;
    }

    static const char *namespaceName = "L@ohos/data/relationalStore/relationalStore;";
    ani_namespace ns;
    if (ANI_OK != env->FindNamespace(namespaceName, &ns)) {
        std::cerr << "Not found '" << namespaceName << "'" << std::endl;
        return ANI_ERROR;
    }

    ani_class cls;
    const char *className = "LResultSetInner;";
    if (ANI_OK != env->Namespace_FindClass(ns, className, &cls)) {
        std::cerr << "Not found '" << className << "'" << std::endl;
        return ANI_ERROR;
    }

    std::array methods = {
        ani_native_function {"getColumnIndex", nullptr, reinterpret_cast<void *>(GetColumnIndex)},
        ani_native_function {"getLong", nullptr, reinterpret_cast<void *>(GetLong)},
        ani_native_function {"getString", nullptr, reinterpret_cast<void *>(GetString)},
    };
    if (ANI_OK != env->Class_BindNativeMethods(cls, methods.data(), methods.size())) {
        std::cerr << "Cannot bind native methods to '" << className << "'" << std::endl;
        return ANI_ERROR;
    }

    *result = ANI_VERSION_1;
    return ANI_OK;
}