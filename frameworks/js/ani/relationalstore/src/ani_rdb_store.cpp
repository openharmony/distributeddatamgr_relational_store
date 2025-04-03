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

#define LOG_TAG "AniRdbStore"
#include <ani.h>
#include <iostream>
#include <string>

#include "logger.h"
#include "rdb_errno.h"
#include "ani_utils.h"
#include "ani_result_set.h"
#include "ani_rdb_error.h"
#include "ani_rdb_store_helper.h"

namespace OHOS {
namespace RelationalStoreAniKit {

using namespace OHOS::NativeRdb;
using namespace OHOS::Rdb;

void ExecuteSqlSync(ani_env *env, ani_object object, ani_string sql, ani_object args)
{
    std::vector<ValueObject> bindArgs;
    bindArgs.clear();

    auto proxy = AniObjectUtils::Unwrap<RdbStoreProxy>(env, object);
    if (nullptr == proxy) {
        std::cerr << "RdbStore should be initialized properly." << std::endl;
        return;
    }
    if (nullptr == proxy->nativeRdb) {
        std::cerr << "RdbStore should be initialized properly." << std::endl;
        return;
    }
    std::cerr << "Got proxy" << std::endl;
    auto sqlStr = AniStringUtils::ToStd(env, sql);
    bindArgs.clear();
    auto status = proxy->nativeRdb->ExecuteSql(sqlStr, bindArgs);
    std::cerr << "Native Rdb call returned " << status << std::endl;
    ThrowBusinessError(env, status);
}

void BeginTransaction(ani_env *env, ani_object object)
{
    auto proxy = AniObjectUtils::Unwrap<RdbStoreProxy>(env, object);
    if (nullptr == proxy) {
        std::cerr << "RdbStore should be initialized properly." << std::endl;
        return;
    }
    if (nullptr == proxy->nativeRdb) {
        std::cerr << "RdbStore should be initialized properly." << std::endl;
        return;
    }
    auto status = proxy->nativeRdb->BeginTransaction();
    ThrowBusinessError(env, status);
}

void Commit(ani_env *env, ani_object object)
{
    auto proxy = AniObjectUtils::Unwrap<RdbStoreProxy>(env, object);
    if (nullptr == proxy) {
        std::cerr << "RdbStore should be initialized properly." << std::endl;
        return;
    }
    if (nullptr == proxy->nativeRdb) {
        std::cerr << "RdbStore should be initialized properly." << std::endl;
        return;
    }
    auto status = proxy->nativeRdb->Commit();
    ThrowBusinessError(env, status);
}

void RollBack(ani_env *env, ani_object object)
{
    auto proxy = AniObjectUtils::Unwrap<RdbStoreProxy>(env, object);
    if (nullptr == proxy) {
        std::cerr << "RdbStore should be initialized properly." << std::endl;
        return;
    }
    if (nullptr == proxy->nativeRdb) {
        std::cerr << "RdbStore should be initialized properly." << std::endl;
        return;
    }
    auto status = proxy->nativeRdb->RollBack();
    ThrowBusinessError(env, status);
}

void BatchInsert(ani_env *env, ani_object object)
{
    auto proxy = AniObjectUtils::Unwrap<RdbStoreProxy>(env, object);
    if (nullptr == proxy) {
        std::cerr << "RdbStore should be initialized properly." << std::endl;
        return;
    }
    if (nullptr == proxy->nativeRdb) {
        std::cerr << "RdbStore should be initialized properly." << std::endl;
        return;
    }
}

ani_status RdbStoreInit(ani_env *env)
{
    static const char *namespaceName = "L@ohos/data/relationalStore/relationalStore;";
    ani_namespace ns;
    if (ANI_OK != env->FindNamespace(namespaceName, &ns)) {
        std::cerr << "Not found '" << namespaceName << "'" << std::endl;
        return ANI_ERROR;
    }

    static const char *clsName = "LRdbStoreInner;";
    ani_class cls;
    if (ANI_OK != env->Namespace_FindClass(ns, clsName, &cls)) {
        std::cerr << "[ANI] Not found class " << clsName << std::endl;
        return ANI_ERROR;
    }

    std::array methods = {
        ani_native_function {"batchInsertSync", nullptr, reinterpret_cast<void *>(BatchInsert)},
        ani_native_function {"beginTransaction", nullptr, reinterpret_cast<void *>(BeginTransaction)},
        ani_native_function {"commit", ":V", reinterpret_cast<void *>(Commit)},
        ani_native_function {"rollBack", nullptr, reinterpret_cast<void *>(RollBack)},
        ani_native_function {"executeSqlSync", nullptr, reinterpret_cast<void *>(ExecuteSqlSync)},
    };
    if (ANI_OK != env->Class_BindNativeMethods(cls, methods.data(), methods.size())) {
        std::cerr << "Cannot bind native methods to '" << clsName << "'" << std::endl;
        return ANI_ERROR;
    }
    return ANI_OK;
}


} // namespace RelationalStoreAniKit
} // namespace OHOS
