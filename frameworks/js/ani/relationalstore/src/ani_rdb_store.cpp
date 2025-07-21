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
#include "ani_rdb_predicates.h"
#include "rdb_utils.h"

namespace OHOS {
namespace RelationalStoreAniKit {

using namespace OHOS::NativeRdb;
using namespace OHOS::Rdb;

bool ConvertBindArgs(ani_env *env, ani_object args, std::vector<ValueObject> &bindArgs, bool isOptional)
{
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return false;
    }
    if (isOptional) {
        ani_boolean isUndefined = true;
        env->Reference_IsUndefined(args, &isUndefined);
        if (isUndefined) {
            bindArgs.clear();
            return true;
        }
    }
    std::vector<ani_ref> valRefs;
    UnionAccessor array2Ref(env, args);
    bool convertArrayOk = array2Ref.TryConvert(valRefs);
    if (!convertArrayOk) {
        LOG_ERROR("conver array fail");
        return false;
    }
    for (const auto& ref : valRefs) {
        ani_object valObject = static_cast<ani_object>(ref);
        ValueObject valueObject;
        UnionAccessor unionAccessor(env, valObject);
        bool convertOk = false;
        convertOk = unionAccessor.TryConvertVariant(valueObject.value);
        if (convertOk) {
            bindArgs.push_back(std::move(valueObject));
        } else {
            LOG_ERROR("conver ValueObject fail");
            return false;
        }
    }
    return true;
}

void ExecuteSqlSync(ani_env *env, ani_object object, ani_string sql, ani_object args)
{
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return;
    }

    std::vector<ValueObject> bindArgs;

    bool convertOk = ConvertBindArgs(env, args, bindArgs, true);
    if (!convertOk) {
        LOG_ERROR("args conver fail");
        ThrowBusinessError(env, E_PARAM_ERROR, "Unknown parameters.");
        return;
    }

    auto proxy = AniObjectUtils::Unwrap<RdbStoreProxy>(env, object);
    if (proxy == nullptr || proxy->nativeRdb == nullptr) {
        LOG_ERROR("RdbStore should be initialized properly.");
        ThrowBusinessError(env, E_INNER_ERROR, "RdbStore uninitialized.");
        return;
    }
    auto sqlStr = AniStringUtils::ToStd(env, sql);
    auto status = proxy->nativeRdb->ExecuteSql(sqlStr, bindArgs);
    ThrowBusinessError(env, status);
}

void BeginTransaction(ani_env *env, ani_object object)
{
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return;
    }
    auto proxy = AniObjectUtils::Unwrap<RdbStoreProxy>(env, object);
    if (proxy == nullptr || proxy->nativeRdb == nullptr) {
        LOG_ERROR("RdbStore should be initialized properly.");
        ThrowBusinessError(env, E_INNER_ERROR, "RdbStore uninitialized.");
        return;
    }
    auto status = proxy->nativeRdb->BeginTransaction();
    ThrowBusinessError(env, status);
}

void Commit(ani_env *env, ani_object object)
{
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return;
    }
    auto proxy = AniObjectUtils::Unwrap<RdbStoreProxy>(env, object);
    if (proxy == nullptr || proxy->nativeRdb == nullptr) {
        LOG_ERROR("RdbStore should be initialized properly.");
        ThrowBusinessError(env, E_INNER_ERROR, "RdbStore uninitialized.");
        return;
    }
    auto status = proxy->nativeRdb->Commit();
    ThrowBusinessError(env, status);
}

void RollBack(ani_env *env, ani_object object)
{
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return;
    }
    auto proxy = AniObjectUtils::Unwrap<RdbStoreProxy>(env, object);
    if (proxy == nullptr || proxy->nativeRdb == nullptr) {
        LOG_ERROR("RdbStore should be initialized properly.");
        ThrowBusinessError(env, E_INNER_ERROR, "RdbStore uninitialized.");
        return;
    }
    auto status = proxy->nativeRdb->RollBack();
    ThrowBusinessError(env, status);
}

ani_double BatchInsert(ani_env *env, ani_object object, ani_string tableName, ani_object values)
{
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return 0;
    }
    auto proxy = AniObjectUtils::Unwrap<RdbStoreProxy>(env, object);
    if (proxy == nullptr || proxy->nativeRdb == nullptr) {
        LOG_ERROR("RdbStore should be initialized properly.");
        ThrowBusinessError(env, E_INNER_ERROR, "RdbStore uninitialized.");
        return 0;
    }
    auto name = AniStringUtils::ToStd(env, tableName);
    std::vector<ani_ref> valRefs;
    UnionAccessor array2Ref(env, values);
    array2Ref.TryConvert(valRefs);
    ValuesBuckets vbs;
    for (const auto& ref : valRefs) {
        ani_object recordObj = static_cast<ani_object>(ref);
        UnionAccessor recordAccessor(env, recordObj);
        ValuesBucket valuesBucket;
        recordAccessor.TryConvert(valuesBucket);
        vbs.Put(valuesBucket);
    }
    auto [status, ret] = proxy->nativeRdb->BatchInsert(name, vbs);
    ThrowBusinessError(env, status);
    return ret;
}

ani_double DeleteSync(ani_env *env, ani_object object, ani_object predicates)
{
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return 0;
    }
    auto proxy = AniObjectUtils::Unwrap<RdbStoreProxy>(env, object);
    if (proxy == nullptr || proxy->nativeRdb == nullptr) {
        LOG_ERROR("RdbStore should be initialized properly.");
        ThrowBusinessError(env, E_INNER_ERROR, "RdbStore uninitialized.");
        return 0;
    }
    auto nativePredicates = AniObjectUtils::Unwrap<PredicatesProxy>(env, predicates);
    if (nativePredicates == nullptr || nativePredicates->predicates == nullptr) {
        LOG_ERROR("Predicates should be initialized properly.");
        ThrowBusinessError(env, E_INNER_ERROR, "Predicates uninitialized.");
        return 0;
    }
    int rows = 0;
    auto status = proxy->nativeRdb->Delete(rows, *(nativePredicates->predicates));
    ThrowBusinessError(env, status);
    return rows;
}

ani_double DeleteShareSync(ani_env *env, ani_object object, ani_string tableName, ani_object dataSharePredicates)
{
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return 0;
    }
    auto proxy = AniObjectUtils::Unwrap<RdbStoreProxy>(env, object);
    if (proxy == nullptr || proxy->nativeRdb == nullptr) {
        LOG_ERROR("RdbStore should be initialized properly.");
        ThrowBusinessError(env, E_INNER_ERROR, "RdbStore uninitialized.");
        return 0;
    }

    std::string name = AniStringUtils::ToStd(env, tableName);

    auto cppDataSharePredicates = AniObjectUtils::Unwrap<DataShare::DataShareAbsPredicates>(env, dataSharePredicates);
    if (cppDataSharePredicates == nullptr) {
        LOG_ERROR("Predicates should be initialized properly.");
        ThrowBusinessError(env, E_INNER_ERROR, "Predicates uninitialized.");
        return 0;
    }
    RdbPredicates rdbPredicates = RdbDataShareAdapter::RdbUtils::ToPredicates(*cppDataSharePredicates, name);
    int rows = 0;
    auto status = proxy->nativeRdb->Delete(rows, rdbPredicates);
    ThrowBusinessError(env, status);
    return rows;
}

ani_object QuerySqlSync(ani_env *env, ani_object object, ani_string sql, ani_object args)
{
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return nullptr;
    }
    std::vector<ValueObject> bindArgs;
    auto sqlStr = AniStringUtils::ToStd(env, sql);

    if (!ConvertBindArgs(env, args, bindArgs, true)) {
        LOG_ERROR("args conver fail");
        return nullptr;
    }
    auto proxy = AniObjectUtils::Unwrap<RdbStoreProxy>(env, object);
    if (proxy == nullptr || proxy->nativeRdb == nullptr) {
        ThrowBusinessError(env, E_INNER_ERROR, "RdbStore uninitialized.");
        return nullptr;
    }
    auto resultsetProxy = new ResultSetProxy();
    if (resultsetProxy == nullptr) {
        ThrowBusinessError(env, E_INNER_ERROR, "Proxy is nullptr.");
        return nullptr;
    }
    resultsetProxy->resultset = proxy->nativeRdb->QueryByStep(sqlStr, bindArgs);
    if (resultsetProxy->resultset == nullptr) {
        delete resultsetProxy;
        ThrowBusinessError(env, E_INNER_ERROR, "QueryByStep returned nullptr.");
        return nullptr;
    }

    static const char *namespaceName = "@ohos.data.relationalStore.relationalStore";
    static const char *className = "LResultSetInner;";
    static const char *initFinalizer = "initFinalizer";
    ani_object obj = AniObjectUtils::Create(env, namespaceName, className);
    if (nullptr == obj) {
        delete resultsetProxy;
        ThrowBusinessError(env, E_INNER_ERROR, "Create ResultSet failed.class: LResultSetInner;");
        return nullptr;
    }
    ani_status status = AniObjectUtils::Wrap(env, obj, resultsetProxy);
    if (ANI_OK != status) {
        delete resultsetProxy;
        ThrowBusinessError(env, E_INNER_ERROR, "Wrap ResultSet  failed.class: LResultSetInner;");
        return nullptr;
    }
    status = AniObjectUtils::CallObjMethod(env, namespaceName, className, initFinalizer, obj);
    if (ANI_OK != status) {
        ThrowBusinessError(env, E_INNER_ERROR, "init ResultSet finalizer failed.class: LResultSetInner;");
        return nullptr;
    }
    return obj;
}

ani_status RdbStoreInit(ani_env *env)
{
    if (env == nullptr) {
        LOG_ERROR("env is nullptr.");
        return ANI_ERROR;
    }

    static const char *clsName = "@ohos.data.relationalStore.relationalStore.RdbStoreInner";
    ani_class cls;
    if (ANI_OK != env->FindClass(clsName, &cls)) {
        LOG_ERROR("Not found '%{public}s'", clsName);
        return ANI_ERROR;
    }

    std::array methods = {
        ani_native_function {"batchInsertSync", nullptr, reinterpret_cast<void *>(BatchInsert)},
        ani_native_function {"beginTransaction", nullptr, reinterpret_cast<void *>(BeginTransaction)},
        ani_native_function {"commit", ":V", reinterpret_cast<void *>(Commit)},
        ani_native_function {"rollBack", nullptr, reinterpret_cast<void *>(RollBack)},
        ani_native_function {"executeSqlSync", nullptr, reinterpret_cast<void *>(ExecuteSqlSync)},
        ani_native_function {"deleteSync", nullptr, reinterpret_cast<void *>(DeleteSync)},
        ani_native_function {"deleteShareSync", nullptr, reinterpret_cast<void *>(DeleteShareSync)},
        ani_native_function {"querySqlSync", nullptr, reinterpret_cast<void *>(QuerySqlSync)},
    };
    if (ANI_OK != env->Class_BindNativeMethods(cls, methods.data(), methods.size())) {
        LOG_ERROR("Cannot bind native methods to '%{public}s'", clsName);
        return ANI_ERROR;
    }
    return ANI_OK;
}


} // namespace RelationalStoreAniKit
} // namespace OHOS

