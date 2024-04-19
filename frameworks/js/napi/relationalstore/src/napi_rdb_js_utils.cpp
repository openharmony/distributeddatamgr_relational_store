/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#define LOG_TAG "NapiRdbJsUtils"
#include "napi_rdb_js_utils.h"

#include <memory>
#include <tuple>

#include "js_ability.h"
#include "js_native_api_types.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_sql_utils.h"
#include "result_set.h"

#define NAPI_CALL_RETURN_ERR(theCall, retVal) \
    do {                                      \
        if ((theCall) != napi_ok) {           \
            return retVal;                    \
        }                                     \
    } while (0)

#ifndef PATH_SPLIT
#define PATH_SPLIT '/'
#endif
namespace OHOS::AppDataMgrJsKit {
namespace JSUtils {
using namespace OHOS::Rdb;
using namespace NativeRdb;
using RelationalStoreJsKit::ParamError;
using namespace RelationalStoreJsKit;
template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, Asset &output)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, jsValue, &type);
    bool isArray;
    napi_status status_array = napi_is_array(env, jsValue, &isArray);
    if (status != napi_ok || type != napi_object || status_array != napi_ok || isArray) {
        LOG_DEBUG("napi_typeof failed status = %{public}d type = %{public}d", status, type);
        return napi_invalid_arg;
    }

    NAPI_CALL_RETURN_ERR(GetNamedProperty(env, jsValue, "name", output.name), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GetNamedProperty(env, jsValue, "uri", output.uri), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GetNamedProperty(env, jsValue, "createTime", output.createTime), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GetNamedProperty(env, jsValue, "modifyTime", output.modifyTime), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GetNamedProperty(env, jsValue, "size", output.size), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GetNamedProperty(env, jsValue, "path", output.path), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GetNamedProperty(env, jsValue, "status", output.status, true), napi_invalid_arg);
    if (output.status != AssetValue::STATUS_DELETE) {
        output.status = AssetValue::STATUS_UNKNOWN;
    }
    output.hash = output.modifyTime + "_" + output.size;
    return napi_ok;
}

template<>
int32_t Convert2Value(napi_env env, napi_value input, DistributedRdb::Reference &output)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, input, &type);
    if (status != napi_ok || type != napi_object) {
        LOG_DEBUG("napi_typeof failed status = %{public}d type = %{public}d", status, type);
        return napi_invalid_arg;
    }

    NAPI_CALL_RETURN_ERR(GetNamedProperty(env, input, "sourceTable", output.sourceTable), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GetNamedProperty(env, input, "targetTable", output.targetTable), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GetNamedProperty(env, input, "refFields", output.refFields), napi_invalid_arg);
    return napi_ok;
}

template<>
int32_t Convert2Value(napi_env env, napi_value input, DistributedRdb::DistributedConfig &output)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, input, &type);
    if (status != napi_ok || type != napi_object) {
        LOG_DEBUG("napi_typeof failed status = %{public}d type = %{public}d", status, type);
        return napi_invalid_arg;
    }

    NAPI_CALL_RETURN_ERR(GetNamedProperty(env, input, "autoSync", output.autoSync), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GetNamedProperty(env, input, "references", output.references, true), napi_invalid_arg);
    return napi_ok;
}

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, ValueObject &valueObject)
{
    auto status = Convert2Value(env, jsValue, valueObject.value);
    if (status != napi_ok) {
        return napi_invalid_arg;
    }
    return napi_ok;
}

template<>
napi_value Convert2JSValue(napi_env env, const Asset &value)
{
    napi_value object = nullptr;
    NAPI_CALL_RETURN_ERR(napi_create_object(env, &object), object);
    NAPI_CALL_RETURN_ERR(SetNamedProperty(env, object, "name", value.name), object);
    NAPI_CALL_RETURN_ERR(SetNamedProperty(env, object, "uri", value.uri), object);
    NAPI_CALL_RETURN_ERR(SetNamedProperty(env, object, "createTime", value.createTime), object);
    NAPI_CALL_RETURN_ERR(SetNamedProperty(env, object, "modifyTime", value.modifyTime), object);
    NAPI_CALL_RETURN_ERR(SetNamedProperty(env, object, "size", value.size), object);
    NAPI_CALL_RETURN_ERR(SetNamedProperty(env, object, "path", value.path), object);
    auto outputStatus = value.status & ~0xF0000000;
    NAPI_CALL_RETURN_ERR(SetNamedProperty(env, object, "status", outputStatus), object);
    return object;
}

template<>
napi_value Convert2JSValue(napi_env env, const RowEntity &rowEntity)
{
    napi_value object = nullptr;
    NAPI_CALL_RETURN_ERR(napi_create_object(env, &object), object);
    auto &values = rowEntity.Get();
    for (auto const &[key, value] : values) {
        NAPI_CALL_RETURN_ERR(SetNamedProperty(env, object, key.c_str(), value), object);
    }
    return object;
}

template<>
napi_value Convert2JSValue(napi_env env, const ValueObject &valueObject)
{
    return JSUtils::Convert2JSValue(env, valueObject.value);
}

template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::Statistic &statistic)
{
    napi_value object = nullptr;
    NAPI_CALL_RETURN_ERR(napi_create_object(env, &object), object);

    NAPI_CALL_RETURN_ERR(SetNamedProperty(env, object, "total", statistic.total), object);
    NAPI_CALL_RETURN_ERR(SetNamedProperty(env, object, "success", statistic.success), object);
    NAPI_CALL_RETURN_ERR(SetNamedProperty(env, object, "successful", statistic.success), object);
    NAPI_CALL_RETURN_ERR(SetNamedProperty(env, object, "failed", statistic.failed), object);
    NAPI_CALL_RETURN_ERR(SetNamedProperty(env, object, "remained", statistic.untreated), object);
    return object;
}

template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::TableDetail &tableDetail)
{
    napi_value object = nullptr;
    NAPI_CALL_RETURN_ERR(napi_create_object(env, &object), object);
    NAPI_CALL_RETURN_ERR(SetNamedProperty(env, object, "upload", tableDetail.upload), object);
    NAPI_CALL_RETURN_ERR(SetNamedProperty(env, object, "download", tableDetail.download), object);
    return object;
}

template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::ProgressDetail &progressDetail)
{
    napi_value object = nullptr;
    NAPI_CALL_RETURN_ERR(napi_create_object(env, &object), object);

    napi_value schedule = Convert2JSValue(env, progressDetail.progress);
    napi_value code = Convert2JSValue(env, progressDetail.code);
    napi_value details = Convert2JSValue(env, progressDetail.details);
    if (details == nullptr) {
        return nullptr;
    }
    napi_set_named_property(env, object, "schedule", schedule);
    napi_set_named_property(env, object, "code", code);
    napi_set_named_property(env, object, "details", details);
    return object;
}

template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::Details &details)
{
    return nullptr;
}

template<>
napi_value Convert2JSValue(napi_env env, const JSChangeInfo &value)
{
    napi_value object = nullptr;
    NAPI_CALL_RETURN_ERR(napi_create_object(env, &object), object);
    NAPI_CALL_RETURN_ERR(SetNamedProperty(env, object, "table", value.table), object);
    NAPI_CALL_RETURN_ERR(SetNamedProperty(env, object, "type", value.type), object);
    NAPI_CALL_RETURN_ERR(SetNamedProperty(env, object, "inserted", value.inserted), object);
    NAPI_CALL_RETURN_ERR(SetNamedProperty(env, object, "updated", value.updated), object);
    NAPI_CALL_RETURN_ERR(SetNamedProperty(env, object, "deleted", value.deleted), object);
    return object;
}

template<>
napi_value Convert2JSValue(napi_env env, const Date &date)
{
    napi_value jsDeta = nullptr;
    NAPI_CALL_RETURN_ERR(napi_create_date(env, date, &jsDeta), jsDeta);
    return jsDeta;
}
template<>
napi_value Convert2JSValue(napi_env env, const BigInt& value)
{
    napi_value val = nullptr;
    napi_status status = napi_create_bigint_words(env, value.Sign(), value.Size(), value.TrueForm(), &val);
    if (status != napi_ok) {
        return nullptr;
    }
    return val;
}

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, BigInt& value)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, jsValue, &type);
    if (status != napi_ok || type != napi_bigint) {
        return napi_invalid_arg;
    }
    int sign = 0;
    size_t count = 0;
    status = napi_get_value_bigint_words(env, jsValue, nullptr, &count, nullptr);
    if (status != napi_ok) {
        return napi_bigint_expected;
    }
    std::vector<uint64_t> words(count, 0);
    status = napi_get_value_bigint_words(env, jsValue, &sign, &count, words.data());
    if (status != napi_ok) {
        return napi_bigint_expected;
    }
    value = BigInteger(sign, std::move(words));
    return napi_ok;
}

template<>
std::string ToString(const PRIKey &key)
{
    auto strVal = std::get_if<std::string>(&key);
    if (strVal != nullptr) {
        return *strVal;
    }
    auto intVal = std::get_if<int64_t>(&key);
    if (intVal != nullptr) {
        return std::to_string(*intVal);
    }
    auto dbVal = std::get_if<double>(&key);
    if (dbVal != nullptr) {
        return std::to_string(static_cast<int64_t>(*dbVal));
    }
    return {};
}

bool IsNapiString(napi_env env, napi_value value)
{
    napi_valuetype type = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, value, &type), false);
    return type == napi_string;
}

int32_t GetLevel(SecurityLevel level, SecurityLevel &out)
{
    switch (level) {
        case SecurityLevel::S1:
        case SecurityLevel::S2:
        case SecurityLevel::S3:
        case SecurityLevel::S4:
            out = level;
            return napi_ok;
        default:
            return napi_invalid_arg;
    }
}

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, RdbConfig &rdbConfig)
{
    int32_t status = GetNamedProperty(env, jsValue, "encrypt", rdbConfig.isEncrypt, true);
    ASSERT(OK == status, "get encrypt failed.", napi_invalid_arg);

    int32_t securityLevel;
    status = GetNamedProperty(env, jsValue, "securityLevel", securityLevel);
    ASSERT(OK == status, "get securityLevel failed.", napi_invalid_arg);
    status = GetLevel(static_cast<SecurityLevel>(securityLevel), rdbConfig.securityLevel);
    ASSERT(status == napi_ok, "get securityLevel failed", status);

    status = GetNamedProperty(env, jsValue, "dataGroupId", rdbConfig.dataGroupId, true);
    ASSERT(OK == status, "get dataGroupId failed.", napi_invalid_arg);

    status = GetNamedProperty(env, jsValue, "autoCleanDirtyData", rdbConfig.isAutoClean, true);
    ASSERT(OK == status, "get autoCleanDirtyData failed.", napi_invalid_arg);

    status = GetNamedProperty(env, jsValue, "name", rdbConfig.name);
    ASSERT(OK == status, "get name failed.", napi_invalid_arg);

    status = GetNamedProperty(env, jsValue, "customDir", rdbConfig.customDir, true);
    ASSERT(OK == status, "get customDir failed.", napi_invalid_arg);

    GetNamedProperty(env, jsValue, "isSearchable", rdbConfig.isSearchable, true);
    ASSERT(OK == status, "get isSearchable failed.", napi_invalid_arg);

    GetNamedProperty(env, jsValue, "vector", rdbConfig.vector, true);
    ASSERT(OK == status, "get vector failed.", napi_invalid_arg);

    GetNamedProperty(env, jsValue, "allowRebuild", rdbConfig.allowRebuild, true);
    ASSERT(OK == status, "get allowRebuild failed.", napi_invalid_arg);
    return napi_ok;
}

int32_t GetCurrentAbilityParam(napi_env env, napi_value jsValue, ContextParam &param)
{
    std::shared_ptr<Context> context = JSAbility::GetCurrentAbility(env, jsValue);
    if (context == nullptr) {
        return napi_invalid_arg;
    }
    param.baseDir = context->GetDatabaseDir();
    param.moduleName = context->GetModuleName();
    param.area = context->GetArea();
    param.bundleName = context->GetBundleName();
    param.isSystemApp = context->IsSystemAppCalled();
    return napi_ok;
}

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, ContextParam &param)
{
    if (jsValue == nullptr) {
        LOG_INFO("hasProp is false -> fa stage");
        param.isStageMode = false;
        return GetCurrentAbilityParam(env, jsValue, param);
    }

    int32_t status = GetNamedProperty(env, jsValue, "stageMode", param.isStageMode);
    ASSERT(status == napi_ok, "get stageMode param failed", napi_invalid_arg);
    if (!param.isStageMode) {
        LOG_WARN("isStageMode is false -> fa stage");
        return GetCurrentAbilityParam(env, jsValue, param);
    }
    LOG_DEBUG("stage mode branch");
    status = GetNamedProperty(env, jsValue, "databaseDir", param.baseDir);
    ASSERT(status == napi_ok, "get databaseDir failed.", napi_invalid_arg);
    status = GetNamedProperty(env, jsValue, "area", param.area, true);
    ASSERT(status == napi_ok, "get area failed.", napi_invalid_arg);

    napi_value hapInfo = nullptr;
    GetNamedProperty(env, jsValue, "currentHapModuleInfo", hapInfo);
    if (hapInfo != nullptr) {
        status = GetNamedProperty(env, hapInfo, "name", param.moduleName);
        ASSERT(status == napi_ok, "get currentHapModuleInfo.name failed.", napi_invalid_arg);
    }

    napi_value appInfo = nullptr;
    GetNamedProperty(env, jsValue, "applicationInfo", appInfo);
    if (appInfo != nullptr) {
        status = GetNamedProperty(env, appInfo, "name", param.bundleName);
        ASSERT(status == napi_ok, "get applicationInfo.name failed.", napi_invalid_arg);
        status = GetNamedProperty(env, appInfo, "systemApp", param.isSystemApp, true);
        ASSERT(status == napi_ok, "get applicationInfo.systemApp failed.", napi_invalid_arg);
    }
    return napi_ok;
}

std::tuple<int32_t, std::shared_ptr<Error>> GetRealPath(
    napi_env env, napi_value jsValue, RdbConfig &rdbConfig, ContextParam &param)
{
    CHECK_RETURN_CORE(rdbConfig.name.find(PATH_SPLIT) == std::string::npos, RDB_DO_NOTHING,
        std::make_tuple(ERR, std::make_shared<ParamError>("StoreConfig.name", "a file name without path.")));

    if (!rdbConfig.customDir.empty()) {
        // determine if the first character of customDir is '/'
        CHECK_RETURN_CORE(rdbConfig.customDir.find_first_of(PATH_SPLIT) != 0, RDB_DO_NOTHING,
            std::make_tuple(ERR, std::make_shared<ParamError>("customDir", "a relative directory.")));
        // customDir length is limited to 128 bytes
        CHECK_RETURN_CORE(rdbConfig.customDir.length() <= 128, RDB_DO_NOTHING,
            std::make_tuple(ERR, std::make_shared<ParamError>("customDir length", "less than or equal to 128 bytes.")));
    }

    std::string baseDir = param.baseDir;
    if (!rdbConfig.dataGroupId.empty()) {
        if (!param.isStageMode) {
            return std::make_tuple(ERR, std::make_shared<InnerError>(E_NOT_STAGE_MODE));
        }
        auto stageContext = JSAbility::GetStageModeContext(env, jsValue);
        if (stageContext == nullptr) {
            return std::make_tuple(ERR, std::make_shared<ParamError>("Illegal context."));
        }
        std::string groupDir;
        int errCode = stageContext->GetSystemDatabaseDir(rdbConfig.dataGroupId, groupDir);
        CHECK_RETURN_CORE(errCode == E_OK || !groupDir.empty(), RDB_DO_NOTHING,
            std::make_tuple(ERR, std::make_shared<InnerError>(E_DATA_GROUP_ID_INVALID)));
        baseDir = groupDir;
    }

    auto [realPath, errorCode] = RdbSqlUtils::GetDefaultDatabasePath(baseDir, rdbConfig.name, rdbConfig.customDir);
    // realPath length is limited to 1024 bytes
    CHECK_RETURN_CORE(errorCode == E_OK && realPath.length() <= 1024, RDB_DO_NOTHING,
        std::make_tuple(ERR, std::make_shared<ParamError>("database path", "a valid path.")));
    rdbConfig.path = realPath;
    return std::make_tuple(E_OK, nullptr);
}

RdbStoreConfig GetRdbStoreConfig(const RdbConfig &rdbConfig, const ContextParam &param)
{
    RdbStoreConfig rdbStoreConfig(rdbConfig.path);
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
}; // namespace JSUtils
} // namespace OHOS::AppDataMgrJsKit