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
#include "rdb_sql_statistic.h"
#include "rdb_sql_utils.h"
#include "rdb_types.h"
#include "result_set.h"
#include "transaction.h"

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
    auto outputStatus = value.status & ~0xF0000000;
    std::vector<napi_property_descriptor> descriptors = {
        DECLARE_JS_PROPERTY(env, "name", value.name),
        DECLARE_JS_PROPERTY(env, "uri", value.uri),
        DECLARE_JS_PROPERTY(env, "createTime", value.createTime),
        DECLARE_JS_PROPERTY(env, "modifyTime", value.modifyTime),
        DECLARE_JS_PROPERTY(env, "size", value.size),
        DECLARE_JS_PROPERTY(env, "path", value.path),
        DECLARE_JS_PROPERTY(env, "status", outputStatus),
    };

    napi_value object = nullptr;
    NAPI_CALL_RETURN_ERR(
        napi_create_object_with_properties(env, &object, descriptors.size(), descriptors.data()), object);
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
napi_value Convert2JSValue(napi_env env, const ValueObject &value)
{
    return Convert2JSValue(env, value.value);
}

template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::Statistic &value)
{
    std::vector<napi_property_descriptor> descriptors = {
        DECLARE_JS_PROPERTY(env, "total", value.total),
        DECLARE_JS_PROPERTY(env, "success", value.success),
        DECLARE_JS_PROPERTY(env, "successful", value.success),
        DECLARE_JS_PROPERTY(env, "failed", value.failed),
        DECLARE_JS_PROPERTY(env, "remained", value.untreated),
    };

    napi_value object = nullptr;
    NAPI_CALL_RETURN_ERR(
        napi_create_object_with_properties(env, &object, descriptors.size(), descriptors.data()), object);
    return object;
}

template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::TableDetail &value)
{
    std::vector<napi_property_descriptor> descriptors = {
        DECLARE_JS_PROPERTY(env, "upload", value.upload),
        DECLARE_JS_PROPERTY(env, "download", value.download),
    };

    napi_value object = nullptr;
    NAPI_CALL_RETURN_ERR(
        napi_create_object_with_properties(env, &object, descriptors.size(), descriptors.data()), object);
    return object;
}

template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::ProgressDetail &value)
{
    std::vector<napi_property_descriptor> descriptors = {
        DECLARE_JS_PROPERTY(env, "schedule", value.progress),
        DECLARE_JS_PROPERTY(env, "code", value.code),
        DECLARE_JS_PROPERTY(env, "details", value.details),
    };

    napi_value object = nullptr;
    NAPI_CALL_RETURN_ERR(
        napi_create_object_with_properties(env, &object, descriptors.size(), descriptors.data()), object);
    return object;
}

template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::SqlObserver::SqlExecutionInfo &value)
{
    std::vector<napi_property_descriptor> descriptors = {
        DECLARE_JS_PROPERTY(env, "sql", value.sql_),
        DECLARE_JS_PROPERTY(env, "totalTime", value.totalTime_),
        DECLARE_JS_PROPERTY(env, "waitTime", value.waitTime_),
        DECLARE_JS_PROPERTY(env, "prepareTime", value.prepareTime_),
        DECLARE_JS_PROPERTY(env, "executeTime", value.executeTime_),
    };

    napi_value object = nullptr;
    NAPI_CALL_RETURN_ERR(
        napi_create_object_with_properties(env, &object, descriptors.size(), descriptors.data()), object);
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
    std::vector<napi_property_descriptor> descriptors = {
        DECLARE_JS_PROPERTY(env, "table", value.table),
        DECLARE_JS_PROPERTY(env, "type", value.type),
        DECLARE_JS_PROPERTY(env, "inserted", value.inserted),
        DECLARE_JS_PROPERTY(env, "updated", value.updated),
        DECLARE_JS_PROPERTY(env, "deleted", value.deleted),
    };

    napi_value object = nullptr;
    NAPI_CALL_RETURN_ERR(
        napi_create_object_with_properties(env, &object, descriptors.size(), descriptors.data()), object);
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
napi_value Convert2JSValue(napi_env env, const BigInt &value)
{
    napi_value val = nullptr;
    napi_status status = napi_create_bigint_words(env, value.Sign(), value.Size(), value.TrueForm(), &val);
    if (status != napi_ok) {
        return nullptr;
    }
    return val;
}

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, BigInt &value)
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
int32_t Convert2Value(napi_env env, napi_value input, CryptoParam &cryptoParam)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, input, &type);
    if (status != napi_ok || type != napi_object) {
        LOG_DEBUG("napi_typeof failed status = %{public}d type = %{public}d", status, type);
        return napi_invalid_arg;
    }

    NAPI_CALL_RETURN_ERR(GetNamedProperty(env, input, "encryptionKey", cryptoParam.encryptKey_), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GetNamedProperty(env, input, "iterationCount", cryptoParam.iterNum, true), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(
        GetNamedProperty(env, input, "encryptionAlgo", cryptoParam.encryptAlgo, true), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GetNamedProperty(env, input, "hmacAlgo", cryptoParam.hmacAlgo, true), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(GetNamedProperty(env, input, "kdfAlgo", cryptoParam.kdfAlgo, true), napi_invalid_arg);
    NAPI_CALL_RETURN_ERR(
        GetNamedProperty(env, input, "cryptoPageSize", cryptoParam.cryptoPageSize, true), napi_invalid_arg);

    return napi_ok;
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

    status = GetNamedProperty(env, jsValue, "rootDir", rdbConfig.rootDir, true);
    ASSERT(OK == status, "get rootDir failed.", napi_invalid_arg);

    GetNamedProperty(env, jsValue, "isSearchable", rdbConfig.isSearchable, true);
    ASSERT(OK == status, "get isSearchable failed.", napi_invalid_arg);

    GetNamedProperty(env, jsValue, "vector", rdbConfig.vector, true);
    ASSERT(OK == status, "get vector failed.", napi_invalid_arg);

    GetNamedProperty(env, jsValue, "allowRebuild", rdbConfig.allowRebuild, true);
    ASSERT(OK == status, "get allowRebuild failed.", napi_invalid_arg);

    GetNamedProperty(env, jsValue, "isReadOnly", rdbConfig.isReadOnly, true);
    ASSERT(OK == status, "get isReadOnly failed.", napi_invalid_arg);

    GetNamedProperty(env, jsValue, "pluginLibs", rdbConfig.pluginLibs, true);
    ASSERT(OK == status, "get pluginLibs failed.", napi_invalid_arg);

    status = GetNamedProperty(env, jsValue, "haMode", rdbConfig.haMode, true);
    ASSERT(OK == status, "get haMode failed.", napi_invalid_arg);

    status = GetNamedProperty(env, jsValue, "cryptoParam", rdbConfig.cryptoParam, true);
    ASSERT(OK == status, "get cryptoParam failed.", napi_invalid_arg);

    int32_t tokenizer = static_cast<int32_t>(Tokenizer::NONE_TOKENIZER);
    status = GetNamedProperty(env, jsValue, "tokenizer", tokenizer, true);
    ASSERT(OK == status, "get tokenizer failed.", napi_invalid_arg);
    ASSERT((tokenizer >= static_cast<int32_t>(Tokenizer::NONE_TOKENIZER) &&
               tokenizer < static_cast<int32_t>(Tokenizer::TOKENIZER_END)),
        "get tokenizer failed", napi_invalid_arg);
    rdbConfig.tokenizer = static_cast<Tokenizer>(tokenizer);
    return napi_ok;
}

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, TransactionOptions &transactionOptions)
{
    int32_t status = GetNamedProperty(env, jsValue, "transactionType", transactionOptions.transactionType, true);
    bool checked = transactionOptions.transactionType >= Transaction::DEFERRED &&
                   transactionOptions.transactionType <= Transaction::EXCLUSIVE;
    ASSERT(OK == status && checked, "get transactionType failed.", napi_invalid_arg);
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
    LOG_DEBUG("Stage mode branch");
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
        int32_t hapVersion = JSAbility::GetHapVersion(env, jsValue);
        JSUtils::SetHapVersion(hapVersion);
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
            std::make_tuple(ERR, std::make_shared<ParamError>("customDir length", "less than or equal to 128 "
                                                                                  "bytes.")));
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

    if (!rdbConfig.rootDir.empty()) {
        // determine if the first character of rootDir is '/'
        CHECK_RETURN_CORE(rdbConfig.rootDir.find_first_of(PATH_SPLIT) == 0, RDB_DO_NOTHING,
            std::make_tuple(ERR, std::make_shared<PathError>()));
        auto [realPath, errorCode] =
            RdbSqlUtils::GetCustomDatabasePath(rdbConfig.rootDir, rdbConfig.name, rdbConfig.customDir);
        CHECK_RETURN_CORE(errorCode == E_OK, RDB_DO_NOTHING,
            std::make_tuple(ERR, std::make_shared<PathError>()));
        rdbConfig.path = realPath;
        return std::make_tuple(E_OK, nullptr);
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
    rdbConfig.vector ? rdbStoreConfig.SetDBType(DB_VECTOR) : rdbStoreConfig.SetDBType(DB_SQLITE);
    rdbStoreConfig.SetAutoClean(rdbConfig.isAutoClean);
    rdbStoreConfig.SetSecurityLevel(rdbConfig.securityLevel);
    rdbStoreConfig.SetDataGroupId(rdbConfig.dataGroupId);
    rdbStoreConfig.SetName(rdbConfig.name);
    rdbStoreConfig.SetCustomDir(rdbConfig.customDir);
    rdbStoreConfig.SetAllowRebuild(rdbConfig.allowRebuild);
    rdbStoreConfig.SetReadOnly(rdbConfig.isReadOnly);
    rdbStoreConfig.SetIntegrityCheck(IntegrityCheck::NONE);
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

bool HasDuplicateAssets(const ValueObject &value)
{
    auto *assets = std::get_if<ValueObject::Assets>(&value.value);
    if (assets == nullptr) {
        return false;
    }
    std::set<std::string> names;
    auto item = assets->begin();
    while (item != assets->end()) {
        if (!names.insert(item->name).second) {
            LOG_ERROR("Duplicate assets! name = %{public}.6s", item->name.c_str());
            return true;
        }
        item++;
    }
    return false;
}

bool HasDuplicateAssets(const std::vector<ValueObject> &values)
{
    for (auto &val : values) {
        if (HasDuplicateAssets(val)) {
            return true;
        }
    }
    return false;
}

bool HasDuplicateAssets(const ValuesBucket &value)
{
    for (auto &[key, val] : value.values_) {
        if (HasDuplicateAssets(val)) {
            return true;
        }
    }
    return false;
}

bool HasDuplicateAssets(const std::vector<ValuesBucket> &values)
{
    for (auto &valueBucket : values) {
        if (HasDuplicateAssets(valueBucket)) {
            return true;
        }
    }
    return false;
}

bool HasDuplicateAssets(const ValuesBuckets &values)
{
    const auto &[fields, vals] = values.GetFieldsAndValues();
    for (const auto &valueObject : *vals) {
        if (HasDuplicateAssets(valueObject)) {
            return true;
        }
    }
    return false;
}
}; // namespace JSUtils
} // namespace OHOS::AppDataMgrJsKit