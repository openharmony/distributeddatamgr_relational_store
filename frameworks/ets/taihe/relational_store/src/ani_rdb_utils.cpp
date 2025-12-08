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
#define LOG_TAG "AniRdbUtils"
#include "ani_rdb_utils.h"

#include <string>

#include "ani_ability_utils.h"
#include "ani_base_context.h"
#include "ani_utils.h"
#include "js_ability.h"
#include "js_utils.h"
#include "logger.h"
#include "napi_rdb_error.h"
#include "rdb_helper.h"
#include "rdb_sql_utils.h"
#include "rdb_store_config.h"

namespace ani_rdbutils {
using namespace taihe;
using namespace OHOS::Rdb;
using TaiheAssetStatus = ::ohos::data::relationalStore::AssetStatus;
using TaiheValueType = ::ohos::data::relationalStore::ValueType;

#ifndef PATH_SPLIT
#define PATH_SPLIT '/'
#endif
static constexpr int ERR = -1;
static const int E_OK = 0;
static const int REALPATH_MAX_LEN = 1024;
static const int INIT_POSITION = -1;
#define API_VERSION_MOD 100

OHOS::NativeRdb::AssetValue AssetToNative(::ohos::data::relationalStore::Asset const &asset)
{
    OHOS::NativeRdb::AssetValue value;
    value.name = std::string(asset.name);
    value.uri = std::string(asset.uri);
    value.createTime = std::string(asset.createTime);
    value.modifyTime = std::string(asset.modifyTime);
    value.size = std::string(asset.size);
    value.path = std::string(asset.path);
    if (asset.status.has_value()) {
        value.status = (OHOS::NativeRdb::AssetValue::Status)((int32_t)(asset.status.value()));
    }
    return value;
}

std::vector<OHOS::NativeRdb::AssetValue> AssetsToNative(
    ::taihe::array<::ohos::data::relationalStore::Asset> const &assets)
{
    std::vector<OHOS::NativeRdb::AssetValue> result;
    result.reserve(assets.size());
    std::transform(assets.begin(), assets.end(), std::back_inserter(result),
        [](const ::ohos::data::relationalStore::Asset &asset) { return AssetToNative(asset); });
    return result;
}

::ohos::data::relationalStore::Asset AssetToAni(OHOS::NativeRdb::AssetValue const &value)
{
    ::ohos::data::relationalStore::Asset asset = {};
    asset.name = value.name;
    asset.uri = value.uri;
    asset.createTime = value.createTime;
    asset.modifyTime = value.modifyTime;
    asset.size = value.size;
    asset.path = value.path;
    TaiheAssetStatus aniStatus((TaiheAssetStatus::key_t)(value.status));
    asset.status = ::taihe::optional<TaiheAssetStatus>::make(aniStatus);
    return asset;
}

std::vector<::ohos::data::relationalStore::Asset> AssetsToAni(OHOS::NativeRdb::ValueObject::Assets const &valueObj)
{
    std::vector<::ohos::data::relationalStore::Asset> aniAssets;
    for (const auto &val : valueObj) {
        aniAssets.emplace_back(AssetToAni(val));
    }
    return aniAssets;
}

std::vector<::ohos::data::relationalStore::Asset> AssetsToAni(OHOS::NativeRdb::ValueObject const &valueObj)
{
    auto nativeAssets = (OHOS::NativeRdb::ValueObject::Assets)valueObj;
    return AssetsToAni(nativeAssets);
}

OHOS::NativeRdb::ReturningConfig ReturningConfigToNative(::ohos::data::relationalStore::ReturningConfig returningConfig)
{
    OHOS::NativeRdb::ReturningConfig config;
    config.columns = std::vector<std::string>(returningConfig.columns.begin(), returningConfig.columns.end());
    if (returningConfig.maxReturningCount.has_value()) {
        config.maxReturningCount = returningConfig.maxReturningCount.value();
    }
    config.defaultRowIndex = OHOS::NativeRdb::ReturningConfig::DEFAULT_ROW_INDEX;
    return config;
}

OHOS::NativeRdb::ValueObject ValueTypeToNative(::ohos::data::relationalStore::ValueType const &value)
{
    OHOS::NativeRdb::ValueObject valueObj;
    auto tag = value.get_tag();
    switch (tag) {
        case TaiheValueType::tag_t::INT64: {
            valueObj.value = value.get_INT64_ref();
            break;
        }
        case TaiheValueType::tag_t::F64: {
            valueObj.value = value.get_F64_ref();
            break;
        }
        case TaiheValueType::tag_t::STRING: {
            valueObj.value = std::string(value.get_STRING_ref());
            break;
        }
        case TaiheValueType::tag_t::BOOL: {
            valueObj.value = value.get_BOOL_ref();
            break;
        }
        case TaiheValueType::tag_t::Uint8Array: {
            ::taihe::array<uint8_t> const &tmp = value.get_Uint8Array_ref();
            valueObj.value = std::vector<uint8_t>(tmp.data(), tmp.data() + tmp.size());
            break;
        }
        case TaiheValueType::tag_t::ASSET: {
            valueObj.value = AssetToNative(value.get_ASSET_ref());
            break;
        }
        case TaiheValueType::tag_t::ASSETS: {
            valueObj.value = AssetsToNative(value.get_ASSETS_ref());
            break;
        }
        case TaiheValueType::tag_t::Float32Array: {
            ::taihe::array<float> const &tmp = value.get_Float32Array_ref();
            valueObj.value = std::vector<float>(tmp.begin(), tmp.end());
            break;
        }
        case TaiheValueType::tag_t::bigint: {
            ::taihe::array<uint64_t> const &tmp = value.get_bigint_ref();
            valueObj.value = OHOS::NativeRdb::BigInteger(false, std::vector<uint64_t>(tmp.begin(), tmp.end()));
            break;
        }
        default:
            break;
    }
    return valueObj;
}

::ohos::data::relationalStore::ValueType ValueObjectToAni(OHOS::NativeRdb::ValueObject const &valueObj)
{
    ::ohos::data::relationalStore::ValueType value = ::ohos::data::relationalStore::ValueType::make_EMPTY();
    switch (valueObj.GetType()) {
        case OHOS::NativeRdb::ValueObject::TypeId::TYPE_INT: {
            value = ::ohos::data::relationalStore::ValueType::make_INT64((int64_t)valueObj);
            break;
        }
        case OHOS::NativeRdb::ValueObject::TypeId::TYPE_DOUBLE: {
            value = ::ohos::data::relationalStore::ValueType::make_F64((double)valueObj);
            break;
        }
        case OHOS::NativeRdb::ValueObject::TypeId::TYPE_STRING: {
            value = ::ohos::data::relationalStore::ValueType::make_STRING((std::string)valueObj);
            break;
        }
        case OHOS::NativeRdb::ValueObject::TypeId::TYPE_BOOL: {
            value = ::ohos::data::relationalStore::ValueType::make_BOOL((bool)valueObj);
            break;
        }
        case OHOS::NativeRdb::ValueObject::TypeId::TYPE_BLOB: {
            auto temp = (OHOS::NativeRdb::ValueObject::Blob)valueObj;
            value = ::ohos::data::relationalStore::ValueType::make_Uint8Array(temp);
            break;
        }
        case OHOS::NativeRdb::ValueObject::TypeId::TYPE_ASSET: {
            auto temp = (OHOS::NativeRdb::ValueObject::Asset)valueObj;
            value = ::ohos::data::relationalStore::ValueType::make_ASSET(AssetToAni(temp));
            break;
        }
        case OHOS::NativeRdb::ValueObject::TypeId::TYPE_ASSETS: {
            auto temp = AssetsToAni(valueObj);
            value = ::ohos::data::relationalStore::ValueType::make_ASSETS(temp);
            break;
        }
        case OHOS::NativeRdb::ValueObject::TypeId::TYPE_VECS: {
            auto temp = (OHOS::NativeRdb::ValueObject::FloatVector)valueObj;
            value = ::ohos::data::relationalStore::ValueType::make_Float32Array(temp);
            break;
        }
        case OHOS::NativeRdb::ValueObject::TypeId::TYPE_BIGINT: {
            auto temp = ((OHOS::NativeRdb::ValueObject::BigInt)valueObj).Value();
            value = ::ohos::data::relationalStore::ValueType::make_bigint(temp);
            break;
        }
        default:
            break;
    }
    return value;
}

OHOS::NativeRdb::ValuesBucket MapValuesToNative(
    taihe::map_view<taihe::string, ::ohos::data::relationalStore::ValueType> const &values)
{
    std::map<std::string, OHOS::NativeRdb::ValueObject> valueMap;
    for (const auto &[key, value] : values) {
        valueMap.emplace(std::string(key), ValueTypeToNative(value));
    }
    return OHOS::NativeRdb::ValuesBucket(std::move(valueMap));
}

std::vector<OHOS::NativeRdb::ValueObject> ArrayValuesToNative(
    taihe::array_view<::ohos::data::relationalStore::ValueType> const &values)
{
    std::vector<OHOS::NativeRdb::ValueObject> nativeValues;
    for (const auto &val : values) {
        nativeValues.emplace_back(ValueTypeToNative(val));
    }
    return nativeValues;
}

OHOS::NativeRdb::ValuesBuckets BucketValuesToNative(
    taihe::array_view<taihe::map<taihe::string, ::ohos::data::relationalStore::ValueType>> const &values)
{
    OHOS::NativeRdb::ValuesBuckets buckets;
    for (const auto &val : values) {
        buckets.Put(MapValuesToNative(val));
    }
    return buckets;
}

OHOS::NativeRdb::ValuesBuckets ValueBucketsToNative(
    taihe::array_view<::ohos::data::relationalStore::ValuesBucket> const &values)
{
    OHOS::NativeRdb::ValuesBuckets buckets;
    for (const auto &val : values) {
        auto bucket = ValueBucketToNative(val);
        if (bucket.IsEmpty()) {
            return {};
        }
        buckets.Put(std::move(bucket));
    }
    return buckets;
}

OHOS::NativeRdb::ValuesBucket ValueBucketToNative(::ohos::data::relationalStore::ValuesBucket const &value)
{
    std::map<std::string, OHOS::NativeRdb::ValueObject> valueMap;
    auto const &values = value.get_VALUESBUCKET_ref();
    for (const auto &[key, value] : values) {
        valueMap.emplace(std::string(key), ValueTypeToNative(value));
    }
    return OHOS::NativeRdb::ValuesBucket(std::move(valueMap));
}

OHOS::NativeRdb::RdbStoreConfig::CryptoParam CryptoParamToNative(
    ::ohos::data::relationalStore::CryptoParam const &param)
{
    OHOS::NativeRdb::RdbStoreConfig::CryptoParam value;
    value.encryptKey_ = std::vector<uint8_t>(param.encryptionKey.begin(), param.encryptionKey.end());
    if (param.iterationCount.has_value()) {
        value.iterNum = param.iterationCount.value();
    }
    if (param.encryptionAlgo.has_value()) {
        value.encryptAlgo = (int32_t)param.encryptionAlgo.value();
    }
    if (param.hmacAlgo.has_value()) {
        value.hmacAlgo = (int32_t)param.hmacAlgo.value();
    }
    if (param.kdfAlgo.has_value()) {
        value.kdfAlgo = (int32_t)param.kdfAlgo.value();
    }
    if (param.cryptoPageSize.has_value()) {
        value.cryptoPageSize = param.cryptoPageSize.value();
    }
    return value;
}

OHOS::AppDataMgrJsKit::JSUtils::RdbConfig AniGetRdbConfig(const ::ohos::data::relationalStore::StoreConfig &storeConfig)
{
    OHOS::AppDataMgrJsKit::JSUtils::RdbConfig rdbConfig;
    if (storeConfig.encrypt.has_value()) {
        rdbConfig.isEncrypt = storeConfig.encrypt.value();
    }
    int32_t securityLevel = (int32_t)storeConfig.securityLevel;
    if (securityLevel == (int32_t)OHOS::NativeRdb::SecurityLevel::S1 ||
        securityLevel == (int32_t)OHOS::NativeRdb::SecurityLevel::S2 ||
        securityLevel == (int32_t)OHOS::NativeRdb::SecurityLevel::S3 ||
        securityLevel == (int32_t)OHOS::NativeRdb::SecurityLevel::S4) {
        rdbConfig.securityLevel = (OHOS::NativeRdb::SecurityLevel)securityLevel;
    }
    if (storeConfig.dataGroupId.has_value()) {
        rdbConfig.dataGroupId = std::string(storeConfig.dataGroupId.value());
    }
    if (storeConfig.autoCleanDirtyData.has_value()) {
        rdbConfig.isAutoClean = storeConfig.autoCleanDirtyData.value();
    }
    rdbConfig.name = std::string(storeConfig.name);

    if (storeConfig.customDir.has_value()) {
        rdbConfig.customDir = std::string(storeConfig.customDir.value());
    }
    if (storeConfig.vector.has_value()) {
        rdbConfig.vector = storeConfig.vector.value();
    }
    if (storeConfig.allowRebuild.has_value()) {
        rdbConfig.allowRebuild = storeConfig.allowRebuild.value();
    }
    if (storeConfig.isReadOnly.has_value()) {
        rdbConfig.isReadOnly = storeConfig.isReadOnly.value();
    }
    if (storeConfig.pluginLibs.has_value()) {
        ::taihe::array<::taihe::string> libs = storeConfig.pluginLibs.value();
        rdbConfig.pluginLibs = std::vector<std::string>(libs.begin(), libs.end());
    }
    if (storeConfig.cryptoParam.has_value()) {
        ::ohos::data::relationalStore::CryptoParam param = storeConfig.cryptoParam.value();
        rdbConfig.cryptoParam = CryptoParamToNative(param);
    }
    return rdbConfig;
}

std::tuple<int32_t, std::shared_ptr<OHOS::RelationalStoreJsKit::Error>> AniGetRdbRealPath(ani_env *env,
    ani_object aniValue, OHOS::AppDataMgrJsKit::JSUtils::RdbConfig &rdbConfig,
    OHOS::AppDataMgrJsKit::JSUtils::ContextParam &param)
{
    using namespace OHOS::AppDataMgrJsKit::JSUtils;
    using namespace OHOS::RelationalStoreJsKit;
    using namespace OHOS::NativeRdb;
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
        auto abilityContext = OHOS::AbilityRuntime::GetStageModeContext(env, aniValue);
        auto stageContext = std::make_shared<OHOS::AppDataMgrJsKit::Context>(abilityContext);
        if (stageContext == nullptr) {
            return std::make_tuple(ERR, std::make_shared<ParamError>("Illegal context."));
        }
        std::string groupDir;
        int errCode = stageContext->GetSystemDatabaseDir(rdbConfig.dataGroupId, groupDir);
        CHECK_RETURN_CORE(errCode == E_OK && !groupDir.empty(), RDB_DO_NOTHING,
            std::make_tuple(ERR, std::make_shared<InnerError>(E_DATA_GROUP_ID_INVALID)));
        baseDir = groupDir;
    }

    if (!rdbConfig.rootDir.empty()) {
        // determine if the first character of rootDir is '/'
        CHECK_RETURN_CORE(rdbConfig.rootDir.find_first_of(PATH_SPLIT) == 0, RDB_DO_NOTHING,
            std::make_tuple(ERR, std::make_shared<PathError>()));
        auto [realPath, errorCode] =
            RdbSqlUtils::GetCustomDatabasePath(rdbConfig.rootDir, rdbConfig.name, rdbConfig.customDir);
        CHECK_RETURN_CORE(errorCode == E_OK, RDB_DO_NOTHING, std::make_tuple(ERR, std::make_shared<PathError>()));
        rdbConfig.path = realPath;
        return std::make_tuple(E_OK, nullptr);
    }

    auto [realPath, errorCode] = RdbSqlUtils::GetDefaultDatabasePath(baseDir, rdbConfig.name, rdbConfig.customDir);
    CHECK_RETURN_CORE(errorCode == E_OK && realPath.length() <= REALPATH_MAX_LEN, RDB_DO_NOTHING,
        std::make_tuple(ERR, std::make_shared<ParamError>("database path", "a valid path.")));
    rdbConfig.path = realPath;
    return std::make_tuple(E_OK, nullptr);
}

void InitRdbStoreConfig(OHOS::NativeRdb::RdbStoreConfig &nativeStoreConfig,
    OHOS::AppDataMgrJsKit::JSUtils::RdbConfig const &rdbConfig,
    OHOS::AppDataMgrJsKit::JSUtils::ContextParam const &contextParam)
{
    using namespace OHOS::NativeRdb;
    nativeStoreConfig.SetEncryptStatus(rdbConfig.isEncrypt);
    nativeStoreConfig.SetSearchable(rdbConfig.isSearchable);
    nativeStoreConfig.SetIsVector(rdbConfig.vector);
    nativeStoreConfig.SetDBType(rdbConfig.vector ? DB_VECTOR : DB_SQLITE);
    nativeStoreConfig.SetStorageMode(rdbConfig.persist ? StorageMode::MODE_DISK : StorageMode::MODE_MEMORY);
    nativeStoreConfig.SetAutoClean(rdbConfig.isAutoClean);
    nativeStoreConfig.SetSecurityLevel(rdbConfig.securityLevel);
    nativeStoreConfig.SetDataGroupId(rdbConfig.dataGroupId);
    nativeStoreConfig.SetName(rdbConfig.name);
    nativeStoreConfig.SetCustomDir(rdbConfig.customDir);
    nativeStoreConfig.SetAllowRebuild(rdbConfig.allowRebuild);
    nativeStoreConfig.SetReadOnly(rdbConfig.isReadOnly);
    nativeStoreConfig.SetIntegrityCheck(IntegrityCheck::NONE);
    nativeStoreConfig.SetTokenizer(rdbConfig.tokenizer);

    if (!contextParam.bundleName.empty()) {
        nativeStoreConfig.SetBundleName(contextParam.bundleName);
    }
    nativeStoreConfig.SetModuleName(contextParam.moduleName);
    nativeStoreConfig.SetArea(contextParam.area);
    nativeStoreConfig.SetPluginLibs(rdbConfig.pluginLibs);
    nativeStoreConfig.SetHaMode(rdbConfig.haMode);

    nativeStoreConfig.SetCryptoParam(rdbConfig.cryptoParam);
}

std::pair<bool, OHOS::NativeRdb::RdbStoreConfig> AniGetRdbStoreConfig(
    ani_env *env, ani_object aniContext, OHOS::AppDataMgrJsKit::JSUtils::RdbConfig &rdbConfig)
{
    using namespace OHOS::RelationalStoreJsKit;
    using namespace OHOS::NativeRdb;

    OHOS::NativeRdb::RdbStoreConfig empty("");
    if (!rdbConfig.cryptoParam.IsValid()) {
        taihe::set_business_error(E_PARAM_ERROR, "Illegal CryptoParam.");
        return std::make_pair(false, empty);
    }
    if (rdbConfig.tokenizer < NONE_TOKENIZER || rdbConfig.tokenizer >= TOKENIZER_END) {
        taihe::set_business_error(E_PARAM_ERROR, "Illegal tokenizer.");
        return std::make_pair(false, empty);
    }
    if (!RdbHelper::IsSupportedTokenizer(rdbConfig.tokenizer)) {
        const std::optional<JsErrorCode> err = OHOS::RelationalStoreJsKit::GetJsErrorCode(E_NOT_SUPPORT);
        if (err.has_value()) {
            taihe::set_business_error(E_NOT_SUPPORT, err.value().message);
        }
        return std::make_pair(false, empty);
    }
    if (!rdbConfig.persist && !rdbConfig.rootDir.empty()) {
        const std::optional<JsErrorCode> err = OHOS::RelationalStoreJsKit::GetJsErrorCode(E_NOT_SUPPORT);
        if (err.has_value()) {
            taihe::set_business_error(E_NOT_SUPPORT, err.value().message);
        }
        return std::make_pair(false, empty);
    }
    OHOS::AppDataMgrJsKit::JSUtils::ContextParam contextParam;
    int32_t ret = ani_abilityutils::AniGetContext(aniContext, contextParam);
    if (ret != ANI_OK) {
        return std::make_pair(false, empty);
    }
    rdbConfig.isSystemApp = contextParam.isSystemApp;
    auto [code, err] = AniGetRdbRealPath(env, aniContext, rdbConfig, contextParam);
    if (!rdbConfig.rootDir.empty()) {
        rdbConfig.isReadOnly = true;
    }
    if (OK != code && err != nullptr) {
        taihe::set_business_error(err->GetCode(), err->GetMessage());
        return std::make_pair(false, empty);
    }

    OHOS::NativeRdb::RdbStoreConfig nativeStoreConfig(rdbConfig.path);
    InitRdbStoreConfig(nativeStoreConfig, rdbConfig, contextParam);
    return std::make_pair(true, nativeStoreConfig);
};

bool HasDuplicateAssets(const OHOS::NativeRdb::ValueObject &value)
{
    auto *assets = std::get_if<OHOS::NativeRdb::ValueObject::Assets>(&value.value);
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

bool HasDuplicateAssets(const std::vector<OHOS::NativeRdb::ValueObject> &values)
{
    for (auto &val : values) {
        if (HasDuplicateAssets(val)) {
            return true;
        }
    }
    return false;
}

bool HasDuplicateAssets(const OHOS::NativeRdb::ValuesBucket &value)
{
    for (auto &[key, val] : value.values_) {
        if (HasDuplicateAssets(val)) {
            return true;
        }
    }
    return false;
}

bool HasDuplicateAssets(const std::vector<OHOS::NativeRdb::ValuesBucket> &values)
{
    for (auto &valueBucket : values) {
        if (HasDuplicateAssets(valueBucket)) {
            return true;
        }
    }
    return false;
}

bool HasDuplicateAssets(const OHOS::NativeRdb::ValuesBuckets &values)
{
    const auto &[fields, vals] = values.GetFieldsAndValues();
    for (const auto &valueObject : *vals) {
        if (HasDuplicateAssets(valueObject)) {
            return true;
        }
    }
    return false;
}

std::pair<int, std::vector<RowEntity>> GetRows(ResultSet &resultSet, int32_t maxCount, int32_t position)
{
    int rowPos = 0;
    resultSet.GetRowIndex(rowPos);
    int errCode = E_OK;
    if (position != INIT_POSITION && position != rowPos) {
        errCode = resultSet.GoToRow(position);
    } else if (rowPos == INIT_POSITION) {
        errCode = resultSet.GoToFirstRow();
        if (errCode == OHOS::NativeRdb::E_ROW_OUT_RANGE) {
            return {E_OK, std::vector<RowEntity>()};
        }
    }
    if (errCode != E_OK) {
        LOG_ERROR("Failed code:%{public}d. [%{public}d, %{public}d]", errCode, maxCount, position);
        return {errCode, std::vector<RowEntity>()};
    }
    std::vector<RowEntity> rowEntities;
    for (int32_t i = 0; i < maxCount; ++i) {
        RowEntity rowEntity;
        int errCode = resultSet.GetRow(rowEntity);
        if (errCode == E_ROW_OUT_RANGE) {
            break;
        }
        if (errCode != E_OK) {
            return {errCode, std::vector<RowEntity>()};
        }
        rowEntities.push_back(rowEntity);
        errCode = resultSet.GoToNextRow();
        if (errCode == E_ROW_OUT_RANGE) {
            break;
        }
        if (errCode != E_OK) {
            return {errCode, std::vector<RowEntity>()};
        }
    }
    return {E_OK, rowEntities};
}

} //namespace ani_rdbutils