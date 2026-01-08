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
#include "rdb_predicates_impl.h"
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

ohos::data::relationalStore::ValuesBucket ValuesBucketToAni(OHOS::NativeRdb::ValuesBucket const &valuesBucket)
{
    auto result = ohos::data::relationalStore::ValuesBucket::make_VALUESBUCKET();
    auto &aniMap = result.get_VALUESBUCKET_ref();
    auto nativeMap = valuesBucket.GetAll();
    for (const auto &[key, value] : nativeMap) {
        aniMap.emplace(taihe::string(key), ValueObjectToAni(value));
    }
    return result;
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

void AniGetRdbConfigAppend(const ohos::data::relationalStore::StoreConfig &storeConfig,
    OHOS::AppDataMgrJsKit::JSUtils::RdbConfig &storeConfigNative)
{
    if (storeConfig.rootDir.has_value()) {
        storeConfigNative.rootDir = std::string(storeConfig.rootDir.value());
    }
    if (storeConfig.isSearchable.has_value()) {
        storeConfigNative.isSearchable = storeConfig.isSearchable.value();
    }
    if (storeConfig.persist.has_value()) {
        storeConfigNative.persist = storeConfig.persist.value();
    }
    if (storeConfig.tokenizer.has_value()) {
        storeConfigNative.tokenizer = TokenizerToNative(storeConfig.tokenizer.value());
    }
    if (storeConfig.enableSemanticIndex.has_value()) {
        storeConfigNative.enableSemanticIndex = storeConfig.enableSemanticIndex.value();
    }
}

OHOS::AppDataMgrJsKit::JSUtils::RdbConfig AniGetRdbConfig(const ohos::data::relationalStore::StoreConfig &storeConfig)
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
    AniGetRdbConfigAppend(storeConfig, rdbConfig);
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

OHOS::DistributedRdb::SubscribeMode SubscribeTypeToMode(ohos::data::relationalStore::SubscribeType type)
{
    switch (type.get_key()) {
        case ohos::data::relationalStore::SubscribeType::key_t::SUBSCRIBE_TYPE_REMOTE:
            return OHOS::DistributedRdb::SubscribeMode::REMOTE;
        case ohos::data::relationalStore::SubscribeType::key_t::SUBSCRIBE_TYPE_CLOUD:
            return OHOS::DistributedRdb::SubscribeMode::CLOUD;
        case ohos::data::relationalStore::SubscribeType::key_t::SUBSCRIBE_TYPE_CLOUD_DETAILS:
            return OHOS::DistributedRdb::SubscribeMode::CLOUD_DETAIL;
        default:
            return OHOS::DistributedRdb::SubscribeMode::LOCAL_DETAIL;
    }
}

OHOS::DistributedRdb::DistributedConfig DistributedConfigToNative(
    const ohos::data::relationalStore::DistributedConfig &config)
{
    OHOS::DistributedRdb::DistributedConfig nativeConfig;
    nativeConfig.autoSync = config.autoSync;
    if (config.references.has_value()) {
        auto values = config.references.value();
        std::vector<OHOS::DistributedRdb::Reference> nativeReferences;
        for (const auto &value : values) {
            nativeReferences.push_back(ReferenceToNative(value));
        }
        nativeConfig.references = std::move(nativeReferences);
    }
    if (config.asyncDownloadAsset.has_value()) {
        nativeConfig.asyncDownloadAsset = config.asyncDownloadAsset.value();
    }
    if (config.enableCloud.has_value()) {
        nativeConfig.enableCloud = config.enableCloud.value();
    }
    return nativeConfig;
}

OHOS::DistributedRdb::Reference ReferenceToNative(const ohos::data::relationalStore::Reference &reference)
{
    OHOS::DistributedRdb::Reference nativeReference;
    nativeReference.sourceTable = reference.sourceTable;
    nativeReference.targetTable = reference.targetTable;
    for (const auto &[key, value] : reference.refFields) {
        nativeReference.refFields[std::string(key)] = std::string(value);
    }
    return nativeReference;
}

ohos::data::relationalStore::ProgressDetails ProgressDetailToTaihe(
    const OHOS::DistributedRdb::ProgressDetail &OrgDetails)
{
    taihe::map<taihe::string, ohos::data::relationalStore::TableDetails> mapTableDetail;
    for (const auto &[key, value] : OrgDetails.details) {
        mapTableDetail.emplace(taihe::string(key), ohos::data::relationalStore::TableDetails {
            StatisticToTaihe(value.upload),
            StatisticToTaihe(value.download)
        });
    }
    return ohos::data::relationalStore::ProgressDetails {
        ohos::data::relationalStore::Progress::from_value(OrgDetails.progress),
        ohos::data::relationalStore::ProgressCode::from_value(OrgDetails.code),
        mapTableDetail
    };
}

OHOS::DistributedRdb::RdbStoreObserver::PrimaryKey PRIKeyToNative(
    const ohos::data::relationalStore::PRIKeyType &priKey)
{
    switch (priKey.get_tag()) {
        case ohos::data::relationalStore::PRIKeyType::tag_t::STRING:
            return std::string(priKey.get_STRING_ref());
        case ohos::data::relationalStore::PRIKeyType::tag_t::INT64:
            return priKey.get_INT64_ref();
        case ohos::data::relationalStore::PRIKeyType::tag_t::F64:
            return priKey.get_F64_ref();
        default:
            LOG_ERROR("Invalid PRIKeyType tag");
            return std::monostate{};
    }
}

ohos::data::relationalStore::PRIKeyType ToNativePRIKeyType(
    const OHOS::DistributedRdb::RdbStoreObserver::PrimaryKey &priKey)
{
    if (std::holds_alternative<std::string>(priKey)) {
        return ::ohos::data::relationalStore::PRIKeyType::make_STRING(std::get<std::string>(priKey));
    } else if (std::holds_alternative<int64_t>(priKey)) {
        return ::ohos::data::relationalStore::PRIKeyType::make_INT64(std::get<int64_t>(priKey));
    } else if (std::holds_alternative<double>(priKey)) {
        return ::ohos::data::relationalStore::PRIKeyType::make_F64(std::get<double>(priKey));
    } else  {
        return ::ohos::data::relationalStore::PRIKeyType::make_STRING("");
    }
}

ohos::data::relationalStore::ModifyTime ToAniModifyTime(
    const std::map<OHOS::NativeRdb::RdbStore::PRIKey, OHOS::NativeRdb::RdbStore::Date> &mapResult)
{
    taihe::map<::ohos::data::relationalStore::PRIKeyType, uintptr_t> modifyTime;
    for (const auto &[key, value] : mapResult) {
        ani_object aniDate{};
        ohos::data::relationalStore::PRIKeyType nativeKey = ToNativePRIKeyType(key);
        ani_rdbutils::WarpDate(static_cast<double>(value), aniDate);
        modifyTime.emplace(nativeKey, reinterpret_cast<uintptr_t>(aniDate));
    }
    return ohos::data::relationalStore::ModifyTime::make_MODIFYTIME(modifyTime);
}

ohos::data::relationalStore::Origin OriginToTaihe(const OHOS::DistributedRdb::Origin &origin)
{
    switch (origin.origin) {
        case OHOS::DistributedRdb::Origin::ORIGIN_LOCAL:  //  means LOCAL
            return ohos::data::relationalStore::Origin::key_t::LOCAL;
        case OHOS::DistributedRdb::Origin::ORIGIN_CLOUD:  //  means cloud
            return ohos::data::relationalStore::Origin::key_t::CLOUD;
        case OHOS::DistributedRdb::Origin::ORIGIN_NEARBY:  //  means remote
            return ohos::data::relationalStore::Origin::key_t::REMOTE;
        default:
            LOG_ERROR("Invalid origin value.");
            return ohos::data::relationalStore::Origin::key_t::LOCAL;
    }
}

ohos::data::relationalStore::ChangeType ToAniChangeType(const OHOS::DistributedRdb::Origin &origin)
{
    switch (origin.dataType) {
        case OHOS::DistributedRdb::Origin::BASIC_DATA:
            return ohos::data::relationalStore::ChangeType::key_t::DATA_CHANGE;
        case OHOS::DistributedRdb::Origin::ASSET_DATA:
            return ohos::data::relationalStore::ChangeType::key_t::ASSET_CHANGE;
        default:
            LOG_ERROR("Invalid origin value.");
            return ohos::data::relationalStore::ChangeType::key_t::DATA_CHANGE;
    }
}

ohos::data::relationalStore::StringOrNumberArray VectorToAniArrayType(
    const std::vector<OHOS::DistributedRdb::RdbStoreObserver::PrimaryKey> &array)
{
    std::vector<int64_t> int64Array;
    std::vector<taihe::string> strArray;
    for (auto &tempPrimaryKey : array) {
        if (std::holds_alternative<std::string>(tempPrimaryKey)) {
            strArray.emplace_back(std::get<std::string>(tempPrimaryKey));
        } else if (std::holds_alternative<int64_t>(tempPrimaryKey)) {
            int64Array.emplace_back(std::get<int64_t>(tempPrimaryKey));
        } else if (std::holds_alternative<double>(tempPrimaryKey)) {
            int64Array.emplace_back(std::get<double>(tempPrimaryKey));
        }
    }
    if (int64Array.size() > 0) {
        return ohos::data::relationalStore::StringOrNumberArray::make_Int64Array(taihe::array<int64_t>(int64Array));
    } else {
        return ohos::data::relationalStore::StringOrNumberArray::make_STRINGARRAY(
            taihe::array<taihe::string>(strArray));
    }
}

taihe::array<ohos::data::relationalStore::ChangeInfo> RdbChangeInfoToTaihe(
    const OHOS::DistributedRdb::Origin &origin,
    const OHOS::DistributedRdb::RdbStoreObserver::ChangeInfo &changeInfo)
{
    std::vector<ohos::data::relationalStore::ChangeInfo> arrChangeInfo;
    
    ohos::data::relationalStore::ChangeType mapType = ToAniChangeType(origin);
    for (auto it = changeInfo.begin(); it != changeInfo.end(); ++it) {
        ohos::data::relationalStore::ChangeInfo info {
            std::string(it->first), mapType,
            VectorToAniArrayType(it->
                second[OHOS::DistributedRdb::RdbStoreObserver::ChangeType::CHG_TYPE_INSERT]),
            VectorToAniArrayType(it->
                second[OHOS::DistributedRdb::RdbStoreObserver::ChangeType::CHG_TYPE_UPDATE]),
            VectorToAniArrayType(it->
                second[OHOS::DistributedRdb::RdbStoreObserver::ChangeType::CHG_TYPE_DELETE])
        };
        arrChangeInfo.emplace_back(std::move(info));
    }
    return taihe::array<ohos::data::relationalStore::ChangeInfo>(arrChangeInfo);
}

taihe::array_view<taihe::string> VectorToTaiheArray(const std::vector<std::string> &vec)
{
    std::vector<taihe::string> strArray;
    for (auto &tempStr : vec) {
        strArray.emplace_back(tempStr);
    }
    return taihe::array_view<taihe::string>(strArray);
}

ohos::data::relationalStore::SqlExecutionInfo SqlExecutionToTaihe(
    const OHOS::DistributedRdb::SqlObserver::SqlExecutionInfo &sqlInfo)
{
    std::vector<taihe::string> strArray;
    for (auto &tempStr : sqlInfo.sql_) {
        strArray.emplace_back(tempStr);
    }
    return ohos::data::relationalStore::SqlExecutionInfo {
        taihe::array<taihe::string>(strArray), sqlInfo.totalTime_, sqlInfo.waitTime_, sqlInfo.prepareTime_,
            sqlInfo.executeTime_
    };
}

ohos::data::relationalStore::Statistic StatisticToTaihe(const OHOS::DistributedRdb::Statistic &statistic)
{
    return ohos::data::relationalStore::Statistic {
        statistic.total, statistic.success, statistic.failed, statistic.untreated
    };
}

uintptr_t ColumnTypeToTaihe(const OHOS::DistributedRdb::ColumnType columnType)
{
    ani_env *env = taihe::get_env();
    ani_enum enumType;
    if (ANI_OK != env->FindEnum("@ohos.data.relationalStore.relationalStore.ColumnType", &enumType)) {
        LOG_ERROR("Find enum failed.");
        return 0;
    }
    ani_enum_item enumItem;
    switch (columnType) {
        case OHOS::DistributedRdb::ColumnType::TYPE_NULL:
            env->Enum_GetEnumItemByName(enumType, "NULL", &enumItem);
            break;
        case OHOS::DistributedRdb::ColumnType::TYPE_INTEGER:
            env->Enum_GetEnumItemByName(enumType, "INTEGER", &enumItem);
            break;
        case OHOS::DistributedRdb::ColumnType::TYPE_FLOAT:
            env->Enum_GetEnumItemByName(enumType, "REAL", &enumItem);
            break;
        case OHOS::DistributedRdb::ColumnType::TYPE_STRING:
            env->Enum_GetEnumItemByName(enumType, "TEXT", &enumItem);
            break;
        case OHOS::DistributedRdb::ColumnType::TYPE_BLOB:
            env->Enum_GetEnumItemByName(enumType, "BLOB", &enumItem);
            break;
        case OHOS::DistributedRdb::ColumnType::TYPE_ASSET:
            env->Enum_GetEnumItemByName(enumType, "ASSET", &enumItem);
            break;
        case OHOS::DistributedRdb::ColumnType::TYPE_ASSETS:
            env->Enum_GetEnumItemByName(enumType, "ASSETS", &enumItem);
            break;
        case OHOS::DistributedRdb::ColumnType::TYPE_FLOAT32_ARRAY:
            env->Enum_GetEnumItemByName(enumType, "FLOAT_VECTOR", &enumItem);
            break;
        case OHOS::DistributedRdb::ColumnType::TYPE_BIGINT:
            env->Enum_GetEnumItemByName(enumType, "UNLIMITED_INT", &enumItem);
            break;
        default:
            LOG_ERROR("Invalid ColumnType value.");
            break;
    }
    return reinterpret_cast<uintptr_t>(enumItem);
}

OHOS::DistributedRdb::SyncMode SyncModeToNative(ohos::data::relationalStore::SyncMode syncMode)
{
    switch (syncMode.get_key()) {
        case ohos::data::relationalStore::SyncMode::key_t::SYNC_MODE_PUSH:
            return OHOS::DistributedRdb::SyncMode::PUSH;
        case ohos::data::relationalStore::SyncMode::key_t::SYNC_MODE_PULL:
            return OHOS::DistributedRdb::SyncMode::PULL;
        case ohos::data::relationalStore::SyncMode::key_t::SYNC_MODE_TIME_FIRST:
            return OHOS::DistributedRdb::SyncMode::TIME_FIRST;
        case ohos::data::relationalStore::SyncMode::key_t::SYNC_MODE_NATIVE_FIRST:
            return OHOS::DistributedRdb::SyncMode::NATIVE_FIRST;
        case ohos::data::relationalStore::SyncMode::key_t::SYNC_MODE_CLOUD_FIRST:
            return OHOS::DistributedRdb::SyncMode::CLOUD_FIRST;
        default:
            LOG_ERROR("Invalid SyncMode value.");
            return OHOS::DistributedRdb::SyncMode::PULL_PUSH;
    }
}

OHOS::NativeRdb::ConflictResolution ConflictResolutionToNative(
    ohos::data::relationalStore::ConflictResolution conflictResolution)
{
    switch (conflictResolution.get_key()) {
        case ohos::data::relationalStore::ConflictResolution::key_t::ON_CONFLICT_NONE:
            return OHOS::NativeRdb::ConflictResolution::ON_CONFLICT_NONE;
        case ohos::data::relationalStore::ConflictResolution::key_t::ON_CONFLICT_ROLLBACK:
            return OHOS::NativeRdb::ConflictResolution::ON_CONFLICT_ROLLBACK;
        case ohos::data::relationalStore::ConflictResolution::key_t::ON_CONFLICT_ABORT:
            return OHOS::NativeRdb::ConflictResolution::ON_CONFLICT_ABORT;
        case ohos::data::relationalStore::ConflictResolution::key_t::ON_CONFLICT_FAIL:
            return OHOS::NativeRdb::ConflictResolution::ON_CONFLICT_FAIL;
        case ohos::data::relationalStore::ConflictResolution::key_t::ON_CONFLICT_IGNORE:
            return OHOS::NativeRdb::ConflictResolution::ON_CONFLICT_IGNORE;
        case ohos::data::relationalStore::ConflictResolution::key_t::ON_CONFLICT_REPLACE:
            return OHOS::NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE;
        default:
            LOG_ERROR("Invalid ConflictResolution value.");
            return OHOS::NativeRdb::ConflictResolution::ON_CONFLICT_NONE;
    }
}

OHOS::NativeRdb::Tokenizer TokenizerToNative(ohos::data::relationalStore::Tokenizer tokenizer)
{
    switch (tokenizer.get_key()) {
        case ohos::data::relationalStore::Tokenizer::key_t::ICU_TOKENIZER:
            return OHOS::NativeRdb::Tokenizer::ICU_TOKENIZER;
        case ohos::data::relationalStore::Tokenizer::key_t::CUSTOM_TOKENIZER:
            return OHOS::NativeRdb::Tokenizer::CUSTOM_TOKENIZER;
        case ohos::data::relationalStore::Tokenizer::key_t::NONE_TOKENIZER:
            return OHOS::NativeRdb::Tokenizer::NONE_TOKENIZER;
        default:
            LOG_ERROR("Invalid Tokenizer value.");
            return OHOS::NativeRdb::Tokenizer::NONE_TOKENIZER;
    }
}

ohos::data::relationalStore::SqlInfo SqlInfoToTaihe(const OHOS::NativeRdb::SqlInfo &sqlInfo)
{
    std::vector<ohos::data::relationalStore::ValueType> argsTaihe;
    for (const auto &value : sqlInfo.args) {
        argsTaihe.push_back(ValueObjectToAni(value));
    }
    return ohos::data::relationalStore::SqlInfo {
        taihe::string(sqlInfo.sql),
        taihe::array<ohos::data::relationalStore::ValueType>(argsTaihe)
    };
}

ohos::data::relationalStore::ExceptionMessage ExceptionMessageToTaihe(
    const OHOS::DistributedRdb::SqlErrorObserver::ExceptionMessage &exceptionMessage)
{
    return ohos::data::relationalStore::ExceptionMessage {
        exceptionMessage.code,
        taihe::string(exceptionMessage.message),
        taihe::string(exceptionMessage.sql)
    };
}

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

std::shared_ptr<OHOS::NativeRdb::RdbPredicates> GetNativePredicatesFromTaihe(
    ohos::data::relationalStore::weak::RdbPredicates predicates)
{
    auto *impl = reinterpret_cast<OHOS::RdbTaihe::RdbPredicatesImpl *>(predicates->GetSpecificImplPtr());
    if (impl == nullptr) {
        LOG_ERROR("Rdb predicates impl is nullptr.");
        return nullptr;
    }
    auto rdbPredicateNative = impl->GetNativePtr();
    if (rdbPredicateNative == nullptr) {
        LOG_ERROR("Rdb predicate native is nullptr.");
        return nullptr;
    }
    return rdbPredicateNative;
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

bool WarpDate(double time, ani_object &outObj)
{
    ani_env *env = ::taihe::get_env();
    if (env == nullptr || time < 0) {
        LOG_ERROR("get_env failed");
        return false;
    }
    ani_class cls;
    ani_status status;
    if (ANI_OK != (status = env->FindClass("std.core.Date", &cls))) {
        LOG_ERROR("FindClass failed, status:%{public}d", status);
        return false;
    }
    ani_method ctor;
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":", &ctor)) != ANI_OK) {
        LOG_ERROR("Class_FindMethod failed, status:%{public}d", status);
        return false;
    }
    if ((status = env->Object_New(cls, ctor, &outObj)) != ANI_OK) {
        LOG_ERROR("Object_New failed, status:%{public}d", status);
        return false;
    }
    ani_double msObj = 0;
    if ((status = env->Object_CallMethodByName_Double(outObj, "setTime", "d:d", &msObj, time)) != ANI_OK) {
        LOG_ERROR("Object_CallMethodByName_Double failed, status:%{public}d", status);
        return false;
    }
    LOG_ERROR("Object_CallMethodByName_Double success, double:%{public}lf", msObj);
    return true;
}
} //namespace ani_rdbutils