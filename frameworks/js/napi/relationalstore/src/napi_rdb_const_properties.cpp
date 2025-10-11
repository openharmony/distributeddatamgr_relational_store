/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "napi_rdb_const_properties.h"

#include "js_utils.h"
#include "rdb_common.h"
#include "rdb_store.h"
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
#include "rdb_store_config.h"
#include "rdb_types.h"

using OHOS::DistributedRdb::SubscribeMode;
using OHOS::DistributedRdb::SyncMode;
#endif
using OHOS::DistributedRdb::DistributedTableType;
using OHOS::DistributedRdb::ProgressCode;
using OHOS::NativeRdb::ConflictResolution;
using OHOS::NativeRdb::SecurityLevel;
using OHOS::DistributedRdb::ColumnType;

#define SET_NAPI_PROPERTY(object, prop, value) \
    napi_set_named_property((env), (object), (prop), AppDataMgrJsKit::JSUtils::Convert2JSValue((env), (value)))

namespace OHOS::RelationalStoreJsKit {
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)

static napi_value ExportSyncMode(napi_env env)
{
    napi_value syncMode = nullptr;
    napi_status status = napi_create_object(env, &syncMode);
    if (status != napi_ok) {
        return nullptr;
    }

    SET_NAPI_PROPERTY(syncMode, "SYNC_MODE_PUSH", int32_t(SyncMode::PUSH));
    SET_NAPI_PROPERTY(syncMode, "SYNC_MODE_PULL", int32_t(SyncMode::PULL));
    SET_NAPI_PROPERTY(syncMode, "SYNC_MODE_TIME_FIRST", int32_t(SyncMode::TIME_FIRST));
    SET_NAPI_PROPERTY(syncMode, "SYNC_MODE_NATIVE_FIRST", int32_t(SyncMode::NATIVE_FIRST));
    SET_NAPI_PROPERTY(syncMode, "SYNC_MODE_CLOUD_FIRST", int32_t(SyncMode::CLOUD_FIRST));
    napi_object_freeze(env, syncMode);
    return syncMode;
}

static napi_value ExportSubscribeType(napi_env env)
{
    napi_value subscribeType = nullptr;
    napi_status status = napi_create_object(env, &subscribeType);
    if (status != napi_ok) {
        return nullptr;
    }

    SET_NAPI_PROPERTY(subscribeType, "SUBSCRIBE_TYPE_REMOTE", int32_t(SubscribeMode::REMOTE));
    SET_NAPI_PROPERTY(subscribeType, "SUBSCRIBE_TYPE_CLOUD", int32_t(SubscribeMode::CLOUD));
    SET_NAPI_PROPERTY(subscribeType, "SUBSCRIBE_TYPE_CLOUD_DETAILS", int32_t(SubscribeMode::CLOUD_DETAIL));
    SET_NAPI_PROPERTY(subscribeType, "SUBSCRIBE_TYPE_LOCAL_DETAILS", int32_t(SubscribeMode::LOCAL_DETAIL));
    napi_object_freeze(env, subscribeType);
    return subscribeType;
}

static napi_value ExportSecurityLevel(napi_env env)
{
    napi_value securityLevel = nullptr;
    napi_status status = napi_create_object(env, &securityLevel);
    if (status != napi_ok) {
        return nullptr;
    }

    SET_NAPI_PROPERTY(securityLevel, "S1", int32_t(SecurityLevel::S1));
    SET_NAPI_PROPERTY(securityLevel, "S2", int32_t(SecurityLevel::S2));
    SET_NAPI_PROPERTY(securityLevel, "S3", int32_t(SecurityLevel::S3));
    SET_NAPI_PROPERTY(securityLevel, "S4", int32_t(SecurityLevel::S4));
    napi_object_freeze(env, securityLevel);
    return securityLevel;
}
#endif

static napi_value ExportProgress(napi_env env)
{
    napi_value progress = nullptr;
    napi_status status = napi_create_object(env, &progress);
    if (status != napi_ok) {
        return nullptr;
    }

    SET_NAPI_PROPERTY(progress, "SYNC_BEGIN", int32_t(DistributedRdb::Progress::SYNC_BEGIN));
    SET_NAPI_PROPERTY(progress, "SYNC_IN_PROGRESS", int32_t(DistributedRdb::Progress::SYNC_IN_PROGRESS));
    SET_NAPI_PROPERTY(progress, "SYNC_FINISH", int32_t(DistributedRdb::Progress::SYNC_FINISH));
    napi_object_freeze(env, progress);
    return progress;
}

static napi_value ExportProgressCode(napi_env env)
{
    napi_value progressCode = nullptr;
    napi_status status = napi_create_object(env, &progressCode);
    if (status != napi_ok) {
        return nullptr;
    }

    SET_NAPI_PROPERTY(progressCode, "SUCCESS", int32_t(ProgressCode::SUCCESS));
    SET_NAPI_PROPERTY(progressCode, "UNKNOWN_ERROR", int32_t(ProgressCode::UNKNOWN_ERROR));
    SET_NAPI_PROPERTY(progressCode, "NETWORK_ERROR", int32_t(ProgressCode::NETWORK_ERROR));
    SET_NAPI_PROPERTY(progressCode, "CLOUD_DISABLED", int32_t(ProgressCode::CLOUD_DISABLED));
    SET_NAPI_PROPERTY(progressCode, "LOCKED_BY_OTHERS", int32_t(ProgressCode::LOCKED_BY_OTHERS));
    SET_NAPI_PROPERTY(progressCode, "RECORD_LIMIT_EXCEEDED", int32_t(ProgressCode::RECORD_LIMIT_EXCEEDED));
    SET_NAPI_PROPERTY(progressCode, "NO_SPACE_FOR_ASSET", int32_t(ProgressCode::NO_SPACE_FOR_ASSET));
    SET_NAPI_PROPERTY(progressCode, "BLOCKED_BY_NETWORK_STRATEGY", int32_t(ProgressCode::BLOCKED_BY_NETWORK_STRATEGY));
    napi_object_freeze(env, progressCode);
    return progressCode;
}

static napi_value ExportOrigin(napi_env env)
{
    napi_value origin = nullptr;
    napi_status status = napi_create_object(env, &origin);
    if (status != napi_ok) {
        return nullptr;
    }

    SET_NAPI_PROPERTY(origin, "LOCAL", int32_t(NativeRdb::AbsPredicates::Origin::LOCAL));
    SET_NAPI_PROPERTY(origin, "CLOUD", int32_t(NativeRdb::AbsPredicates::Origin::CLOUD));
    SET_NAPI_PROPERTY(origin, "REMOTE", int32_t(NativeRdb::AbsPredicates::Origin::REMOTE));
    napi_object_freeze(env, origin);
    return origin;
}

static napi_value ExportField(napi_env env)
{
    napi_value field = nullptr;
    napi_status status = napi_create_object(env, &field);
    if (status != napi_ok) {
        return nullptr;
    }

    SET_NAPI_PROPERTY(field, "CURSOR_FIELD", std::string(DistributedRdb::Field::CURSOR_FIELD));
    SET_NAPI_PROPERTY(field, "ORIGIN_FIELD", std::string(DistributedRdb::Field::ORIGIN_FIELD));
    SET_NAPI_PROPERTY(field, "DELETED_FLAG_FIELD", std::string(DistributedRdb::Field::DELETED_FLAG_FIELD));
    SET_NAPI_PROPERTY(field, "DATA_STATUS_FIELD", std::string(DistributedRdb::Field::DATA_STATUS_FIELD));
    SET_NAPI_PROPERTY(field, "OWNER_FIELD", std::string(DistributedRdb::Field::OWNER_FIELD));
    SET_NAPI_PROPERTY(field, "PRIVILEGE_FIELD", std::string(DistributedRdb::Field::PRIVILEGE_FIELD));
    SET_NAPI_PROPERTY(field, "SHARING_RESOURCE_FIELD", std::string(DistributedRdb::Field::SHARING_RESOURCE_FIELD));
    napi_object_freeze(env, field);
    return field;
}

static napi_value ExportDistributedType(napi_env env)
{
    napi_value distributedType = nullptr;
    napi_status status = napi_create_object(env, &distributedType);
    if (status != napi_ok) {
        return nullptr;
    }

    SET_NAPI_PROPERTY(distributedType, "DISTRIBUTED_DEVICE", int32_t(DistributedTableType::DISTRIBUTED_DEVICE));
    SET_NAPI_PROPERTY(distributedType, "DISTRIBUTED_CLOUD", int32_t(DistributedTableType::DISTRIBUTED_CLOUD));
    napi_object_freeze(env, distributedType);
    return distributedType;
}

static napi_value ExportChangeType(napi_env env)
{
    napi_value changeType = nullptr;
    napi_status status = napi_create_object(env, &changeType);
    if (status != napi_ok) {
        return nullptr;
    }

    SET_NAPI_PROPERTY(changeType, "DATA_CHANGE", int32_t(DistributedRdb::Origin::BASIC_DATA));
    SET_NAPI_PROPERTY(changeType, "ASSET_CHANGE", int32_t(DistributedRdb::Origin::ASSET_DATA));
    napi_object_freeze(env, changeType);
    return changeType;
}

static napi_value ExportAssetStatus(napi_env env)
{
    napi_value assetStatus = nullptr;
    napi_status status = napi_create_object(env, &assetStatus);
    if (status != napi_ok) {
        return nullptr;
    }

    SET_NAPI_PROPERTY(assetStatus, "ASSET_NORMAL", int32_t(NativeRdb::AssetValue::STATUS_NORMAL));
    SET_NAPI_PROPERTY(assetStatus, "ASSET_INSERT", int32_t(NativeRdb::AssetValue::STATUS_INSERT));
    SET_NAPI_PROPERTY(assetStatus, "ASSET_UPDATE", int32_t(NativeRdb::AssetValue::STATUS_UPDATE));
    SET_NAPI_PROPERTY(assetStatus, "ASSET_DELETE", int32_t(NativeRdb::AssetValue::STATUS_DELETE));
    SET_NAPI_PROPERTY(assetStatus, "ASSET_ABNORMAL", int32_t(NativeRdb::AssetValue::STATUS_ABNORMAL));
    SET_NAPI_PROPERTY(assetStatus, "ASSET_DOWNLOADING", int32_t(NativeRdb::AssetValue::STATUS_DOWNLOADING));
    napi_object_freeze(env, assetStatus);
    return assetStatus;
}

static napi_value ExportConflictResolution(napi_env env)
{
    napi_value conflictResolution = nullptr;
    napi_status status = napi_create_object(env, &conflictResolution);
    if (status != napi_ok) {
        return nullptr;
    }

    SET_NAPI_PROPERTY(conflictResolution, "ON_CONFLICT_NONE", int32_t(ConflictResolution::ON_CONFLICT_NONE));
    SET_NAPI_PROPERTY(conflictResolution, "ON_CONFLICT_ROLLBACK", int32_t(ConflictResolution::ON_CONFLICT_ROLLBACK));
    SET_NAPI_PROPERTY(conflictResolution, "ON_CONFLICT_ABORT", int32_t(ConflictResolution::ON_CONFLICT_ABORT));
    SET_NAPI_PROPERTY(conflictResolution, "ON_CONFLICT_FAIL", int32_t(ConflictResolution::ON_CONFLICT_FAIL));
    SET_NAPI_PROPERTY(conflictResolution, "ON_CONFLICT_IGNORE", int32_t(ConflictResolution::ON_CONFLICT_IGNORE));
    SET_NAPI_PROPERTY(conflictResolution, "ON_CONFLICT_REPLACE", int32_t(ConflictResolution::ON_CONFLICT_REPLACE));

    napi_object_freeze(env, conflictResolution);
    return conflictResolution;
}

static napi_value ExportRebuiltType(napi_env env)
{
    napi_value rebuiltType = nullptr;
    napi_status status = napi_create_object(env, &rebuiltType);
    if (status != napi_ok) {
        return nullptr;
    }

    SET_NAPI_PROPERTY(rebuiltType, "NONE", int32_t(NativeRdb::RebuiltType::NONE));
    SET_NAPI_PROPERTY(rebuiltType, "REBUILT", int32_t(NativeRdb::RebuiltType::REBUILT));
    SET_NAPI_PROPERTY(rebuiltType, "REPAIRED", int32_t(NativeRdb::RebuiltType::REPAIRED));

    napi_object_freeze(env, rebuiltType);
    return rebuiltType;
}

static napi_value ExportHAMode(napi_env env)
{
    napi_value haMode = nullptr;
    napi_status status = napi_create_object(env, &haMode);
    if (status != napi_ok) {
        return nullptr;
    }

    SET_NAPI_PROPERTY(haMode, "SINGLE", int32_t(NativeRdb::HAMode::SINGLE));
    SET_NAPI_PROPERTY(haMode, "MAIN_REPLICA", int32_t(NativeRdb::HAMode::MAIN_REPLICA));
    napi_object_freeze(env, haMode);
    return haMode;
}

static napi_value ExportEncryptionAlgo(napi_env env)
{
    napi_value encryptionAlgo = nullptr;
    napi_status status = napi_create_object(env, &encryptionAlgo);
    if (status != napi_ok) {
        return nullptr;
    }

    SET_NAPI_PROPERTY(encryptionAlgo, "AES_256_GCM", int32_t(NativeRdb::EncryptAlgo::AES_256_GCM));
    SET_NAPI_PROPERTY(encryptionAlgo, "AES_256_CBC", int32_t(NativeRdb::EncryptAlgo::AES_256_CBC));
    SET_NAPI_PROPERTY(encryptionAlgo, "PLAIN_TEXT", int32_t(NativeRdb::EncryptAlgo::PLAIN_TEXT));
    napi_object_freeze(env, encryptionAlgo);
    return encryptionAlgo;
}

static napi_value ExportHmacAlgo(napi_env env)
{
    napi_value hmacAlgo = nullptr;
    napi_status status = napi_create_object(env, &hmacAlgo);
    if (status != napi_ok) {
        return nullptr;
    }

    SET_NAPI_PROPERTY(hmacAlgo, "SHA1", int32_t(NativeRdb::HmacAlgo::SHA1));
    SET_NAPI_PROPERTY(hmacAlgo, "SHA256", int32_t(NativeRdb::HmacAlgo::SHA256));
    SET_NAPI_PROPERTY(hmacAlgo, "SHA512", int32_t(NativeRdb::HmacAlgo::SHA512));
    napi_object_freeze(env, hmacAlgo);
    return hmacAlgo;
}

static napi_value ExportKdfAlgo(napi_env env)
{
    napi_value kdfAlgo = nullptr;
    napi_status status = napi_create_object(env, &kdfAlgo);
    if (status != napi_ok) {
        return nullptr;
    }

    SET_NAPI_PROPERTY(kdfAlgo, "KDF_SHA1", int32_t(NativeRdb::KdfAlgo::KDF_SHA1));
    SET_NAPI_PROPERTY(kdfAlgo, "KDF_SHA256", int32_t(NativeRdb::KdfAlgo::KDF_SHA256));
    SET_NAPI_PROPERTY(kdfAlgo, "KDF_SHA512", int32_t(NativeRdb::KdfAlgo::KDF_SHA512));
    napi_object_freeze(env, kdfAlgo);
    return kdfAlgo;
}

static napi_value ExportTransactionType(napi_env env)
{
    napi_value transactionType = nullptr;
    napi_status status = napi_create_object(env, &transactionType);
    if (status != napi_ok) {
        return nullptr;
    }

    SET_NAPI_PROPERTY(transactionType, "DEFERRED", int32_t(NativeRdb::Transaction::DEFERRED));
    SET_NAPI_PROPERTY(transactionType, "IMMEDIATE", int32_t(NativeRdb::Transaction::IMMEDIATE));
    SET_NAPI_PROPERTY(transactionType, "EXCLUSIVE", int32_t(NativeRdb::Transaction::EXCLUSIVE));
    napi_object_freeze(env, transactionType);
    return transactionType;
}

static napi_value ExportTokenizer(napi_env env)
{
    napi_value tokenizerType = nullptr;
    napi_status status = napi_create_object(env, &tokenizerType);
    if (status != napi_ok) {
        return nullptr;
    }

    SET_NAPI_PROPERTY(tokenizerType, "ICU_TOKENIZER", int32_t(NativeRdb::Tokenizer::ICU_TOKENIZER));
    SET_NAPI_PROPERTY(tokenizerType, "CUSTOM_TOKENIZER", int32_t(NativeRdb::Tokenizer::CUSTOM_TOKENIZER));
    napi_object_freeze(env, tokenizerType);
    return tokenizerType;
}

static napi_value ExportColumnType(napi_env env)
{
    napi_value columnType = nullptr;
    napi_status status = napi_create_object(env, &columnType);
    if (status != napi_ok) {
        return nullptr;
    }

    SET_NAPI_PROPERTY(columnType, "NULL", int32_t(ColumnType::TYPE_NULL));
    SET_NAPI_PROPERTY(columnType, "INTEGER", int32_t(ColumnType::TYPE_INTEGER));
    SET_NAPI_PROPERTY(columnType, "REAL", int32_t(ColumnType::TYPE_FLOAT));
    SET_NAPI_PROPERTY(columnType, "TEXT", int32_t(ColumnType::TYPE_STRING));
    SET_NAPI_PROPERTY(columnType, "BLOB", int32_t(ColumnType::TYPE_BLOB));
    SET_NAPI_PROPERTY(columnType, "ASSET", int32_t(ColumnType::TYPE_ASSET));
    SET_NAPI_PROPERTY(columnType, "ASSETS", int32_t(ColumnType::TYPE_ASSETS));
    SET_NAPI_PROPERTY(columnType, "FLOAT_VECTOR", int32_t(ColumnType::TYPE_FLOAT32_ARRAY));
    SET_NAPI_PROPERTY(columnType, "UNLIMITED_INT", int32_t(ColumnType::TYPE_BIGINT));
    napi_object_freeze(env, columnType);
    return columnType;
}

napi_status InitConstProperties(napi_env env, napi_value exports)
{
    const napi_property_descriptor properties[] = {
        DECLARE_NAPI_PROPERTY("ConflictResolution", ExportConflictResolution(env)),
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
        DECLARE_NAPI_PROPERTY("SyncMode", ExportSyncMode(env)),
        DECLARE_NAPI_PROPERTY("SubscribeType", ExportSubscribeType(env)),
        DECLARE_NAPI_PROPERTY("SecurityLevel", ExportSecurityLevel(env)),
#endif
        DECLARE_NAPI_PROPERTY("Progress", ExportProgress(env)),
        DECLARE_NAPI_PROPERTY("ProgressCode", ExportProgressCode(env)),
        DECLARE_NAPI_PROPERTY("DistributedType", ExportDistributedType(env)),
        DECLARE_NAPI_PROPERTY("AssetStatus", ExportAssetStatus(env)),
        DECLARE_NAPI_PROPERTY("ChangeType", ExportChangeType(env)),
        DECLARE_NAPI_PROPERTY("Origin", ExportOrigin(env)),
        DECLARE_NAPI_PROPERTY("Field", ExportField(env)),
        DECLARE_NAPI_PROPERTY("RebuildType", ExportRebuiltType(env)),
        DECLARE_NAPI_PROPERTY("HAMode", ExportHAMode(env)),
        DECLARE_NAPI_PROPERTY("EncryptionAlgo", ExportEncryptionAlgo(env)),
        DECLARE_NAPI_PROPERTY("HmacAlgo", ExportHmacAlgo(env)),
        DECLARE_NAPI_PROPERTY("KdfAlgo", ExportKdfAlgo(env)),
        DECLARE_NAPI_PROPERTY("TransactionType", ExportTransactionType(env)),
        DECLARE_NAPI_PROPERTY("Tokenizer", ExportTokenizer(env)),
        DECLARE_NAPI_PROPERTY("ColumnType", ExportColumnType(env)),
    };

    size_t count = sizeof(properties) / sizeof(properties[0]);
    return napi_define_properties(env, exports, count, properties);
}
} // namespace OHOS::RelationalStoreJsKit