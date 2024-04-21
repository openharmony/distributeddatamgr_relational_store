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
#include "rdb_common.h"
#include "rdb_store.h"
#include "js_utils.h"
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
#include "rdb_store_config.h"
#include "rdb_types.h"

using OHOS::DistributedRdb::SyncMode;
using OHOS::DistributedRdb::SubscribeMode;

#endif
using OHOS::NativeRdb::SecurityLevel;
using OHOS::NativeRdb::ConflictResolution;
using OHOS::DistributedRdb::ProgressCode;
using OHOS::DistributedRdb::DistributedTableType;

#define SET_NAPI_PROPERTY(object, prop, value)                         \
    napi_set_named_property((env), (object), (prop), AppDataMgrJsKit::JSUtils::Convert2JSValue((env), (value)))

namespace OHOS::RelationalStoreJsKit {
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)

static napi_value ExportSyncMode(napi_env env)
{
    napi_value syncMode = nullptr;
    napi_create_object(env, &syncMode);

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
    napi_create_object(env, &subscribeType);

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
    napi_create_object(env, &securityLevel);

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
    napi_create_object(env, &progress);

    SET_NAPI_PROPERTY(progress, "SYNC_BEGIN", int32_t(DistributedRdb::Progress::SYNC_BEGIN));
    SET_NAPI_PROPERTY(progress, "SYNC_IN_PROGRESS", int32_t(DistributedRdb::Progress::SYNC_IN_PROGRESS));
    SET_NAPI_PROPERTY(progress, "SYNC_FINISH", int32_t(DistributedRdb::Progress::SYNC_FINISH));
    napi_object_freeze(env, progress);
    return progress;
}

static napi_value ExportProgressCode(napi_env env)
{
    napi_value progressCode = nullptr;
    napi_create_object(env, &progressCode);

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
    napi_create_object(env, &origin);

    SET_NAPI_PROPERTY(origin, "LOCAL", int32_t(NativeRdb::AbsPredicates::Origin::LOCAL));
    SET_NAPI_PROPERTY(origin, "CLOUD", int32_t(NativeRdb::AbsPredicates::Origin::CLOUD));
    SET_NAPI_PROPERTY(origin, "REMOTE", int32_t(NativeRdb::AbsPredicates::Origin::REMOTE));
    napi_object_freeze(env, origin);
    return origin;
}

static napi_value ExportField(napi_env env)
{
    napi_value field = nullptr;
    napi_create_object(env, &field);

    SET_NAPI_PROPERTY(field, "CURSOR_FIELD", std::string(DistributedRdb::Field::CURSOR_FIELD));
    SET_NAPI_PROPERTY(field, "ORIGIN_FIELD", std::string(DistributedRdb::Field::ORIGIN_FIELD));
    SET_NAPI_PROPERTY(field, "DELETED_FLAG_FIELD", std::string(DistributedRdb::Field::DELETED_FLAG_FIELD));
    SET_NAPI_PROPERTY(field, "OWNER_FIELD", std::string(DistributedRdb::Field::OWNER_FIELD));
    SET_NAPI_PROPERTY(field, "PRIVILEGE_FIELD", std::string(DistributedRdb::Field::PRIVILEGE_FIELD));
    SET_NAPI_PROPERTY(field, "SHARING_RESOURCE_FIELD", std::string(DistributedRdb::Field::SHARING_RESOURCE_FIELD));
    napi_object_freeze(env, field);
    return field;
}

static napi_value ExportDistributedType(napi_env env)
{
    napi_value distributedType = nullptr;
    napi_create_object(env, &distributedType);

    SET_NAPI_PROPERTY(distributedType, "DISTRIBUTED_DEVICE", int32_t(DistributedTableType::DISTRIBUTED_DEVICE));
    SET_NAPI_PROPERTY(distributedType, "DISTRIBUTED_CLOUD", int32_t(DistributedTableType::DISTRIBUTED_CLOUD));
    napi_object_freeze(env, distributedType);
    return distributedType;
}

static napi_value ExportChangeType(napi_env env)
{
    napi_value changeType = nullptr;
    napi_create_object(env, &changeType);

    SET_NAPI_PROPERTY(changeType, "DATA_CHANGE", int32_t(DistributedRdb::Origin::BASIC_DATA));
    SET_NAPI_PROPERTY(changeType, "ASSET_CHANGE", int32_t(DistributedRdb::Origin::ASSET_DATA));
    napi_object_freeze(env, changeType);
    return changeType;
}

static napi_value ExportAssetStatus(napi_env env)
{
    napi_value assetStatus = nullptr;
    napi_create_object(env, &assetStatus);

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
    napi_create_object(env, &conflictResolution);

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
    napi_create_object(env, &rebuiltType);

    SET_NAPI_PROPERTY(rebuiltType, "NONE", int32_t(NativeRdb::RebuiltType::NONE));
    SET_NAPI_PROPERTY(rebuiltType, "REBUILT", int32_t(NativeRdb::RebuiltType::REBUILT));

    napi_object_freeze(env, rebuiltType);
    return rebuiltType;
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
    };

    size_t count = sizeof(properties) / sizeof(properties[0]);
    return napi_define_properties(env, exports, count, properties);
}
} // namespace OHOS::RelationalStoreJsKit