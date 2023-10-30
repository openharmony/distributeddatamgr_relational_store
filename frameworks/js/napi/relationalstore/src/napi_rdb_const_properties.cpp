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
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
#include "rdb_store_config.h"
#include "rdb_types.h"

using OHOS::DistributedRdb::SyncMode;
using OHOS::DistributedRdb::SubscribeMode;
#endif
using OHOS::NativeRdb::SecurityLevel;
using OHOS::NativeRdb::ConflictResolution;

#define SET_NAPI_PROPERTY(object, propName, value)                        \
{                                                                         \
    (void) SetNamedProperty(env, (object), (propName), (int32_t)(value)); \
}

namespace OHOS::RelationalStoreJsKit {
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
static napi_status SetNamedProperty(napi_env env, napi_value& obj, const std::string& name, int32_t value)
{
    napi_value property = nullptr;
    napi_status status = napi_create_int32(env, value, &property);
    if (status != napi_ok) {
        return status;
    }
    status = napi_set_named_property(env, obj, name.c_str(), property);
    if (status != napi_ok) {
        return status;
    }
    return status;
}

static napi_status SetNamedProperty(napi_env env, napi_value& obj, const std::string& name, const std::string &value)
{
    napi_value property = nullptr;
    napi_status status = napi_create_string_utf8(env, value.c_str(), value.size(), &property);
    if (status != napi_ok) {
        return status;
    }
    if (property == nullptr) {
        return napi_invalid_arg;
    }
    return napi_set_named_property(env, obj, name.c_str(), property);
}

static napi_value ExportSyncMode(napi_env env)
{
    napi_value syncMode = nullptr;
    napi_create_object(env, &syncMode);

    SET_NAPI_PROPERTY(syncMode, "SYNC_MODE_PUSH", SyncMode::PUSH);
    SET_NAPI_PROPERTY(syncMode, "SYNC_MODE_PULL", SyncMode::PULL);
    SET_NAPI_PROPERTY(syncMode, "SYNC_MODE_TIME_FIRST", SyncMode::TIME_FIRST);
    SET_NAPI_PROPERTY(syncMode, "SYNC_MODE_NATIVE_FIRST", SyncMode::NATIVE_FIRST);
    SET_NAPI_PROPERTY(syncMode, "SYNC_MODE_CLOUD_FIRST", SyncMode::CLOUD_FIRST);
    napi_object_freeze(env, syncMode);
    return syncMode;
}

static napi_value ExportSubscribeType(napi_env env)
{
    napi_value subscribeType = nullptr;
    napi_create_object(env, &subscribeType);

    SET_NAPI_PROPERTY(subscribeType, "SUBSCRIBE_TYPE_REMOTE", SubscribeMode::REMOTE);
    SET_NAPI_PROPERTY(subscribeType, "SUBSCRIBE_TYPE_CLOUD", SubscribeMode::CLOUD);
    SET_NAPI_PROPERTY(subscribeType, "SUBSCRIBE_TYPE_CLOUD_DETAILS", SubscribeMode::CLOUD_DETAIL);
    napi_object_freeze(env, subscribeType);
    return subscribeType;
}

static napi_value ExportSecurityLevel(napi_env env)
{
    napi_value securityLevel = nullptr;
    napi_create_object(env, &securityLevel);

    SET_NAPI_PROPERTY(securityLevel, "S1", SecurityLevel::S1);
    SET_NAPI_PROPERTY(securityLevel, "S2", SecurityLevel::S2);
    SET_NAPI_PROPERTY(securityLevel, "S3", SecurityLevel::S3);
    SET_NAPI_PROPERTY(securityLevel, "S4", SecurityLevel::S4);
    napi_object_freeze(env, securityLevel);
    return securityLevel;
}
#endif

static napi_value ExportProgress(napi_env env)
{
    napi_value progress = nullptr;
    napi_create_object(env, &progress);

    SET_NAPI_PROPERTY(progress, "SYNC_BEGIN", 0);
    SET_NAPI_PROPERTY(progress, "SYNC_IN_PROGRESS", 1);
    SET_NAPI_PROPERTY(progress, "SYNC_FINISH", 2);
    napi_object_freeze(env, progress);
    return progress;
}

static napi_value ExportProgressCode(napi_env env)
{
    napi_value progressCode = nullptr;
    napi_create_object(env, &progressCode);

    SET_NAPI_PROPERTY(progressCode, "SUCCESS", 0);
    SET_NAPI_PROPERTY(progressCode, "UNKNOWN_ERROR", 1);
    SET_NAPI_PROPERTY(progressCode, "NETWORK_ERROR", 2);
    SET_NAPI_PROPERTY(progressCode, "CLOUD_DISABLED", 3);
    SET_NAPI_PROPERTY(progressCode, "LOCKED_BY_OTHERS", 4);
    SET_NAPI_PROPERTY(progressCode, "RECORD_LIMIT_EXCEEDED", 5);
    SET_NAPI_PROPERTY(progressCode, "NO_SPACE_FOR_ASSET", 6);
    napi_object_freeze(env, progressCode);
    return progressCode;
}

static napi_value ExportOrigin(napi_env env)
{
    napi_value origin = nullptr;
    napi_create_object(env, &origin);

    SET_NAPI_PROPERTY(origin, "LOCAL", NativeRdb::AbsPredicates::Origin::LOCAL);
    SET_NAPI_PROPERTY(origin, "CLOUD", NativeRdb::AbsPredicates::Origin::CLOUD);
    SET_NAPI_PROPERTY(origin, "REMOTE", NativeRdb::AbsPredicates::Origin::REMOTE);
    napi_object_freeze(env, origin);
    return origin;
}

static napi_value ExportField(napi_env env)
{
    napi_value field = nullptr;
    napi_create_object(env, &field);

    SetNamedProperty(env, field, "CURSOR_FIELD", DistributedRdb::Field::CURSOR_FIELD);
    SetNamedProperty(env, field, "ORIGIN_FIELD", DistributedRdb::Field::ORIGIN_FIELD);
    SetNamedProperty(env, field, "DELETED_FLAG_FIELD", DistributedRdb::Field::DELETED_FLAG_FIELD);
    SetNamedProperty(env, field, "OWNER_FIELD", DistributedRdb::Field::OWNER_FIELD);
    SetNamedProperty(env, field, "PRIVILEGE_FIELD", DistributedRdb::Field::PRIVILEGE_FIELD);
    napi_object_freeze(env, field);
    return field;
}

static napi_value ExportDistributedType(napi_env env)
{
    napi_value distributedType = nullptr;
    napi_create_object(env, &distributedType);

    SET_NAPI_PROPERTY(distributedType, "DISTRIBUTED_DEVICE", 0);
    SET_NAPI_PROPERTY(distributedType, "DISTRIBUTED_CLOUD", 1);
    napi_object_freeze(env, distributedType);
    return distributedType;
}

static napi_value ExportChangeType(napi_env env)
{
    napi_value changeType = nullptr;
    napi_create_object(env, &changeType);

    SET_NAPI_PROPERTY(changeType, "DATA_CHANGE", DistributedRdb::Origin::BASIC_DATA);
    SET_NAPI_PROPERTY(changeType, "ASSET_CHANGE", DistributedRdb::Origin::ASSET_DATA);
    napi_object_freeze(env, changeType);
    return changeType;
}

static napi_value ExportAssetStatus(napi_env env)
{
    napi_value assetStatus = nullptr;
    napi_create_object(env, &assetStatus);

    SET_NAPI_PROPERTY(assetStatus, "ASSET_NORMAL", NativeRdb::AssetValue::STATUS_NORMAL);
    SET_NAPI_PROPERTY(assetStatus, "ASSET_INSERT", NativeRdb::AssetValue::STATUS_INSERT);
    SET_NAPI_PROPERTY(assetStatus, "ASSET_UPDATE", NativeRdb::AssetValue::STATUS_UPDATE);
    SET_NAPI_PROPERTY(assetStatus, "ASSET_DELETE", NativeRdb::AssetValue::STATUS_DELETE);
    SET_NAPI_PROPERTY(assetStatus, "ASSET_ABNORMAL", NativeRdb::AssetValue::STATUS_ABNORMAL);
    SET_NAPI_PROPERTY(assetStatus, "ASSET_DOWNLOADING", NativeRdb::AssetValue::STATUS_DOWNLOADING);
    napi_object_freeze(env, assetStatus);
    return assetStatus;
}

static napi_value ExportConflictResolution(napi_env env)
{
    napi_value conflictResolution = nullptr;
    napi_create_object(env, &conflictResolution);

    SET_NAPI_PROPERTY(conflictResolution, "ON_CONFLICT_NONE", ConflictResolution::ON_CONFLICT_NONE);
    SET_NAPI_PROPERTY(conflictResolution, "ON_CONFLICT_ROLLBACK", ConflictResolution::ON_CONFLICT_ROLLBACK);
    SET_NAPI_PROPERTY(conflictResolution, "ON_CONFLICT_ABORT", ConflictResolution::ON_CONFLICT_ABORT);
    SET_NAPI_PROPERTY(conflictResolution, "ON_CONFLICT_FAIL", ConflictResolution::ON_CONFLICT_FAIL);
    SET_NAPI_PROPERTY(conflictResolution, "ON_CONFLICT_IGNORE", ConflictResolution::ON_CONFLICT_IGNORE);
    SET_NAPI_PROPERTY(conflictResolution, "ON_CONFLICT_REPLACE", ConflictResolution::ON_CONFLICT_REPLACE);

    napi_object_freeze(env, conflictResolution);
    return conflictResolution;
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
    };

    size_t count = sizeof(properties) / sizeof(properties[0]);
    return napi_define_properties(env, exports, count, properties);
}
} // namespace OHOS::RelationalStoreJsKit