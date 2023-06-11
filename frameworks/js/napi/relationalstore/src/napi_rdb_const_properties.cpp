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
    SET_NAPI_PROPERTY(subscribeType, "SUBSCRIBE_TYPE_CLOUD_DETAIL", SubscribeMode::CLOUD_DETAIL);
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

static napi_value ExportDistributedType(napi_env env)
{
    napi_value distributedType = nullptr;
    napi_create_object(env, &distributedType);

    SET_NAPI_PROPERTY(distributedType, "DISTRIBUTED_DEVICE", 0);
    SET_NAPI_PROPERTY(distributedType, "DISTRIBUTED_CLOUD", 1);
    napi_object_freeze(env, distributedType);
    return distributedType;
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
        DECLARE_NAPI_PROPERTY("DistributedType", ExportDistributedType(env)),
    };

    size_t count = sizeof(properties) / sizeof(properties[0]);
    return napi_define_properties(env, exports, count, properties);
}
} // namespace OHOS::RelationalStoreJsKit