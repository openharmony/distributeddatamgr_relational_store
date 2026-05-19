/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <cstdlib>

#include "cj_lambda.h"
#include "ffi_remote_data.h"
#include "js_ability.h"
#include "logger.h"
#include "napi_base_context.h"
#include "napi_rdb_js_utils.h"
#include "rdb_common.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_sql_utils.h"
#include "rdb_store_config.h"
#include "relational_store_impl_rdbstore.h"
#include "relational_store_utils.h"
#include "unistd.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Relational {
extern "C" {
int64_t FfiOHOSRelationalStoreGetRdbStore(OHOS::AbilityRuntime::Context *context, StoreConfig config, int32_t *errCode)
{
    return GetRdbStore(context, config, errCode);
}

FFI_EXPORT int64_t FfiOHOSRelationalStoreGetRdbStoreEx(OHOS::AbilityRuntime::Context *context,
    const StoreConfigEx *config, int32_t *errCode)
{
    return GetRdbStoreEx(context, config, errCode);
}

void FfiOHOSRelationalStoreDeleteRdbStore(OHOS::AbilityRuntime::Context *context, const char *name, int32_t *errCode)
{
    DeleteRdbStore(context, name, errCode);
}

void FfiOHOSRelationalStoreDeleteRdbStoreConfig(
    OHOS::AbilityRuntime::Context *context, StoreConfig config, int32_t *errCode)
{
    DeleteRdbStoreConfig(context, config, errCode);
}

void FfiOHOSRelationalStoreDeleteRdbStoreConfigEx(
    OHOS::AbilityRuntime::Context *context, const StoreConfigEx *config, int32_t *errCode)
{
    DeleteRdbStoreConfigEx(context, config, errCode);
}
}
}
}