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

#define LOG_TAG "AniResultSet"
#include <ani.h>
#include <iostream>
#include "ani_rdb_predicates.h"
#include "ani_rdb_store_helper.h"
#include "ani_result_set.h"
#include "ani_utils.h"
#include "logger.h"

using namespace OHOS::Rdb;
using namespace OHOS::RelationalStoreAniKit;

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    if (vm == nullptr) {
        LOG_ERROR("vm is nullptr.");
        return ANI_ERROR;
    }

    ani_env *env;
    auto status = vm->GetEnv(ANI_VERSION_1, &env);
    if (ANI_OK != status) {
        LOG_ERROR("Unsupported ANI_VERSION_1 errcode %{public}d", status);
        return ANI_ERROR;
    }

    status = ResultSetInit(env);
    if (ANI_OK != status) {
        LOG_ERROR("ResultSetInit failed errcode %{public}d", status);
        return ANI_ERROR;
    }

    status = RdbStoreHelperInit(env);
    if (ANI_OK != status) {
        LOG_ERROR("RdbStoreHelperInit failed errcode %{public}d", status);
        return ANI_ERROR;
    }

    status = RdbStoreInit(env);
    if (ANI_OK != status) {
        LOG_ERROR("RdbStoreInit failed errcode %{public}d", status);
        return ANI_ERROR;
    }

    status = PredicatesInit(env);
    if (ANI_OK != status) {
        LOG_ERROR("PredicatesInit failed errcode %{public}d", status);
        return ANI_ERROR;
    }

    status = CleanerInit(env);
    if (ANI_OK != status) {
        LOG_ERROR("CleanerInit failed errcode %{public}d", status);
        return ANI_ERROR;
    }

    *result = ANI_VERSION_1;
    return ANI_OK;
}

