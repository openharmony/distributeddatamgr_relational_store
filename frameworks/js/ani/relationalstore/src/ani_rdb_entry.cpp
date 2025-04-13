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
#include "logger.h"

using namespace OHOS::Rdb;
using namespace OHOS::RelationalStoreAniKit;

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        LOG_ERROR("Unsupported ANI_VERSION_1");
        return ANI_ERROR;
    }

    if (ANI_OK != ResultSetInit(env)) {
        LOG_ERROR("ResultSetInit failed.");
        return ANI_ERROR;
    }

    if (ANI_OK != RdbStoreHelperInit(env)) {
        LOG_ERROR("RdbStoreHelperInit failed.");
        return ANI_ERROR;
    }

    if (ANI_OK != RdbStoreInit(env)) {
        LOG_ERROR("RdbStoreInit failed.");
        return ANI_ERROR;
    }

    if (ANI_OK != PredicatesInit(env)) {
        LOG_ERROR("PredicatesInit failed.");
        return ANI_ERROR;
    }

    *result = ANI_VERSION_1;
    return ANI_OK;
}

