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
#include <ani.h>
#include <iostream>
#include "ani_result_set.h"
#include "ani_rdb_store_helper.h"

using namespace OHOS::RelationalStoreAniKit;

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        std::cerr << "Unsupported ANI_VERSION_1" << std::endl;
        return ANI_ERROR;
    }

    if (ANI_OK != ResultSetInit(env)) {
        std::cerr << "ResultSetInit failed." << std::endl;
        return ANI_ERROR;
    }

    if (ANI_OK != RdbStoreHelperInit(env)) {
        std::cerr << "RdbStoreHelperInit failed." << std::endl;
        return ANI_ERROR;
    }

    if (ANI_OK != RdbStoreInit(env)) {
        std::cerr << "RdbStoreInit failed." << std::endl;
        return ANI_ERROR;
    }

    *result = ANI_VERSION_1;
    return ANI_OK;
}
