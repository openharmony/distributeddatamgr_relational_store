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
#ifndef ANI_RDB_ERROR_H
#define ANI_RDB_ERROR_H

#include <map>
#include <optional>
#include <string>
#include <ani.h>
#include "logger.h"
#include "rdb_errno.h"

namespace OHOS {
namespace RelationalStoreAniKit {
constexpr int MAX_INPUT_COUNT = 10;
constexpr int OK = 0;
constexpr int ERR = -1;

constexpr int E_NON_SYSTEM_APP_ERROR = 202;
constexpr int E_PARAM_ERROR = 401;
constexpr int E_INNER_ERROR = 14800000;
constexpr int E_NOT_STAGE_MODE = 14801001;
constexpr int E_DATA_GROUP_ID_INVALID = 14801002;

struct JsErrorCode {
    int32_t status;
    int32_t jsCode;
    const char *message;
};
const std::optional<JsErrorCode> GetJsErrorCode(int32_t errorCode);
ani_object GetAniBusinessError(ani_env *env, int32_t errorCode);
void ThrowBusinessError(ani_env *env, int32_t status);
void ThrowBusinessError(ani_env *env, int32_t status, std::string message);

} // namespace RelationalStoreAniKit
} // namespace OHOS

#endif // ANI_RDB_ERROR_H

