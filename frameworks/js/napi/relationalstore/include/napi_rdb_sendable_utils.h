/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef RDB_JSKIT_NAPI_RDB_SENDABLE_UTILS_H
#define RDB_JSKIT_NAPI_RDB_SENDABLE_UTILS_H

#include "napi_rdb_js_utils.h"
namespace OHOS::AppDataMgrJsKit {
namespace JSUtils {
template<>
napi_value Convert2Sendable(napi_env env, const Asset &value);

template<>
napi_value Convert2Sendable(napi_env env, const RowEntity &rowEntity);

template<>
napi_value Convert2Sendable(napi_env env, const ValueObject &value);

template<>
napi_value Convert2Sendable(napi_env env, const BigInt &value);
} // namespace JSUtils
} // namespace OHOS::AppDataMgrJsKit
#endif // RDB_JSKIT_NAPI_RDB_SENDABLE_UTILS_H