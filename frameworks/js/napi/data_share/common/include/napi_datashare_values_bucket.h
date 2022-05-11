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

#ifndef NAPI_DATASHARE_VALUES_BUCKET_H
#define NAPI_DATASHARE_VALUES_BUCKET_H

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "datashare_values_bucket.h"
#include "datashare_js_utils.h"

namespace OHOS {
namespace DataShare {
napi_value DataShareValueBucketNewInstance(napi_env env, DataShareValuesBucket &valuesBucket);
void SetValuesBucketObject(
    DataShareValuesBucket &valuesBucket, const napi_env &env, std::string keyStr, napi_value value);
void GetValueBucketObject(DataShareValuesBucket &valuesBucket, const napi_env &env, const napi_value &arg);
} // namespace DataShare
} // namespace OHOS
#endif // NAPI_DATASHARE_VALUES_BUCKET_H
