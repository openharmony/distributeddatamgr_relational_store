/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef APPDATAMGR_NAPI_VALUES_BUCKET_H
#define APPDATAMGR_NAPI_VALUES_BUCKET_H

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "values_bucket.h"

namespace OHOS {
namespace RdbJsKit {

class ValuesBucketProxy {
public:
    explicit ValuesBucketProxy(NativeRdb::ValuesBucket &valuesBucket_);

    napi_value Convert2JSValue(napi_env env);

private:
    NativeRdb::ValuesBucket &valuesBucket_;
};

} // namespace RdbJsKit
} // namespace OHOS
#endif //APPDATAMGR_NAPI_VALUES_BUCKET_H
