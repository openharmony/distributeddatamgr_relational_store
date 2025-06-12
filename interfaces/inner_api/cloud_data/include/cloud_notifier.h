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

#ifndef OHOS_DISTRIBUTED_DATA_CLOUD_CLOUD_NOTIFIER_H
#define OHOS_DISTRIBUTED_DATA_CLOUD_CLOUD_NOTIFIER_H

#include "cloud_types.h"
#include "distributeddata_relational_store_ipc_interface_code.h"
#include "rdb_types.h"

namespace OHOS::CloudData {
class ICloudNotifier {
public:
    virtual int32_t OnComplete(uint32_t seqNum, DistributedRdb::Details &&result) = 0;
};
} // namespace OHOS::CloudData
#endif // OHOS_DISTRIBUTED_DATA_CLOUD_CLOUD_NOTIFIER_H
