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

#ifndef NAPI_RDB_STORE_OBSERVER_H
#define NAPI_RDB_STORE_OBSERVER_H
#include "js_uv_queue.h"
#include "rdb_types.h"

namespace OHOS::RdbJsKit {
using namespace OHOS::AppDataMgrJsKit;
class NapiRdbStoreObserver
    : public DistributedRdb::RdbStoreObserver
    , public std::enable_shared_from_this<NapiRdbStoreObserver> {
public:
    explicit NapiRdbStoreObserver(
        napi_value callback, std::shared_ptr<UvQueue> uvQueue, int32_t mode = DistributedRdb::REMOTE);
    virtual ~NapiRdbStoreObserver() noexcept;
    bool operator==(napi_value value);
    void OnChange(const std::vector<std::string> &devices) override;
    void Clear();

private:
    std::shared_ptr<UvQueue> uvQueue_;
    napi_ref callback_;
};
} // namespace OHOS::RdbJsKit
#endif
