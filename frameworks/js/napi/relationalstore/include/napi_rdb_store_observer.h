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

#include "rdb_types.h"
#include "js_uv_queue.h"

namespace OHOS::RelationalStoreJsKit  {
using namespace OHOS::AppDataMgrJsKit;

class NapiRdbStoreObserver : public DistributedRdb::RdbStoreObserver,
    public std::enable_shared_from_this<NapiRdbStoreObserver> {
public:
    using Origin = DistributedRdb::Origin;
    struct JSChangeInfo {
        JSChangeInfo(const Origin &origin, ChangeInfo::iterator info);
        std::string table;
        int32_t type;
        std::vector<PrimaryKey> inserted;
        std::vector<PrimaryKey> updated;
        std::vector<PrimaryKey> deleted;
    };
    explicit NapiRdbStoreObserver(napi_value callback, std::shared_ptr<UvQueue> uvQueue,
        int32_t mode = DistributedRdb::REMOTE);
    virtual ~NapiRdbStoreObserver() noexcept;

    void OnChange(const std::vector<std::string>& devices) override;

    void OnChange(const Origin &origin, const PrimaryFields &fields, ChangeInfo &&changeInfo) override;

    void OnChange() override;

    void Clear();

    bool operator==(napi_value value);

private:
    int32_t mode_ = DistributedRdb::REMOTE;
    std::shared_ptr<UvQueue> uvQueue_;
    napi_ref callback_;
};
} // namespace OHOS::RelationalStoreJsKit
#endif
