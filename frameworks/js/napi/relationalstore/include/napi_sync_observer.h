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

#ifndef RDB_JSKIT_NAPI_SYNC_OBSERVER_H
#define RDB_JSKIT_NAPI_SYNC_OBSERVER_H

#include "js_proxy.h"
#include "js_uv_queue.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_rdb_error.h"
#include "rdb_types.h"

namespace OHOS {
namespace RelationalStoreJsKit {

class SyncObserver
    : public DistributedRdb::DetailProgressObserver
    , public std::enable_shared_from_this<SyncObserver> {
public:
    SyncObserver(napi_env env, napi_value callback, std::shared_ptr<AppDataMgrJsKit::UvQueue> uvQueue);
    virtual ~SyncObserver();
    void Clear();
    bool operator==(napi_value value);
    void ProgressNotification(const DistributedRdb::Details &details) override;

private:
    napi_env env_ = nullptr;
    napi_ref callback_ = nullptr;
    std::shared_ptr<AppDataMgrJsKit::UvQueue> queue_ = nullptr;
};
} // namespace RelationalStoreJsKit
} // namespace OHOS

#endif // RDB_JSKIT_NAPI_SYNC_OBSERVER_H
