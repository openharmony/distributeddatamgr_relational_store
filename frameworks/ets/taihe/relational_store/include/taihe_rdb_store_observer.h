/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_RELATION_STORE_TAIHE_RDBSTORE_OBSERVER_H
#define OHOS_RELATION_STORE_TAIHE_RDBSTORE_OBSERVER_H

#include "ani_rdb_utils.h"

namespace ani_rdbutils {
using namespace taihe;

class TaiheRdbStoreObserver : public OHOS::DistributedRdb::RdbStoreObserver,
    public std::enable_shared_from_this<TaiheRdbStoreObserver> {
public:
    using SubscribeFuncType = std::function<int32_t(std::shared_ptr<TaiheRdbStoreObserver> observer)>;
    using UnSubscribeFuncType = std::function<int32_t(std::shared_ptr<TaiheRdbStoreObserver> observer)>;

    explicit TaiheRdbStoreObserver(
        ani_env *env,
        ani_ref callbackRef,
        std::shared_ptr<RdbStoreVarCallbackType> callbackPtr,
        OHOS::DistributedRdb::SubscribeMode subscribeMode
    );
    ~TaiheRdbStoreObserver();

    bool IsEquals(ani_ref ref);

    void OnChange(const std::vector<std::string> &devices) override;
    void OnChange(const OHOS::DistributedRdb::Origin &origin, const PrimaryFields &fields,
        OHOS::DistributedRdb::RdbStoreObserver::ChangeInfo &&changeInfo) override;
    void OnChange() override;

    static int32_t AddCallback(RdbObserversData &rdbObserversData, OHOS::DistributedRdb::SubscribeMode subscribeMode,
        RdbStoreVarCallbackType callbackFunc, uintptr_t opq, SubscribeFuncType subscribeFunc);
    static void RemoveCallback(RdbObserversData &rdbObserversData, OHOS::DistributedRdb::SubscribeMode subscribeMode,
        std::optional<uintptr_t> opq, UnSubscribeFuncType unSubscribeFunc);
    static int32_t AddCallback(RdbObserversData &rdbObserversData, std::string event,
        OHOS::DistributedRdb::SubscribeMode subscribeMode,
        RdbStoreVarCallbackType callbackFunc, uintptr_t opq, SubscribeFuncType subscribeFunc);
    static void RemoveCallback(RdbObserversData &rdbObserversData, std::string event,
        OHOS::DistributedRdb::SubscribeMode subscribeMode,
        std::optional<uintptr_t> opq, UnSubscribeFuncType unSubscribeFunc);

private:
    ani_env *env_;
    ani_ref callbackRef_;
    std::shared_ptr<RdbStoreVarCallbackType> callbackPtr_;
    OHOS::DistributedRdb::SubscribeMode subscribeMode_;
};
}

#endif // OHOS_RELATION_STORE_TAIHE_RDBSTORE_OBSERVER_H