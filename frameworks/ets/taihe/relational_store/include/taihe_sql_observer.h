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

#ifndef OHOS_RELATION_STORE_TAIHE_SQL_OBSERVER_H
#define OHOS_RELATION_STORE_TAIHE_SQL_OBSERVER_H

#include "ani_rdb_utils.h"

namespace ani_rdbutils {
using namespace taihe;

class TaiheSqlObserver : public OHOS::DistributedRdb::SqlObserver,
    public std::enable_shared_from_this<TaiheSqlObserver> {
public:
    using SubscribeFuncType = std::function<int32_t(std::shared_ptr<TaiheSqlObserver> observer)>;
    using UnSubscribeFuncType = std::function<int32_t(std::shared_ptr<TaiheSqlObserver> observer)>;

    explicit TaiheSqlObserver(
        ani_env *env,
        ani_ref callbackRef,
        std::shared_ptr<JsSqlExecutionCallbackType> callbackPtr
    );
    ~TaiheSqlObserver();

    bool IsEquals(ani_ref ref);

    void OnStatistic(const SqlExecutionInfo &info) override;

    static int32_t AddCallbackForStatistics(RdbObserversData &rdbObserversData,
        JsSqlExecutionCallbackType callbackFunc, uintptr_t opq, SubscribeFuncType subscribeFunc);
    static void RemoveCallbackForStatistics(RdbObserversData &rdbObserversData,
        std::optional<uintptr_t> opq, UnSubscribeFuncType unSubscribeFunc);
    static int32_t AddCallbackForPerfStat(RdbObserversData &rdbObserversData,
        JsSqlExecutionCallbackType callbackFunc, uintptr_t opq, SubscribeFuncType subscribeFunc);
    static void RemoveCallbackForPerfStat(RdbObserversData &rdbObserversData,
        std::optional<uintptr_t> opq, UnSubscribeFuncType unSubscribeFunc);

private:
    ani_env *env_;
    ani_ref callbackRef_;
    std::shared_ptr<JsSqlExecutionCallbackType> callbackPtr_;
};
}

#endif // OHOS_RELATION_STORE_TAIHE_SQL_OBSERVER_H