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
#ifndef OHOS_RELATION_STORE_TAIHE_RDB_OBSERVERS_DATA_H_
#define OHOS_RELATION_STORE_TAIHE_RDB_OBSERVERS_DATA_H_

#include "taihe_log_observer.h"
#include "taihe_rdb_store_observer.h"
#include "taihe_sql_observer.h"
#include "taihe_sync_observer.h"

namespace ani_rdbutils {
using RdbStoreObserverSubscribeFuncType = std::function<int32_t(std::shared_ptr<TaiheRdbStoreObserver> observer)>;
using RdbStoreObserverUnSubscribeFuncType = std::function<int32_t(std::shared_ptr<TaiheRdbStoreObserver> observer)>;
using SyncObserverSubscribeFuncType = std::function<int32_t(std::shared_ptr<TaiheSyncObserver> observer)>;
using SyncObserverUnSubscribeFuncType = std::function<int32_t(std::shared_ptr<TaiheSyncObserver> observer)>;
using SqlObserverSubscribeFuncType = std::function<int32_t(std::shared_ptr<TaiheSqlObserver> observer)>;
using SqlObserverUnSubscribeFuncType = std::function<int32_t(std::shared_ptr<TaiheSqlObserver> observer)>;
using LogObserverSubscribeFuncType = std::function<int32_t(std::shared_ptr<TaiheLogObserver> observer)>;
using LogObserverUnSubscribeFuncType = std::function<int32_t(std::shared_ptr<TaiheLogObserver> observer)>;

struct TaiheRdbObserversData {
    std::mutex rdbObserversMutex_;
    std::list<std::shared_ptr<TaiheRdbStoreObserver>> observers_[OHOS::DistributedRdb::SUBSCRIBE_MODE_MAX];
    std::map<std::string, std::list<std::shared_ptr<TaiheRdbStoreObserver>>> localObservers_;
    std::map<std::string, std::list<std::shared_ptr<TaiheRdbStoreObserver>>> localSharedObservers_;
    std::list<std::shared_ptr<TaiheSyncObserver>> syncObservers_;
    std::list<std::shared_ptr<TaiheSqlObserver>> statisticses_;
    std::list<std::shared_ptr<TaiheSqlObserver>> perfStats_;
    std::list<std::shared_ptr<TaiheLogObserver>> logObservers_;

    int32_t OnDataChange(OHOS::DistributedRdb::SubscribeMode subscribeMode,
        RdbStoreVarCallbackType callbackFunc, uintptr_t opq, RdbStoreObserverSubscribeFuncType subscribeFunc);
    int32_t OffDataChange(OHOS::DistributedRdb::SubscribeMode subscribeMode,
        std::optional<uintptr_t> opq, RdbStoreObserverUnSubscribeFuncType unSubscribeFunc);
    int32_t OnCommon(std::string event, OHOS::DistributedRdb::SubscribeMode subscribeMode,
        RdbStoreVarCallbackType callbackFunc, uintptr_t opq, RdbStoreObserverSubscribeFuncType subscribeFunc);
    int32_t OffCommon(std::string event, OHOS::DistributedRdb::SubscribeMode subscribeMode,
        std::optional<uintptr_t> opq, RdbStoreObserverUnSubscribeFuncType unSubscribeFunc);

    int32_t OnAutoSyncProgress(JsProgressDetailsCallbackType callbackFunc,
        uintptr_t opq, SyncObserverSubscribeFuncType subscribeFunc);
    int32_t OffAutoSyncProgress(std::optional<uintptr_t> opq, SyncObserverUnSubscribeFuncType unSubscribeFunc);

    int32_t OnStatistics(JsSqlExecutionCallbackType callbackFunc,
        uintptr_t opq, SqlObserverSubscribeFuncType subscribeFunc);
    int32_t OffStatistics(std::optional<uintptr_t> opq, SqlObserverUnSubscribeFuncType unSubscribeFunc);
    int32_t OnPerfStat(JsSqlExecutionCallbackType callbackFunc,
        uintptr_t opq, SqlObserverSubscribeFuncType subscribeFunc);
    int32_t OffPerfStat(std::optional<uintptr_t> opq, SqlObserverUnSubscribeFuncType unSubscribeFunc);

    int32_t OnSqliteErrorOccurred(JsExceptionMessageCallbackType callbackFunc,
        uintptr_t opq, LogObserverSubscribeFuncType subscribeFunc);
    int32_t OffSqliteErrorOccurred(std::optional<uintptr_t> opq, LogObserverUnSubscribeFuncType unSubscribeFunc);
};
} // namespace ani_rdbutils

#endif