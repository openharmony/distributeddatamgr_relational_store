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

#ifndef OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_SQL_LOG_H
#define OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_SQL_LOG_H
#include <set>
#include <string>
#include <memory>
#include <mutex>
#include <unordered_map>

#include "rdb_types.h"
#include "rdb_visibility.h"
 
namespace OHOS {
template<typename _Key, typename _Tp>
class ConcurrentMap;
namespace NativeRdb {
using ExceptionMessage = DistributedRdb::SqlErrorObserver::ExceptionMessage;
using SqlErrorObserver = DistributedRdb::SqlErrorObserver;
class SqlLog {
public:
    SqlLog();
    ~SqlLog();
    API_EXPORT static int Subscribe(const std::string storeId, std::shared_ptr<SqlErrorObserver> observer);
    API_EXPORT static int Unsubscribe(const std::string storeId, std::shared_ptr<SqlErrorObserver> observer);
    static void Notify(const std::string &storeId, const ExceptionMessage &exceptionMessage);
    static void Pause();
    static void Resume();
private:
    static ConcurrentMap<std::string, std::set<std::shared_ptr<SqlErrorObserver>>> observerSets_;
    static std::unordered_map<uint64_t, int> suspenders_;
    static std::mutex mutex_;
    static std::atomic<bool> enabled_;
};
} // namespace NativeRdb
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DATA_RELATIONAL_STORE_FRAMEWORKS_NATIVE_RDB_SQL_LOG_H
