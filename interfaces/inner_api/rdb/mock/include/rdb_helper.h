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

#ifndef NATIVE_RDB_RDB_HELPER_H
#define NATIVE_RDB_RDB_HELPER_H

#include <memory>
#include <mutex>
#include <string>

#include "rdb_open_callback.h"
#include "rdb_store.h"
#include "rdb_store_config.h"
#include "timer.h"

namespace OHOS {
namespace NativeRdb {
enum class RdbStatus {
    ON_CREATE = 0,
    ON_OPEN = 1,
};

struct RdbStoreNode {
    RdbStoreNode(const std::shared_ptr<RdbStore> &rdbStore);
    RdbStoreNode &operator=(const std::shared_ptr<RdbStore> &store);

    std::shared_ptr<RdbStore> rdbStore_;
    uint32_t timerId_;
};

class RdbStoreManager {
public:
    static RdbStoreManager &GetInstance();
    RdbStoreManager();
    virtual ~RdbStoreManager();
    std::shared_ptr<RdbStore> GetRdbStore(const RdbStoreConfig &config, int &errCode);
    void Remove(const std::string &path);
    void Clear();

private:
    void RestartTimer(const std::string &path, RdbStoreNode &node);
    static void AutoClose(const std::string &path, RdbStoreManager *manager);
    std::mutex mutex_;
    std::shared_ptr<Utils::Timer> timer_;
    std::map<std::string, std::shared_ptr<RdbStoreNode>> storeCache_;
};

class RdbHelper final {
public:
    static std::shared_ptr<RdbStore> GetRdbStore(
        const RdbStoreConfig &config, int version, RdbOpenCallback &openCallback, int &errCode);
    static int DeleteRdbStore(const std::string &path);
    static void ClearCache();

private:
    static int ProcessOpenCallback(
        RdbStore &rdbStore, const RdbStoreConfig &config, int version, RdbOpenCallback &openCallback);
};
} // namespace NativeRdb
} // namespace OHOS
#endif
