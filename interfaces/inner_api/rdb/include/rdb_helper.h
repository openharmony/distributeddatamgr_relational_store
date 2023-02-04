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
    std::shared_ptr<RdbStore> GetRdbStore(const RdbStoreConfig &config,
        int &errCode, int version, RdbOpenCallback &openCallback);
    void Remove(const std::string &path);
    void Clear();
    int SetSecurityLabel(const RdbStoreConfig &config);
    void SetReleaseTime(int ms);

private:
    int ProcessOpenCallback(RdbStore &rdbStore,
        const RdbStoreConfig &config, int version, RdbOpenCallback &openCallback);
    void RestartTimer(const std::string &path, RdbStoreNode &node);
    static void AutoClose(const std::string &path, RdbStoreManager *manager);
    std::mutex mutex_;
    std::shared_ptr<Utils::Timer> timer_;
    std::map<std::string, std::shared_ptr<RdbStoreNode>> storeCache_;
    // ms_ : [10*1000 ~ 10*60*1000]
    int ms_;
};

/**
 * The RdbHelper class of RDB.
 */
class RdbHelper final {
public:
    /**
     * @brief Obtains an RDB store.
     *
     * You can set parameters of the RDB store as required. In general, this method is recommended
     * to obtain a rdb store.
     *
     * @param config Indicates the {@link RdbStoreConfig} configuration of the database related to this RDB store.
     * @param version Indicates the database version for upgrade or downgrade.
     * @param openCallback version the database version for upgrade or downgrade.
     * @param errCode Indicates the {@link RdbOpenCallback} callback of the store.
     *
     * @return Returns the RDB store {@link RdbStore}.
     */
    static std::shared_ptr<RdbStore> GetRdbStore(
        const RdbStoreConfig &config, int version, RdbOpenCallback &openCallback, int &errCode);
    /**
     * @brief Deletes the database with a specified name.
     *
     * @param path Indicates the database path.
     */
    static int DeleteRdbStore(const std::string &path);
    /**
     * @brief Clear Cache.
     */
    static void ClearCache();

private:
    static void InitSecurityManager(const RdbStoreConfig &config);
};
} // namespace NativeRdb
} // namespace OHOS
#endif
