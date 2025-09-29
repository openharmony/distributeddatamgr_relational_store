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

namespace OHOS {
namespace NativeRdb {
class API_EXPORT RdbHelper final {
public:
    /**
     * @brief Obtains an RDB store.
     *
     * You can set parameters of the RDB store as required. In general, this method is recommended
     * to obtain a rdb store. BundleName is mandatory and must be the same for different RDB stores
     * of the same application.
     *
     * @param config Indicates the {@link RdbStoreConfig} configuration of the database related to this RDB store.
     * @param version Indicates the database version for upgrade or downgrade.
     * @param openCallback version the database version for upgrade or downgrade.
     * @param errCode Indicates the {@link RdbOpenCallback} callback of the store.
     *
     * @return Returns the RDB store {@link RdbStore}.
     */
    API_EXPORT static std::shared_ptr<RdbStore> GetRdbStore(
        const RdbStoreConfig &config, int version, RdbOpenCallback &openCallback, int &errCode);

    API_EXPORT static std::shared_ptr<RdbStore> GetRdb(const RdbStoreConfig &config);

    /**
     * @brief Deletes the database with a specified name.
     *
     * @param path Indicates the database path.
     */
    API_EXPORT static int DeleteRdbStore(const std::string &path, bool shouldClose = true);

    API_EXPORT static int DeleteRdbStore(const RdbStoreConfig &config, bool shouldClose = true);

    /**
     * @brief Clear Cache.
     */
    API_EXPORT static void ClearCache();

    /**
     * @brief Checks whether the vector database is supported.
     *
     * @return Returns {@code true} if the vector database is supported; returns {@code false} otherwise.
     */
    API_EXPORT static bool IsSupportArkDataDb();

	/**
     * @brief Checks whether the custom tokenizer is supported.
     *
     * @return Returns {@code true} if the custom tokenizer is supported; returns {@code false} otherwise.
     */
    API_EXPORT static bool IsSupportedTokenizer(Tokenizer tokenizer);

    struct DestroyOption {
        bool cleanOpenSSL = false;
        bool cleanICU = false;
    };
    /**
     * @brief initialization resources.
     *
     * @note Create pool initialization resources.
     */
    API_EXPORT static bool Init();

    /**
     * @brief Clean up resources before dlclose.
     *
     * @note This interface is only used to release resources before calling dlclose, and can only be called before
     * actually uninstalling rdb. Please manually release all resources obtained from rdb (rdbStore, resultSet,
     * transaction, etc.) before calling, and then dlopen again to use them normally
     */
    API_EXPORT static bool Destroy(const DestroyOption &option = { false, false });

    /**
     * @brief Obtaining the BundleName.
     *
     * @note Obtaining the BundleName from the Server.
     */
    API_EXPORT static std::string GetSelfBundleName();
};
} // namespace NativeRdb
} // namespace OHOS
#endif
