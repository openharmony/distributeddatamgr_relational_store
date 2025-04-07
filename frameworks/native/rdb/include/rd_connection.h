/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef NATIVE_RDB_RD_CONNECTION_H
#define NATIVE_RDB_RD_CONNECTION_H

#include <memory>
#include <mutex>
#include <vector>

#include "connection.h"
#include "rd_utils.h"
#include "rdb_common.h"
#include "rdb_store_config.h"
#include "value_object.h"

typedef struct ClientChangedData ClientChangedData;
namespace OHOS {
namespace NativeRdb {

class RdConnection : public Connection {
public:
    static std::pair<int32_t, std::shared_ptr<Connection>> Create(const RdbStoreConfig &config, bool isWrite);
    static int32_t Repair(const RdbStoreConfig &config);
    static int32_t Delete(const RdbStoreConfig &config);
    RdConnection(const RdbStoreConfig &config, bool isWriteConnection);
    ~RdConnection();
    int32_t VerifyAndRegisterHook(const RdbStoreConfig &config) override;
    std::pair<int32_t, Stmt> CreateStatement(const std::string &sql, SConn conn) override;
    int32_t GetDBType() const override;
    bool IsWriter() const override;
    bool IsInTrans() const override;
    int32_t ReSetKey(const RdbStoreConfig &config) override;
    int32_t TryCheckPoint(bool timeout) override;
    int32_t LimitWalSize() override;
    int32_t ConfigLocale(const std::string &localeStr) override;
    int32_t CleanDirtyData(const std::string &table, uint64_t cursor) override;
    int32_t SubscribeTableChanges(const Notifier &notifier) override;
    int32_t GetMaxVariable() const override;
    int32_t GetJournalMode() override;
    int32_t ClearCache() override;
    int32_t Subscribe(const std::shared_ptr<DistributedDB::StoreObserver> &observer) override;
    int32_t Unsubscribe(const std::shared_ptr<DistributedDB::StoreObserver> &observer) override;
    int32_t Backup(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey, bool isAsync,
        SlaveStatus &slaveStatus) override;
    int32_t Restore(const std::string &databasePath, const std::vector<uint8_t> &destEncryptKey,
        SlaveStatus &slaveStatus) override;
    ExchangeStrategy GenerateExchangeStrategy(const SlaveStatus &status) override;
    int SetKnowledgeSchema(const DistributedRdb::RdbKnowledgeSchema &schema) override;
    int CleanDirtyLog(const std::string &table, uint64_t cursor) override;

private:
    static void CheckConfig(std::shared_ptr<Connection> conn, const RdbStoreConfig &config);
    static void ExecuteSet(std::shared_ptr<Connection> conn, const std::string &paramName, int num);

    static constexpr int MAX_VARIABLE_NUM = 500;
    static constexpr const char *GRD_OPEN_CONFIG_STR =
        "\"pageSize\":8, \"crcCheckEnable\":0, \"redoFlushByTrx\":1, \"bufferPoolSize\":10240,"
        "\"sharedModeEnable\":1, \"metaInfoBak\":1, \"maxConnNum\":500";
    static constexpr uint32_t NO_ITER = 0;
    static constexpr uint32_t ITER_V1 = 5000;
    static constexpr uint32_t ITERS[] = { NO_ITER, ITER_V1 };
    static constexpr uint32_t ITERS_COUNT = sizeof(ITERS) / sizeof(ITERS[0]);
    static constexpr int NCANDIDATES_DEFAULT_NUM = 128;
    static const int32_t regCreator_;
    static const int32_t regRepairer_;
    static const int32_t regDeleter_;

    static std::string GetConfigStr(const std::vector<uint8_t> &keys, bool isEncrypt);
    std::string GetConfigStr(const std::vector<uint8_t> &keys);
    int InnerOpen(const RdbStoreConfig &config);
    bool isWriter_ = false;
    GRD_DB *dbHandle_ = nullptr;
    const RdbStoreConfig config_;
};

} // namespace NativeRdb
} // namespace OHOS
#endif // NATIVE_RDB_RD_CONNECTION_H
