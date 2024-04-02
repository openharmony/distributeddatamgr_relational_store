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

#include <mutex>
#include <memory>
#include <vector>

#include "rd_utils.h"
#include "rdb_connection.h"
#include "rdb_statement.h"
#include "rdb_store_config.h"
#include "sqlite_statement.h"
#include "value_object.h"
#include "shared_block.h"

typedef struct ClientChangedData ClientChangedData;
namespace OHOS {
namespace NativeRdb {

class RdConnection : public RdbConnection {
public:
    static std::shared_ptr<RdConnection> Open(const RdbStoreConfig &config, bool isWriteConnection, int &errCode);
    explicit RdConnection(bool isWriteConnection);
    ~RdConnection();
    int Prepare(const std::string &sql, bool &outIsReadOnly) override;
    int ExecuteSql(
        const std::string &sql, const std::vector<ValueObject> &bindArgs) override;

    std::shared_ptr<RdbStatement> BeginStepQuery(int &errCode, const std::string &sql,
        const std::vector<ValueObject> &args) const override;
    int DesFinalize() override;
    int EndStepQuery() override;

    void SetInTransaction(bool transaction) override;
    bool IsInTransaction() override;
    GRD_DB *GetDbHandle()
    {
        return dbHandle_;
    }
private:
    static constexpr const char *GRD_OPEN_CONFIG_STR = "{\"pageSize\":16, \"redoFlushByTrx\":1}";

    int PrepareAndBind(const std::string &sql, const std::vector<ValueObject> &bindArgs);
    int InnerOpen(const RdbStoreConfig &config);
    GRD_DB *dbHandle_ = nullptr;
    bool inTransaction_;
    std::string configStr_ = GRD_OPEN_CONFIG_STR;
};

} // namespace NativeRdb
} // namespace OHOS
#endif // NATIVE_RDB_RD_CONNECTION_H
