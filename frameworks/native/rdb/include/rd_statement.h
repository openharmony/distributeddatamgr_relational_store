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

#ifndef NATIVE_RDB_RD_STATEMENT_H
#define NATIVE_RDB_RD_STATEMENT_H

#include <memory>
#include <vector>

#include "connection.h"
#include "rd_connection.h"
#include "rd_utils.h"
#include "rdb_store_config.h"
#include "statement.h"
#include "value_object.h"

namespace OHOS {
namespace NativeRdb {
class RdStatement final : public Statement {
public:
    RdStatement();
    ~RdStatement();
    int Finalize() override;
    int32_t Prepare(const std::string &sql) override;
    int32_t Bind(const std::vector<ValueObject> &args) override;
    std::pair<int32_t, int32_t> Count() override;
    int32_t Step() override;
    int32_t Reset() override;
    int32_t Execute(const std::vector<ValueObject> &args) override;
    int32_t Execute(const std::vector<std::reference_wrapper<ValueObject>> &args) override;
    std::pair<int, ValueObject> ExecuteForValue(const std::vector<ValueObject> &args) override;
    std::pair<int, std::vector<ValuesBucket>> ExecuteForRows(
        const std::vector<ValueObject> &args, int32_t maxCount) override;
    std::pair<int, std::vector<ValuesBucket>> ExecuteForRows(
        const std::vector<std::reference_wrapper<ValueObject>> &args, int32_t maxCount) override;
    int32_t Changes() const override;
    int64_t LastInsertRowId() const override;
    int32_t GetColumnCount() const override;
    std::pair<int32_t, std::string> GetColumnName(int32_t index) const override;
    std::pair<int32_t, int32_t> GetColumnType(int32_t index) const override;
    std::pair<int32_t, size_t> GetSize(int32_t index) const override;
    std::pair<int32_t, ValueObject> GetColumn(int32_t index) const override;
    bool ReadOnly() const override;
    bool SupportBlockInfo() const override;
    int32_t FillBlockInfo(SharedBlockInfo *info, int retiyTime = RETRY_TIME) const override;
    std::pair<int32_t, std::vector<ValuesBucket>> GetRows(int32_t maxCount) override;
    void GetProperties();

private:
    friend class RdConnection;
    int Prepare(GRD_DB *db, const std::string &sql);
    int32_t Bind(const std::vector<std::reference_wrapper<ValueObject>> &args);
    int InnerBindBlobTypeArgs(const ValueObject &bindArg, uint32_t index) const;
    int IsValid(int index) const;
    int PreGetColCount();

    bool readOnly_ = false;
    bool bound_ = false;
    bool isStepInPrepare_ = false;
    int stepCnt_ = 0;
    std::string sql_ = "";
    GRD_SqlStmt *stmtHandle_ = nullptr;
    GRD_DB *dbHandle_ = nullptr;
    std::shared_ptr<Connection> conn_;
    int columnCount_ = 0;

    std::map<std::string, std::function<int32_t(const int &value)>> setPragmas_;
    std::map<std::string, std::function<int32_t(int &version)>> getPragmas_;
    const RdbStoreConfig *config_ = nullptr;
};
} // namespace NativeRdb
} // namespace OHOS
#endif // NATIVE_RDB_RD_STATEMENT_H
