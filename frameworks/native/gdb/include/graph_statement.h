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

#ifndef OHOS_DISTRIBUTED_DATA_NATIVE_GDB_GRAPH_STATEMENT_H
#define OHOS_DISTRIBUTED_DATA_NATIVE_GDB_GRAPH_STATEMENT_H

#ifndef JSON_NOEXCEPTION
#define JSON_NOEXCEPTION
#endif
#include "connection.h"
#include "grd_adapter.h"
#include "statement.h"

namespace OHOS::DistributedDataAip {
class GraphStatement final : public Statement {
public:
    GraphStatement(GRD_DB *db, const std::string &gql, std::shared_ptr<Connection> conn, int32_t &errCode);
    ~GraphStatement();

    int32_t Prepare() override;
    int32_t Step() override;
    int32_t Finalize() override;

    uint32_t GetColumnCount() const override;
    std::pair<int32_t, std::string> GetColumnName(int32_t index) const override;
    std::pair<int32_t, ColumnType> GetColumnType(int32_t index) const override;
    std::pair<int32_t, GraphValue> GetColumnValue(int32_t index) const override;

    bool IsReady() const override;

private:
    std::shared_ptr<Connection> conn_;
    std::string gql_;
    GRD_Stmt *stmtHandle_ = nullptr;
    GRD_DB *dbHandle_ = nullptr;
    static GraphValue ParseJsonStr(const std::string &jsonStr, int32_t &errCode) ;
};
} // namespace OHOS::DistributedDataAip
#endif //OHOS_DISTRIBUTED_DATA_NATIVE_GDB_GRAPH_STATEMENT_H
