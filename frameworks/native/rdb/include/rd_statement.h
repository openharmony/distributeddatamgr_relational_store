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

#include "rd_connection.h"
#include "rd_utils.h"
#include "rdb_statement.h"
#include "value_object.h"

namespace OHOS {
namespace NativeRdb {

class RdStatement : public RdbStatement {
public:
    RdStatement();
    ~RdStatement();
    static std::shared_ptr<RdStatement> CreateStatement(
        std::shared_ptr<RdConnection> connection, const std::string &sql);
    int Prepare(GRD_DB *db, const std::string &sql);
    int Finalize() override;
    int BindArguments(const std::vector<ValueObject> &bindArgs) const override;
    int ResetStatementAndClearBindings() const override;
    int Step() const override;

    int GetColumnCount(int &count) const override;
    int GetColumnName(int index, std::string &columnName) const override;
    int GetColumnType(int index, int &columnType) const override;
    int GetColumnBlob(int index, std::vector<uint8_t> &value) const override;
    int GetColumnString(int index, std::string &value) const override;
    int GetColumnInt(int index, int &value);
    int GetColumnLong(int index, int64_t &value) const override;
    int GetColumnDouble(int index, double &value) const override;
    int GetFloat32Array(int32_t index, std::vector<float> &vecs) const override;
    int GetSize(int index, size_t &size) const override;
    int GetColumn(int index, ValueObject &value) const override;
    bool IsReadOnly() const override;

private:
    int InnerBindArguments(const std::vector<ValueObject> &bindArgs) const;
    int InnerBindBlobTypeArgs(const ValueObject &bindArg, uint32_t index) const;

    int IsValid(int index) const;
    std::string sql_ = "";
    GRD_SqlStmt *stmtHandle_ = nullptr;
    int columnCount_ = 0;
};

} // namespace NativeRdb
} // namespace OHOS
#endif // NATIVE_RDB_RD_STATEMENT_H