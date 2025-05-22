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

#ifndef NATIVE_RDB_TRANS_DB_H
#define NATIVE_RDB_TRANS_DB_H
#include <memory>

#include "connection.h"
#include "rdb_store.h"
#include "statement.h"
namespace OHOS::NativeRdb {
class TransDB : public RdbStore {
public:
    TransDB(std::shared_ptr<Connection> conn, const std::string &name);
    std::pair<int, int64_t> Insert(const std::string &table, const Row &row, Resolution resolution) override;
    std::pair<int, int64_t> BatchInsert(const std::string &table, const RefRows &rows) override;
    std::pair<int32_t, Results> BatchInsert(const std::string &table, const RefRows &rows,
        const std::vector<std::string> &returningFields, Resolution resolution) override;
    std::pair<int32_t, Results> Update(const Row &row, const AbsRdbPredicates &predicates,
        const std::vector<std::string> &returningFields, Resolution resolution) override;
    std::pair<int32_t, Results> Delete(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &returningFields) override;
    std::shared_ptr<AbsSharedResultSet> QuerySql(const std::string &sql, const Values &args) override;
    std::shared_ptr<ResultSet> QueryByStep(const std::string &sql, const Values &args, bool preCount) override;
    std::pair<int32_t, ValueObject> Execute(const std::string &sql, const Values &args, int64_t trxId) override;
    std::pair<int32_t, Results> ExecuteExt(const std::string &sql, const Values &args) override;
    int GetVersion(int &version) override;
    int SetVersion(int version) override;
    int Sync(const SyncOption &option, const std::vector<std::string> &tables, const AsyncDetail &async) override;

private:
    std::pair<int32_t, std::shared_ptr<Statement>> GetStatement(const std::string &sql) const;
    void HandleSchemaDDL(std::shared_ptr<Statement> statement);
    static inline constexpr uint32_t MAX_RETURNING_ROWS = 1024;
    static Results GenerateResult(int32_t code, std::shared_ptr<Statement> statement, bool isDML = true);
    static ValuesBuckets GetValues(std::shared_ptr<Statement> statement);

    int32_t maxArgs_ = 0;
    int64_t vSchema_ = 0;
    std::weak_ptr<Connection> conn_;
    std::string name_;
};
} // namespace OHOS::NativeRdb
#endif // NATIVE_RDB_TRANS_DB_H