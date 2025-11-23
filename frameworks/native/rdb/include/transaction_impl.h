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
#ifndef NATIVE_RDB_TRANSACTION_IMPL_H
#define NATIVE_RDB_TRANSACTION_IMPL_H

#include <memory>
#include <mutex>
#include <vector>

#include "connection.h"
#include "transaction.h"

namespace OHOS::NativeRdb {
class RdbStore;
class TransactionImpl : public Transaction {
public:
    TransactionImpl(std::shared_ptr<Connection> connection, const std::string &path);
    ~TransactionImpl() override;

    int32_t Commit() override;
    int32_t Rollback() override;
    int32_t Close() override;

    std::pair<int32_t, int64_t> Insert(const std::string &table, const Row &row, Resolution resolution) override;
    std::pair<int32_t, int64_t> BatchInsert(const std::string &table, const Rows &rows) override;
    std::pair<int32_t, int64_t> BatchInsert(const std::string &table, const RefRows &rows) override;
    std::pair<int32_t, Results> BatchInsert(const std::string &table, const RefRows &rows,
        const std::vector<std::string> &returningFields, Resolution resolution) override;
    std::pair<int32_t, Results> Update(const Row &row, const AbsRdbPredicates &predicates,
        const std::vector<std::string> &returningFields, Resolution resolution) override;
    std::pair<int32_t, Results> Delete(
        const AbsRdbPredicates &predicates, const std::vector<std::string> &returningFields) override;
    std::shared_ptr<ResultSet> QueryByStep(const std::string &sql, const Values &args, bool preCount) override;
    std::shared_ptr<ResultSet> QueryByStep(const std::string &sql, const Values &args,
        const QueryOptions &options) override;
    std::shared_ptr<ResultSet> QueryByStep(const AbsRdbPredicates &predicates, const Fields &columns,
        bool preCount) override;
    std::shared_ptr<ResultSet> QueryByStep(const AbsRdbPredicates &predicates, const Fields &columns,
        const QueryOptions &options) override;
    std::pair<int32_t, ValueObject> Execute(const std::string &sql, const Values &args) override;
    std::pair<int32_t, Results> ExecuteExt(const std::string &sql, const Values &args) override;
    static std::pair<int32_t, std::shared_ptr<Transaction>> Create(
        int32_t type, std::shared_ptr<Connection> connection, const std::string &path);

private:
    static std::string GetBeginSql(int32_t type);
    int32_t Begin(int32_t type);
    int32_t CloseInner(bool connRecycle = true);
    std::shared_ptr<RdbStore> GetStore();
    void AddResultSet(std::weak_ptr<ResultSet> resultSet);

    std::string path_;
    uint32_t seqId_ = 0;
    std::recursive_mutex mutex_;
    std::shared_ptr<RdbStore> store_;
    std::shared_ptr<Connection> connection_;
    std::vector<std::weak_ptr<ResultSet>> resultSets_;

    static const int32_t regCreator_;
    static constexpr char COMMIT_SQL[] = "COMMIT;";
    static constexpr char ROLLBACK_SQL[] = "ROLLBACK;";
    static constexpr const char *BEGIN_SQLS[] = { "BEGIN DEFERRED;", "BEGIN IMMEDIATE;", "BEGIN EXCLUSIVE;" };
};
} // namespace OHOS::NativeRdb
#endif
