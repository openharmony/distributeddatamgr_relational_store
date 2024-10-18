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
#include "transaction.h"

#include "connection.h"
#include "rdb_errno.h"
#include "trans_db.h"
namespace OHOS::NativeRdb {
class TransactionImpl : public Transaction {
public:
    TransactionImpl(std::shared_ptr<Connection>, const std::string &name);
    int32_t Begin(int32_t type);
    int32_t Commit() override;
    int32_t Rollback() override;
    std::pair<int32_t, std::shared_ptr<RdbStore>> GetTransDB() override;
    int32_t Close() override;

private:
    std::string name_;
    std::shared_ptr<Connection> conn_;
};

std::pair<int32_t, std::shared_ptr<Transaction>> Transaction::Create(int32_t type, std::shared_ptr<Connection> conn,
    const std::string &name)
{
    if (type < DEFERRED || type >= TRANS_BUTT) {
        return { E_INVALID_ARGS, nullptr };
    }
    auto transImpl = std::make_shared<TransactionImpl>(conn, name);
    auto errCode = transImpl->Begin(type);
    if (errCode != E_OK) {
        return { errCode, nullptr };
    }
    return { E_OK, transImpl };
}

TransactionImpl::TransactionImpl(std::shared_ptr<Connection> conn, const std::string &name)
    : name_(name), conn_(std::move(conn))
{
}
int32_t TransactionImpl::Begin(int32_t type)
{
    if (type < DEFERRED || type >= TRANS_BUTT) {
        return E_INVALID_ARGS;
    }
    return E_OK;
}
int32_t TransactionImpl::Commit()
{
    return E_OK;
}
int32_t TransactionImpl::Rollback()
{
    return E_OK;
}

std::pair<int32_t, std::shared_ptr<RdbStore>> TransactionImpl::GetTransDB()
{
    auto store = std::make_shared<TransDB>(conn_, name_);
    return { E_OK, store };
}

int32_t TransactionImpl::Close()
{
    conn_ = nullptr;
    return 0;
}
} // namespace OHOS::NativeRdb