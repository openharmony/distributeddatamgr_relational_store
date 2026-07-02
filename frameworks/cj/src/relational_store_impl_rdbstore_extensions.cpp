/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "relational_store_utils.h"
#include "rdb_store.h"
#include "rdb_errno.h"
#include "native_log.h"
#include "relational_store_impl_rdbstore.h"
#include "relational_store_impl_literesultset.h"
#include "relational_store_impl_transaction.h"

using namespace OHOS::FFI;

namespace OHOS {
namespace Relational {

int64_t RdbStoreImpl::BatchInsertWithConflictResolution(const char *tableName, ValuesBucketEx *valuesBuckets,
    int64_t valuesSize, int32_t conflict, int32_t *errCode)
{
    if (tableName == nullptr || valuesBuckets == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }
    auto store = GetRdbStore();
    if (store == nullptr) {
        *errCode = NativeRdb::E_ALREADY_CLOSED;
        return -1;
    }
    std::vector<NativeRdb::ValuesBucket> buckets;
    buckets.reserve(valuesSize);
    for (int64_t i = 0; i < valuesSize; ++i) {
        NativeRdb::ValuesBucket bucket;
        for (int64_t j = 0; j < valuesBuckets[i].size; ++j) {
            NativeRdb::ValueObject valueObj = ValueTypeExToValueObject(valuesBuckets[i].value[j]);
            bucket.Put(valuesBuckets[i].key[j], valueObj);
        }
        buckets.push_back(std::move(bucket));
    }
    auto conflictResolution = static_cast<NativeRdb::ConflictResolution>(conflict);
    auto [ret, output] = store->BatchInsert(tableName, buckets, conflictResolution);
    *errCode = ret;
    return output;
}

ValueTypeEx RdbStoreImpl::Execute(const char *sql, ValueTypeEx *bindArgs, int64_t bindArgsSize,
    int32_t *errCode)
{
    if (sql == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return ValueTypeEx{};
    }
    auto store = GetRdbStore();
    if (store == nullptr) {
        *errCode = NativeRdb::E_ALREADY_CLOSED;
        return ValueTypeEx{};
    }
    std::vector<NativeRdb::ValueObject> args;
    if (bindArgs != nullptr && bindArgsSize > 0) {
        args.reserve(bindArgsSize);
        for (int64_t i = 0; i < bindArgsSize; ++i) {
            args.push_back(ValueTypeExToValueObject(bindArgs[i]));
        }
    }
    int32_t status = NativeRdb::E_ERROR;
    NativeRdb::ValueObject output;
    std::tie(status, output) = store->Execute(sql, args);
    *errCode = status;
    if (status != NativeRdb::E_OK) {
        return ValueTypeEx{};
    }
    return ValueObjectToValueTypeEx(output);
}

ValueTypeEx RdbStoreImpl::Execute(const char *sql, ValueTypeEx *bindArgs, int64_t bindArgsSize,
    int64_t txId, int32_t *errCode)
{
    if (sql == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return ValueTypeEx{};
    }
    auto store = GetRdbStore();
    if (store == nullptr) {
        *errCode = NativeRdb::E_ALREADY_CLOSED;
        return ValueTypeEx{};
    }
    std::vector<NativeRdb::ValueObject> args;
    if (bindArgs != nullptr && bindArgsSize > 0) {
        args.reserve(bindArgsSize);
        for (int64_t i = 0; i < bindArgsSize; ++i) {
            args.push_back(ValueTypeExToValueObject(bindArgs[i]));
        }
    }
    int32_t status = NativeRdb::E_ERROR;
    NativeRdb::ValueObject output;
    std::tie(status, output) = store->Execute(sql, args, txId);
    *errCode = status;
    if (status != NativeRdb::E_OK) {
        return ValueTypeEx{};
    }
    return ValueObjectToValueTypeEx(output);
}

int64_t RdbStoreImpl::BeginTrans(int32_t *errCode)
{
    auto store = GetRdbStore();
    if (store == nullptr) {
        *errCode = NativeRdb::E_ALREADY_CLOSED;
        return -1;
    }
    int32_t status = NativeRdb::E_ERROR;
    int64_t txId = 0;
    std::tie(status, txId) = store->BeginTrans();
    *errCode = status;
    return txId;
}

int32_t RdbStoreImpl::Close()
{
    std::unique_lock<std::mutex> lock(observerMutex_);
    if (rdbStore_ == nullptr) {
        return NativeRdb::E_ALREADY_CLOSED;
    }
    for (int32_t mode = DistributedRdb::REMOTE; mode < DistributedRdb::SUBSCRIBE_MODE_MAX; mode++) {
        for (auto &obs : observers_[mode]) {
            if (obs == nullptr) {
                continue;
            }
            rdbStore_->UnSubscribe({ static_cast<DistributedRdb::SubscribeMode>(mode) }, obs);
        }
        observers_[mode].clear();
    }
    for (auto &obs : observers_[DistributedRdb::LOCAL_DETAIL]) {
        if (obs == nullptr) {
            continue;
        }
        rdbStore_->UnsubscribeObserver({ DistributedRdb::LOCAL_DETAIL }, obs);
    }
    observers_[DistributedRdb::LOCAL_DETAIL].clear();
    for (const auto &[event, obsList] : localObservers_) {
        for (const auto &obs : obsList) {
            if (obs == nullptr) {
                continue;
            }
            rdbStore_->UnSubscribe({ DistributedRdb::LOCAL, event }, obs);
        }
    }
    localObservers_.clear();
    for (const auto &[event, obsList] : localSharedObservers_) {
        for (const auto &obs : obsList) {
            if (obs == nullptr) {
                continue;
            }
            rdbStore_->UnSubscribe({ DistributedRdb::LOCAL_SHARED, event }, obs);
        }
    }
    localSharedObservers_.clear();
    for (const auto &obs : syncObservers_) {
        rdbStore_->UnregisterAutoSyncCallback(obs);
    }
    syncObservers_.clear();
    rdbStore_ = nullptr;
    return NativeRdb::E_OK;
}

ReturningResult RdbStoreImpl::BatchInsertWithReturning(const char *tableName, ValuesBucketEx *valuesBuckets,
    int64_t valuesSize, ReturningConfig config, int32_t conflict, int32_t *errCode)
{
    ReturningResult result = { 0, 0, NativeRdb::E_ERROR };
    if (tableName == nullptr || valuesBuckets == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return result;
    }
    auto store = GetRdbStore();
    if (store == nullptr) {
        *errCode = NativeRdb::E_ALREADY_CLOSED;
        return result;
    }
    if (!IsValidTableName(tableName)) {
        *errCode = NativeRdb::E_INVALID_ARGS_NEW;
        return result;
    }
    NativeRdb::ValuesBuckets rows;
    rows.Reserve(valuesSize);
    for (int64_t i = 0; i < valuesSize; ++i) {
        NativeRdb::ValuesBucket bucket;
        for (int64_t j = 0; j < valuesBuckets[i].size; ++j) {
            NativeRdb::ValueObject valueObj = ValueTypeExToValueObject(valuesBuckets[i].value[j]);
            bucket.Put(valuesBuckets[i].key[j], std::move(valueObj));
        }
        rows.Put(std::move(bucket));
    }
    auto nativeConfig = CReturningConfigToNative(config);
    auto conflictResolution = static_cast<NativeRdb::ConflictResolution>(conflict);
    auto [ret, results] = store->BatchInsert(tableName, rows, nativeConfig, conflictResolution);
    *errCode = ret;
    if (ret != NativeRdb::E_OK) {
        return result;
    }
    result.changed = results.changed;
    if (results.results != nullptr) {
        auto liteResultSet = FFIData::Create<LiteResultSetImpl>(results.results);
        if (liteResultSet != nullptr) {
            result.resultSetId = liteResultSet->GetID();
        }
    }
    result.errCode = NativeRdb::E_OK;
    return result;
}

ReturningResult RdbStoreImpl::UpdateWithReturning(ValuesBucketEx valuesBucket, RdbPredicatesImpl &predicates,
    ReturningConfig config, int32_t conflict, int32_t *errCode)
{
    ReturningResult result = { 0, 0, NativeRdb::E_ERROR };
    auto store = GetRdbStore();
    if (store == nullptr) {
        *errCode = NativeRdb::E_ALREADY_CLOSED;
        return result;
    }
    NativeRdb::ValuesBucket row;
    for (int64_t i = 0; i < valuesBucket.size; ++i) {
        NativeRdb::ValueObject valueObj = ValueTypeExToValueObject(valuesBucket.value[i]);
        row.Put(valuesBucket.key[i], std::move(valueObj));
    }
    auto nativeConfig = CReturningConfigToNative(config);
    auto conflictResolution = static_cast<NativeRdb::ConflictResolution>(conflict);
    auto [ret, results] = store->Update(row, *predicates.GetPredicates(), nativeConfig, conflictResolution);
    *errCode = ret;
    if (ret != NativeRdb::E_OK) {
        return result;
    }
    result.changed = results.changed;
    if (results.results != nullptr) {
        auto liteResultSet = FFIData::Create<LiteResultSetImpl>(results.results);
        if (liteResultSet != nullptr) {
            result.resultSetId = liteResultSet->GetID();
        }
    }
    result.errCode = NativeRdb::E_OK;
    return result;
}

ReturningResult RdbStoreImpl::DeleteWithReturning(RdbPredicatesImpl &predicates, ReturningConfig config,
    int32_t *errCode)
{
    ReturningResult result = { 0, 0, NativeRdb::E_ERROR };
    auto store = GetRdbStore();
    if (store == nullptr) {
        *errCode = NativeRdb::E_ALREADY_CLOSED;
        return result;
    }
    auto nativeConfig = CReturningConfigToNative(config);
    auto [ret, results] = store->Delete(*predicates.GetPredicates(), nativeConfig);
    *errCode = ret;
    if (ret != NativeRdb::E_OK) {
        return result;
    }
    result.changed = results.changed;
    if (results.results != nullptr) {
        auto liteResultSet = FFIData::Create<LiteResultSetImpl>(results.results);
        if (liteResultSet != nullptr) {
            result.resultSetId = liteResultSet->GetID();
        }
    }
    result.errCode = NativeRdb::E_OK;
    return result;
}

int64_t RdbStoreImpl::QueryWithoutRowCount(RdbPredicatesImpl &predicates, char **columns,
    int64_t columnsSize, int32_t *errCode)
{
    auto store = GetRdbStore();
    if (store == nullptr) {
        *errCode = NativeRdb::E_ALREADY_CLOSED;
        return -1;
    }
    std::vector<std::string> cols;
    if (columns != nullptr && columnsSize > 0) {
        cols.reserve(columnsSize);
        for (int64_t i = 0; i < columnsSize; ++i) {
            cols.push_back(columns[i]);
        }
    }
    DistributedRdb::QueryOptions options{.preCount = false, .isGotoNextRowReturnLastError = true};
    auto resultSet = store->QueryByStep(*predicates.GetPredicates(), cols, options);
    if (resultSet == nullptr) {
        *errCode = NativeRdb::E_ALREADY_CLOSED;
        return -1;
    }
    auto liteResultSet = FFIData::Create<LiteResultSetImpl>(resultSet);
    if (liteResultSet == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }
    *errCode = NativeRdb::E_OK;
    return liteResultSet->GetID();
}

int64_t RdbStoreImpl::QuerySqlWithoutRowCount(const char *sql, ValueTypeEx *bindArgs,
    int64_t size, int32_t *errCode)
{
    if (sql == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }
    auto store = GetRdbStore();
    if (store == nullptr) {
        *errCode = NativeRdb::E_ALREADY_CLOSED;
        return -1;
    }
    std::vector<NativeRdb::ValueObject> args;
    if (bindArgs != nullptr && size > 0) {
        args.reserve(size);
        for (int64_t i = 0; i < size; ++i) {
            args.push_back(ValueTypeExToValueObject(bindArgs[i]));
        }
    }
    DistributedRdb::QueryOptions options{.preCount = false, .isGotoNextRowReturnLastError = true};
    auto resultSet = store->QueryByStep(sql, args, options);
    if (resultSet == nullptr) {
        *errCode = NativeRdb::E_ALREADY_CLOSED;
        return -1;
    }
    auto liteResultSet = FFIData::Create<LiteResultSetImpl>(resultSet);
    if (liteResultSet == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }
    *errCode = NativeRdb::E_OK;
    return liteResultSet->GetID();
}

int64_t RdbStoreImpl::CreateTransaction(int32_t transactionType, int32_t *errCode)
{
    auto store = GetRdbStore();
    if (store == nullptr) {
        *errCode = NativeRdb::E_ALREADY_CLOSED;
        return -1;
    }
    int32_t code = NativeRdb::E_ERROR;
    std::shared_ptr<NativeRdb::Transaction> transaction;
    std::tie(code, transaction) = store->CreateTransaction(transactionType);
    *errCode = code;
    if (code != NativeRdb::E_OK || transaction == nullptr) {
        return -1;
    }
    auto transactionImpl = FFIData::Create<TransactionImpl>(transaction);
    if (transactionImpl == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }
    return transactionImpl->GetID();
}

int32_t RdbStoreImpl::Attach(const char *fullPath, const char *attachName, int32_t waitTime, int32_t *errCode)
{
    if (fullPath == nullptr || attachName == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }
    auto store = GetRdbStore();
    if (store == nullptr) {
        *errCode = NativeRdb::E_ALREADY_CLOSED;
        return -1;
    }
    if (waitTime < 1 || waitTime > RdbStoreImpl::WAIT_TIME_LIMIT) {
        *errCode = NativeRdb::E_INVALID_ARGS_NEW;
        return -1;
    }
    NativeRdb::RdbStoreConfig storeConfig(fullPath);
    auto [ret, attachedNum] = store->Attach(storeConfig, attachName, waitTime);
    *errCode = ret;
    return attachedNum;
}

int32_t RdbStoreImpl::AttachConfig(OHOS::AbilityRuntime::Context *context, StoreConfigEx *config,
    const char *attachName, int32_t waitTime, int32_t *errCode)
{
    if (context == nullptr || config == nullptr || attachName == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }
    auto store = GetRdbStore();
    if (store == nullptr) {
        *errCode = NativeRdb::E_ALREADY_CLOSED;
        return -1;
    }
    if (waitTime < 1 || waitTime > RdbStoreImpl::WAIT_TIME_LIMIT) {
        *errCode = NativeRdb::E_INVALID_ARGS_NEW;
        return -1;
    }
    // shared_from_this() shares the existing control block for correct ref-counting;
    // context validity is guaranteed by upstream callers.
    auto abilityContext = std::make_shared<AppDataMgrJsKit::Context>(context->shared_from_this());
    OHOS::AppDataMgrJsKit::JSUtils::ContextParam param;
    initContextParam(param, abilityContext);
    OHOS::AppDataMgrJsKit::JSUtils::RdbConfig rdbConfig;
    initRdbConfigEx(rdbConfig, *config);
    *errCode = GetRealPath(rdbConfig, param, abilityContext);
    if (*errCode != NativeRdb::E_OK) {
        return -1;
    }
    NativeRdb::RdbStoreConfig storeConfig = getRdbStoreConfigEx(rdbConfig, param);
    auto [ret, attachedNum] = store->Attach(storeConfig, attachName, waitTime);
    *errCode = ret;
    return attachedNum;
}

int32_t RdbStoreImpl::Detach(const char *attachName, int32_t waitTime, int32_t *errCode)
{
    if (attachName == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }
    auto store = GetRdbStore();
    if (store == nullptr) {
        *errCode = NativeRdb::E_ALREADY_CLOSED;
        return -1;
    }
    if (waitTime < 1 || waitTime > RdbStoreImpl::WAIT_TIME_LIMIT) {
        *errCode = NativeRdb::E_INVALID_ARGS_NEW;
        return -1;
    }
    auto [ret, attachedNum] = store->Detach(attachName, waitTime);
    *errCode = ret;
    return attachedNum;
}
}
}