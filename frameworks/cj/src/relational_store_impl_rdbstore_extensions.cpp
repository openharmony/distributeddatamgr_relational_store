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

using namespace OHOS::FFI;

namespace OHOS {
namespace Relational {

int64_t RdbStoreImpl::BatchInsertWithConflictResolution(const char *tableName, ValuesBucketEx *valuesBuckets,
    int64_t valuesSize, int32_t conflict, int32_t *errCode)
{
    if (rdbStore_ == nullptr || tableName == nullptr || valuesBuckets == nullptr) {
        *errCode = NativeRdb::E_ERROR;
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
    auto [ret, output] = rdbStore_->BatchInsert(tableName, buckets, conflictResolution);
    *errCode = ret;
    return output;
}

ValueTypeEx RdbStoreImpl::Execute(const char *sql, ValueTypeEx *bindArgs, int64_t bindArgsSize,
    int32_t *errCode)
{
    if (rdbStore_ == nullptr || sql == nullptr) {
        *errCode = NativeRdb::E_ERROR;
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
    std::tie(status, output) = rdbStore_->Execute(sql, args);
    *errCode = status;
    if (status != NativeRdb::E_OK) {
        return ValueTypeEx{};
    }
    return ValueObjectToValueTypeEx(output);
}

ValueTypeEx RdbStoreImpl::Execute(const char *sql, ValueTypeEx *bindArgs, int64_t bindArgsSize,
    int64_t txId, int32_t *errCode)
{
    if (rdbStore_ == nullptr || sql == nullptr) {
        *errCode = NativeRdb::E_ERROR;
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
    std::tie(status, output) = rdbStore_->Execute(sql, args, txId);
    *errCode = status;
    if (status != NativeRdb::E_OK) {
        return ValueTypeEx{};
    }
    return ValueObjectToValueTypeEx(output);
}

int64_t RdbStoreImpl::BeginTrans(int32_t *errCode)
{
    if (rdbStore_ == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }
    int32_t status = NativeRdb::E_ERROR;
    int64_t txId = 0;
    std::tie(status, txId) = rdbStore_->BeginTrans();
    *errCode = status;
    return txId;
}

int32_t RdbStoreImpl::Close()
{
    if (rdbStore_ == nullptr) {
        return NativeRdb::E_ALREADY_CLOSED;
    }
    std::unique_lock<std::mutex> lock(observerMutex_);
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

int32_t RdbStoreImpl::Attach(const char *fullPath, const char *attachName, int32_t waitTime, int32_t *errCode)
{
    if (rdbStore_ == nullptr || fullPath == nullptr || attachName == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }
    NativeRdb::RdbStoreConfig storeConfig(fullPath);
    auto [ret, attachedNum] = rdbStore_->Attach(storeConfig, attachName, waitTime);
    *errCode = ret;
    return attachedNum;
}

int32_t RdbStoreImpl::AttachConfig(OHOS::AbilityRuntime::Context *context, StoreConfigEx *config,
    const char *attachName, int32_t waitTime, int32_t *errCode)
{
    if (rdbStore_ == nullptr || context == nullptr || config == nullptr || attachName == nullptr) {
        *errCode = NativeRdb::E_ERROR;
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
    auto [ret, attachedNum] = rdbStore_->Attach(storeConfig, attachName, waitTime);
    *errCode = ret;
    return attachedNum;
}

int32_t RdbStoreImpl::Detach(const char *attachName, int32_t waitTime, int32_t *errCode)
{
    if (rdbStore_ == nullptr || attachName == nullptr) {
        *errCode = NativeRdb::E_ERROR;
        return -1;
    }
    auto [ret, attachedNum] = rdbStore_->Detach(attachName, waitTime);
    *errCode = ret;
    return attachedNum;
}
}
}