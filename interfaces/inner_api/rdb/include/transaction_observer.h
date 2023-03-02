/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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


#ifndef APPDATAMGR_TRANSACTION_OBSERVER_H
#define APPDATAMGR_TRANSACTION_OBSERVER_H

#include "rdb_visibility.h"

namespace OHOS {
namespace NativeRdb {
/**
 * The TransactionObserver class of RDB.
 */
class RDB_API_EXPORT TransactionObserver {
public:
    /**
     * @brief Destructor.
     */
    RDB_API_EXPORT virtual ~TransactionObserver() {}

    /**
     * @brief Begin transaction.
     */
    RDB_API_EXPORT virtual void OnBegin() const;

    /**
     * @brief Commit transaction.
     */
    RDB_API_EXPORT virtual void OnCommit() const;

    /**
     * @brief Rollback transaction.
     */
    RDB_API_EXPORT virtual void OnRollback() const;
};
} // namespace NativeRdb
} // namespace OHOS

#endif