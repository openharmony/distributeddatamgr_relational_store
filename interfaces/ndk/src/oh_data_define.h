/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OH_DATA_DEFINE_H
#define OH_DATA_DEFINE_H

#include <cstdint>
#include <vector>

#include "oh_cursor.h"
#include "oh_predicates.h"
#include "oh_rdb_transaction.h"
#include "oh_values_bucket.h"
#include "rdb_store_config.h"
#include "transaction.h"
#include "value_object.h"
struct OH_Rdb_Transaction {
    static constexpr int64_t OH_RDB_TRANS_ID = 0x10000000;
    int64_t id = OH_RDB_TRANS_ID;

    std::shared_ptr<OHOS::NativeRdb::Transaction> trans_;
    bool IsValid() const;
};

struct OH_RDB_TransOptions {
    static constexpr int64_t OH_TRANS_OPTION_ID = 0x10001000;
    int64_t id = OH_TRANS_OPTION_ID;

    OH_RDB_TransType type_;
    bool IsValid() const;
};

struct OH_Data_Value {
    static constexpr int64_t OH_VALUE_ID = 0x10002000;
    int64_t id = OH_VALUE_ID;

    OHOS::NativeRdb::ValueObject value_;
    bool IsValid() const;
};

struct OH_Data_Values {
    static constexpr int64_t OH_VALUES_ID = 0x10003000;
    int64_t id = OH_VALUES_ID;

    std::vector<OH_Data_Value> values_;
    bool IsValid() const;
};

struct OH_Data_VBuckets {
    static constexpr int64_t OH_VBUCKETS_ID = 0x10004000;
    int64_t id = OH_VBUCKETS_ID;

    std::vector<OH_VBucket *> rows_;
    bool IsValid() const;
};

struct OH_Rdb_CryptoParam {
    static constexpr int64_t OH_CRYPTO_PARAM_ID = 0x10005000;
    int64_t id = OH_CRYPTO_PARAM_ID;

    OHOS::NativeRdb::RdbStoreConfig::CryptoParam cryptoParam;
    bool IsValid() const;
};

struct OH_RDB_ReturningContext {
    static constexpr int64_t OH_CRYPTO_PARAM_ID = 0x10006000;
    int64_t id = OH_CRYPTO_PARAM_ID;
    int64_t changed = -1;
    OH_Cursor *cursor = nullptr;
    OHOS::NativeRdb::ReturningConfig config;
    bool IsValid() const;
};
#endif
