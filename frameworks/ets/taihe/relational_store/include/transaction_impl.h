/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_RELATION_STORE_TRANSACTION_IMPL_H
#define OHOS_RELATION_STORE_TRANSACTION_IMPL_H

#include "ani_rdb_utils.h"
#include "lite_result_set_impl.h"
#include "lite_result_set_proxy.h"
#include "result_set_impl.h"
#include "result_set_proxy.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_predicates.h"
#include "rdb_predicates_impl.h"
#include "rdb_result_set_bridge.h"
#include "rdb_sql_utils.h"
#include "rdb_store_config.h"
#include "rdb_store_impl.h"
#include "rdb_types.h"
#include "rdb_utils.h"

namespace OHOS {
namespace RdbTaihe {
using namespace taihe;
using namespace ohos::data::relationalStore;
using namespace OHOS::RelationalStoreJsKit;
using RdbSqlUtils = OHOS::NativeRdb::RdbSqlUtils;
using namespace OHOS;
using namespace OHOS::Rdb;
using namespace OHOS::RdbTaihe;
using ValueType = ohos::data::relationalStore::ValueType;
using ValueObject = OHOS::NativeRdb::ValueObject;

class TransactionImpl {
public:
    TransactionImpl();
    explicit TransactionImpl(std::shared_ptr<OHOS::NativeRdb::Transaction> transaction);
    void CommitSync();
    void RollbackSync();
    int64_t InsertSync(
        string_view table, map_view<::taihe::string, ValueType> values, optional_view<ConflictResolution> conflict);
    int64_t BatchInsertSync(string_view table, array_view<map<string, ValueType>> values);
    int64_t UpdateSync(map_view<string, ValueType> values, weak::RdbPredicates predicates,
        optional_view<ConflictResolution> conflict);
    int64_t DeleteSync(weak::RdbPredicates predicates);
    ResultSet QuerySync(weak::RdbPredicates predicates, optional_view<array<string>> columns);
    ResultSet QuerySqlSync(string_view sql, optional_view<array<ValueType>> args);
    LiteResultSet QueryWithoutRowCountSync(weak::RdbPredicates predicates, optional_view<array<string>> columns);
    LiteResultSet QuerySqlWithoutRowCountSync(string_view sql, optional_view<array<ValueType>> args);
    ValueType ExecuteSync(string_view sql, optional_view<array<ValueType>> args);
    Result BatchInsertWithReturningSync(string_view table, array_view<ValuesBucket> values,
        ReturningConfig const &config, optional_view<ConflictResolution> conflict);
    Result UpdateWithReturningSync(ValuesBucket values, weak::RdbPredicates predicates,
        ReturningConfig const &config, optional_view<ConflictResolution> conflict);
    Result DeleteWithReturningSync(weak::RdbPredicates predicates, ReturningConfig const &config);
    int64_t BatchInsertWithConflictResolutionSync(taihe::string_view table,
        taihe::array_view<ohos::data::relationalStore::ValuesBucket> values,
        ohos::data::relationalStore::ConflictResolution conflict);

protected:
    std::shared_ptr<OHOS::NativeRdb::Transaction> nativeTransaction_ = nullptr;
};
}
}

#endif // OHOS_RELATION_STORE_TRANSACTION_IMPL_H