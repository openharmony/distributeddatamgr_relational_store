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

#ifndef NAPI_RDB_CONTEXT_H
#define NAPI_RDB_CONTEXT_H

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "abs_shared_result_set.h"
#include "napi_async_call.h"
#include "rdb_predicates.h"
#include "rdb_types.h"
#include "result_set.h"
#include "value_object.h"
#include "values_bucket.h"

namespace OHOS {
namespace RdbJsKit {

using BaseContext = AppDataMgrJsKit::BaseContext;
using ValuesBucket = OHOS::NativeRdb::ValuesBucket;
using ValueObject = OHOS::NativeRdb::ValueObject;
using AbsSharedResultSet = OHOS::NativeRdb::AbsSharedResultSet;
using ResultSet = OHOS::NativeRdb::ResultSet;
using RdbPredicates = OHOS::NativeRdb::RdbPredicates;

struct PredicatesProxy;
class RdbPredicatesProxy;

struct RdbStoreContext : public BaseContext {
    bool isNapiString = false;
    std::string device;
    std::string tableName;
    std::vector<std::string> tablesName;
    std::string whereClause;
    std::vector<std::string> whereArgs;
    std::vector<std::string> selectionArgs;
    std::string sql;
    RdbPredicatesProxy *predicatesProxy;
    std::vector<std::string> columns;
    ValuesBucket valuesBucket;
    std::vector<ValuesBucket> valuesBuckets;
    std::map<std::string, ValueObject> numberMaps;
    std::vector<ValueObject> bindArgs;
    int64_t rowId = -1;
    int64_t insertNum = -1;
    std::vector<uint8_t> newKey;
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    std::shared_ptr<AbsSharedResultSet> resultSet;
#else
    std::shared_ptr<ResultSet> resultSet;
#endif
    std::shared_ptr<ResultSet> stepResultSet;
    std::string aliasName;
    std::string pathName;
    std::string srcName;
    int32_t enumArg;
#if !defined(WINDOWS_PLATFORM) && !defined(MAC_PLATFORM)
    DistributedRdb::SyncResult syncResult;
#endif
    std::shared_ptr<RdbPredicates> rdbPredicates = nullptr;

    RdbStoreContext() : predicatesProxy(nullptr), rowId(0), insertNum(0), enumArg(0)
    {
    }
    virtual ~RdbStoreContext()
    {
    }
};

} // namespace RdbJsKit
} // namespace OHOS

#endif // NAPI_RDB_CONTEXT_H