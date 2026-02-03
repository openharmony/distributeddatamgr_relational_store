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

#ifndef OHOS_RELATION_STORE_RELATION_STORE_IMPL_H
#define OHOS_RELATION_STORE_RELATION_STORE_IMPL_H

#include "ohos.data.relationalStore.impl.hpp"

#include "abs_rdb_predicates.h"
#include "ani_rdb_utils.h"
#include "ani_utils.h"
#include "datashare_abs_predicates.h"
#include "js_proxy.h"
#include "logger.h"
#include "napi_rdb_js_utils.h"
#include "ohos.data.relationalStore.proj.hpp"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_predicates.h"
#include "rdb_result_set_bridge.h"
#include "rdb_sql_utils.h"
#include "rdb_store_config.h"
#include "rdb_types.h"
#include "rdb_utils.h"
#include "result_set_bridge.h"
#include "stdexcept"
#include "taihe/runtime.hpp"
#include "lite_result_set_impl.h"
#include "lite_result_set_proxy.h"
#include "rdb_predicates_impl.h"
#include "rdb_store_impl.h"
#include "result_set_impl.h"
#include "result_set_proxy.h"
#include "transaction_impl.h"
#include "error_throw_utils.h"

namespace OHOS {
namespace RdbTaihe {
using namespace taihe;
using namespace ohos::data::relationalStore;
using namespace OHOS::RelationalStoreJsKit;
using RdbSqlUtils =  OHOS::NativeRdb::RdbSqlUtils;
using namespace OHOS;
using namespace OHOS::Rdb;
using namespace OHOS::RdbTaihe;
using ValueType = ohos::data::relationalStore::ValueType;
using ValueObject = OHOS::NativeRdb::ValueObject;

static constexpr int ERR_NULL = -1;
static constexpr int INIT_POSITION = -1;

template <class T>
Result BatchInsertWithReturning(std::shared_ptr<T> store, string_view table,
    array_view<ValuesBucket> values, ReturningConfig const &config,
    optional_view<ConflictResolution> conflict)
{
    Result returnVal = { -1, make_holder<LiteResultSetImpl, LiteResultSet>() };
    ASSERT_RETURN_THROW_ERROR(
        store != nullptr, std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), returnVal);
    ASSERT_RETURN_THROW_ERROR(RdbSqlUtils::IsValidTableName(std::string(table)),
        std::make_shared<InnerError>(OHOS::NativeRdb::E_INVALID_ARGS_NEW, "Illegal table name"), returnVal);
    auto buckets = ani_rdbutils::ValueBucketsToNative(values);
    ASSERT_RETURN_THROW_ERROR(buckets.RowSize() != 0,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_INVALID_ARGS_NEW, "ValuesBuckets is invalid."), returnVal);
    ASSERT_RETURN_THROW_ERROR(!RdbSqlUtils::HasDuplicateAssets(buckets),
        std::make_shared<InnerError>(OHOS::NativeRdb::E_INVALID_ARGS_NEW, "Duplicate assets are not allowed"),
        returnVal);
    auto nativeConfig = ani_rdbutils::ReturningConfigToNative(config);
    nativeConfig.columns = RdbSqlUtils::BatchTrim(nativeConfig.columns);
    ASSERT_RETURN_THROW_ERROR(RdbSqlUtils::IsValidFields(nativeConfig.columns),
        std::make_shared<InnerError>(OHOS::NativeRdb::E_INVALID_ARGS_NEW, "Illegal columns."), returnVal);
    ASSERT_RETURN_THROW_ERROR(RdbSqlUtils::IsValidReturningMaxCount(nativeConfig.maxReturningCount),
        std::make_shared<InnerError>(
            OHOS::NativeRdb::E_INVALID_ARGS_NEW, "MaxReturningcount is not within the valid range."), returnVal);
    auto nativeConflict = OHOS::NativeRdb::ConflictResolution::ON_CONFLICT_NONE;
    if (conflict.has_value()) {
        nativeConflict = (OHOS::NativeRdb::ConflictResolution)conflict.value().get_key();
    }
    auto [errCode, result] =
        store->BatchInsert(std::string(table), buckets, nativeConfig, nativeConflict);
    ASSERT_RETURN_THROW_ERROR(errCode == OHOS::NativeRdb::E_OK, std::make_shared<InnerError>(errCode), returnVal);
    return { result.changed, make_holder<LiteResultSetImpl, LiteResultSet>(result.results) };
}

template <class T>
Result UpdateWithReturning(std::shared_ptr<T> store, ValuesBucket values,
    weak::RdbPredicates predicates, ReturningConfig const &config, optional_view<ConflictResolution> conflict)
{
    Result returnVal = { -1, make_holder<LiteResultSetImpl, LiteResultSet>() };
    ASSERT_RETURN_THROW_ERROR(
        store != nullptr, std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), returnVal);
    auto bucket = ani_rdbutils::ValueBucketToNative(values);
    ASSERT_RETURN_THROW_ERROR(bucket.Size() != 0,
        std::make_shared<InnerError>(OHOS::NativeRdb::E_INVALID_ARGS_NEW, "ValuesBucket is invalid."), returnVal);
    ASSERT_RETURN_THROW_ERROR(!RdbSqlUtils::HasDuplicateAssets(bucket),
        std::make_shared<InnerError>(OHOS::NativeRdb::E_INVALID_ARGS_NEW, "Duplicate assets are not allowed"),
        returnVal);
    auto *impl = reinterpret_cast<RdbPredicatesImpl *>(predicates->GetSpecificImplPtr());
    ASSERT_RETURN_THROW_ERROR(
        impl != nullptr, std::make_shared<ParamError>("predicates", "an RdbPredicates."), returnVal);
    std::shared_ptr<OHOS::NativeRdb::RdbPredicates> rdbPredicateNative = impl->GetNativePtr();
    ASSERT_RETURN_THROW_ERROR(
        rdbPredicateNative != nullptr, std::make_shared<ParamError>("predicates", "an RdbPredicates."), returnVal);
    ASSERT_RETURN_THROW_ERROR(RdbSqlUtils::IsValidTableName(rdbPredicateNative->GetTableName()),
            std::make_shared<InnerError>(OHOS::NativeRdb::E_INVALID_ARGS_NEW, "Illegal table name"), returnVal);
    auto nativeConfig = ani_rdbutils::ReturningConfigToNative(config);
    nativeConfig.columns = RdbSqlUtils::BatchTrim(nativeConfig.columns);
    ASSERT_RETURN_THROW_ERROR(RdbSqlUtils::IsValidFields(nativeConfig.columns),
        std::make_shared<InnerError>(OHOS::NativeRdb::E_INVALID_ARGS_NEW, "Illegal columns."), returnVal);
    ASSERT_RETURN_THROW_ERROR(RdbSqlUtils::IsValidReturningMaxCount(nativeConfig.maxReturningCount),
        std::make_shared<InnerError>(
            OHOS::NativeRdb::E_INVALID_ARGS_NEW, "MaxReturningcount is not within the valid range."), returnVal);
    auto nativeConflict = OHOS::NativeRdb::ConflictResolution::ON_CONFLICT_NONE;
    if (conflict.has_value()) {
        nativeConflict = (OHOS::NativeRdb::ConflictResolution)conflict.value().get_key();
    }
    auto [errCode, result] = store->Update(bucket, *rdbPredicateNative, nativeConfig, nativeConflict);
    ASSERT_RETURN_THROW_ERROR(errCode == OHOS::NativeRdb::E_OK, std::make_shared<InnerError>(errCode), returnVal);
    return { result.changed, make_holder<LiteResultSetImpl, LiteResultSet>(result.results) };
}

template <class T>
Result DeleteWithReturning(std::shared_ptr<T> store, weak::RdbPredicates predicates, ReturningConfig const &config)
{
    Result returnVal = { -1, make_holder<LiteResultSetImpl, LiteResultSet>() };
    ASSERT_RETURN_THROW_ERROR(
        store != nullptr, std::make_shared<InnerError>(OHOS::NativeRdb::E_ALREADY_CLOSED), returnVal);
    auto *impl = reinterpret_cast<RdbPredicatesImpl *>(predicates->GetSpecificImplPtr());
    ASSERT_RETURN_THROW_ERROR(
        impl != nullptr, std::make_shared<ParamError>("predicates", "an RdbPredicates."), returnVal);
    std::shared_ptr<OHOS::NativeRdb::RdbPredicates> rdbPredicateNative = impl->GetNativePtr();
    ASSERT_RETURN_THROW_ERROR(
        rdbPredicateNative != nullptr, std::make_shared<ParamError>("predicates", "an RdbPredicates."), returnVal);
    ASSERT_RETURN_THROW_ERROR(RdbSqlUtils::IsValidTableName(rdbPredicateNative->GetTableName()),
        std::make_shared<InnerError>(OHOS::NativeRdb::E_INVALID_ARGS_NEW, "Illegal table name"), returnVal);
    auto nativeConfig = ani_rdbutils::ReturningConfigToNative(config);
    nativeConfig.columns = RdbSqlUtils::BatchTrim(nativeConfig.columns);
    ASSERT_RETURN_THROW_ERROR(RdbSqlUtils::IsValidFields(nativeConfig.columns),
        std::make_shared<InnerError>(OHOS::NativeRdb::E_INVALID_ARGS_NEW, "Illegal columns."), returnVal);
    ASSERT_RETURN_THROW_ERROR(RdbSqlUtils::IsValidReturningMaxCount(nativeConfig.maxReturningCount),
        std::make_shared<InnerError>(
            OHOS::NativeRdb::E_INVALID_ARGS_NEW, "MaxReturningcount is not within the valid range."), returnVal);
    auto [errCode, result] = store->Delete(*rdbPredicateNative, nativeConfig);
    ASSERT_RETURN_THROW_ERROR(errCode == OHOS::NativeRdb::E_OK, std::make_shared<InnerError>(errCode), returnVal);
    return { result.changed, make_holder<LiteResultSetImpl, LiteResultSet>(result.results) };
}
}
}

#endif // OHOS_RELATION_STORE_RELATION_STORE_IMPL_H