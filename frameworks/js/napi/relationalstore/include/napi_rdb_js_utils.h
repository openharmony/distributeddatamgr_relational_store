/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef RDB_JSKIT_NAPI_RDB_JS_UTILS_H
#define RDB_JSKIT_NAPI_RDB_JS_UTILS_H

#include "asset_value.h"
#include "js_utils.h"
#include "napi_rdb_store_observer.h"
#include "result_set.h"
#include "value_object.h"
#include "rdb_types.h"

namespace OHOS::AppDataMgrJsKit {
namespace JSUtils {
using Asset = OHOS::NativeRdb::AssetValue;
using RowEntity = OHOS::NativeRdb::RowEntity;
using ValueObject = OHOS::NativeRdb::ValueObject;
using Date = OHOS::DistributedRdb::Date;
using JSChangeInfo = OHOS::RelationalStoreJsKit::NapiRdbStoreObserver::JSChangeInfo;
using PRIKey = OHOS::DistributedRdb::RdbStoreObserver::PrimaryKey;

template<>
int32_t Convert2Value(napi_env env, napi_value input, Asset &output);

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, ValueObject &valueObject);

template<>
napi_value Convert2JSValue(napi_env env, const Asset &value);

template<>
napi_value Convert2JSValue(napi_env env, const RowEntity &value);

template<>
napi_value Convert2JSValue(napi_env env, const ValueObject &value);

template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::Statistic &statistic);
template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::TableDetail &tableDetail);
template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::TableDetails &tableDetails);
template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::ProgressDetail &progressDetail);
template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::Details &details);
template<>
napi_value Convert2JSValue(napi_env env, const JSChangeInfo &value);
template<>
napi_value Convert2JSValue(napi_env env, const Date &date);
template<>
std::string ToString(const PRIKey &key);
}; // namespace JSUtils
} // namespace OHOS::AppDataMgrJsKit
#endif // RDB_JSKIT_NAPI_RDB_JS_UTILS_H
