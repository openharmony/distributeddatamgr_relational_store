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

#include <stdint.h>
#include "asset_value.h"
#include "js_utils.h"
#include "napi_rdb_error.h"
#include "napi_rdb_store_observer.h"
#include "rdb_store_config.h"
#include "result_set.h"
#include "value_object.h"
namespace OHOS::AppDataMgrJsKit {
namespace JSUtils {
using Asset = OHOS::NativeRdb::AssetValue;
using RowEntity = OHOS::NativeRdb::RowEntity;
using ValueObject = OHOS::NativeRdb::ValueObject;
using Date = OHOS::DistributedRdb::Date;
using JSChangeInfo = OHOS::RelationalStoreJsKit::NapiRdbStoreObserver::JSChangeInfo;
using PRIKey = OHOS::DistributedRdb::RdbStoreObserver::PrimaryKey;
using Error = RelationalStoreJsKit::Error;
using SecurityLevel = NativeRdb::SecurityLevel;
using RdbStoreConfig = NativeRdb::RdbStoreConfig;
using BigInt = OHOS::NativeRdb::BigInteger;
struct RdbConfig {
    bool isEncrypt = false;
    bool isSearchable = false;
    bool isAutoClean = false;
    bool vector = false;
    bool allowRebuild = false;
    SecurityLevel securityLevel = SecurityLevel::LAST;
    std::string dataGroupId;
    std::string name;
    std::string customDir;
    std::string path;
};

struct ContextParam {
    std::string bundleName;
    std::string moduleName;
    std::string baseDir;
    int32_t area;
    bool isSystemApp = false;
    bool isStageMode = true;
};

template<>
int32_t Convert2Value(napi_env env, napi_value input, Asset &output);

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, DistributedRdb::Reference &output);

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, DistributedRdb::DistributedConfig &output);

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, ValueObject &valueObject);

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, RdbConfig &rdbConfig);

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, ContextParam &context);

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
napi_value Convert2JSValue(napi_env env, const DistributedRdb::ProgressDetail &progressDetail);
template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::Details &details);
template<>
napi_value Convert2JSValue(napi_env env, const JSChangeInfo &value);
template<>
napi_value Convert2JSValue(napi_env env, const Date &date);
template<>
napi_value Convert2JSValue(napi_env env, const BigInt &value);
template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, BigInt &value);
template<>
std::string ToString(const PRIKey &key);

bool IsNapiString(napi_env env, napi_value value);

std::tuple<int32_t, std::shared_ptr<Error>> GetRealPath(
    napi_env env, napi_value jsValue, RdbConfig &rdbConfig, ContextParam &param);
RdbStoreConfig GetRdbStoreConfig(const RdbConfig &rdbConfig, const ContextParam &param);

}; // namespace JSUtils
} // namespace OHOS::AppDataMgrJsKit
#endif // RDB_JSKIT_NAPI_RDB_JS_UTILS_H