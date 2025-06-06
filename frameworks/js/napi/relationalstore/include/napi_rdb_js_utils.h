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
#include "js_sendable_utils.h"
#include "js_utils.h"
#include "napi_rdb_error.h"
#include "napi_rdb_store_observer.h"
#include "rdb_store_config.h"
#include "result_set.h"
#include "value_object.h"
#include "values_bucket.h"
#include "values_buckets.h"

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
using Tokenizer = NativeRdb::Tokenizer;
using RdbStoreConfig = NativeRdb::RdbStoreConfig;
using BigInt = OHOS::NativeRdb::BigInteger;
using SqlExecInfo = DistributedRdb::SqlObserver::SqlExecutionInfo;
using ExceptionMessage = DistributedRdb::SqlErrorObserver::ExceptionMessage;
using ValuesBucket = OHOS::NativeRdb::ValuesBucket;
using ValuesBuckets = OHOS::NativeRdb::ValuesBuckets;
using HAMode = NativeRdb::HAMode;
using HmacAlgo = NativeRdb::HmacAlgo;
using KdfAlgo = NativeRdb::KdfAlgo;
using EncryptAlgo = NativeRdb::EncryptAlgo;
using CryptoParam = NativeRdb::RdbStoreConfig::CryptoParam;
struct RdbConfig {
    bool isEncrypt = false;
    bool isSearchable = false;
    bool isAutoClean = true;
    bool vector = false;
    bool allowRebuild = false;
    bool isReadOnly = false;
    bool persist = true;
    bool enableSemanticIndex = false;
    SecurityLevel securityLevel = SecurityLevel::LAST;
    Tokenizer tokenizer = Tokenizer::NONE_TOKENIZER;
    std::string dataGroupId;
    std::string name;
    std::string customDir;
    std::string rootDir;
    std::string path;
    std::vector<std::string> pluginLibs = {};
    int32_t haMode = HAMode::SINGLE;
    CryptoParam cryptoParam;
};

struct ContextParam {
    std::string bundleName;
    std::string moduleName;
    std::string baseDir;
    int32_t area;
    bool isSystemApp = false;
    bool isStageMode = true;
};

struct TransactionOptions {
    int32_t transactionType = 0;
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
int32_t Convert2Value(napi_env env, napi_value jsValue, CryptoParam &cryptoParam);

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, RdbConfig &rdbConfig);

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, TransactionOptions &transactionOptions);

template<>
int32_t Convert2Value(napi_env env, napi_value jsValue, ContextParam &context);

template<>
napi_value Convert2JSValue(napi_env env, const Asset &value);

template<>
napi_value Convert2JSValue(napi_env env, const RowEntity &value);

template<>
napi_value Convert2JSValue(napi_env env, const ValueObject &value);

template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::Statistic &value);
template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::TableDetail &value);

template<>
napi_value Convert2JSValue(napi_env env, const DistributedRdb::ProgressDetail &value);
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
template<>
napi_value Convert2JSValue(napi_env env, const SqlExecInfo &value);
template<>
napi_value Convert2JSValue(napi_env env, const ExceptionMessage &value);
bool IsNapiString(napi_env env, napi_value value);

std::tuple<int32_t, std::shared_ptr<Error>> GetRealPath(
    napi_env env, napi_value jsValue, RdbConfig &rdbConfig, ContextParam &param);
RdbStoreConfig GetRdbStoreConfig(const RdbConfig &rdbConfig, const ContextParam &param);

bool HasDuplicateAssets(const ValueObject &value);
bool HasDuplicateAssets(const std::vector<ValueObject> &values);
bool HasDuplicateAssets(const ValuesBucket &value);
bool HasDuplicateAssets(const std::vector<ValuesBucket> &values);
bool HasDuplicateAssets(const ValuesBuckets &values);
}; // namespace JSUtils
} // namespace OHOS::AppDataMgrJsKit
#endif // RDB_JSKIT_NAPI_RDB_JS_UTILS_H