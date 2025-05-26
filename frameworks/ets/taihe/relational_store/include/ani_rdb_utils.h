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
#ifndef OHOS_RELATION_STORE_ANI_RDB_UTILS_H_
#define OHOS_RELATION_STORE_ANI_RDB_UTILS_H_

#include <functional>
#include <memory>

#include "taihe/runtime.hpp"
#include "ohos.data.relationalStore.proj.hpp"
#include "ohos.data.relationalStore.impl.hpp"

#include "value_object.h"
#include "napi_rdb_js_utils.h"

namespace ani_rdbutils {

OHOS::NativeRdb::AssetValue AssetToNative(::ohos::data::relationalStore::Asset const &asset);
::ohos::data::relationalStore::Asset AssetToAni(OHOS::NativeRdb::AssetValue const &value);
OHOS::NativeRdb::ValueObject ValueTypeToNative(::ohos::data::relationalStore::ValueType const &value);
::ohos::data::relationalStore::ValueType ValueObjectToAni(OHOS::NativeRdb::ValueObject const &valueObj);
OHOS::NativeRdb::ValuesBucket MapValuesToNative(
    taihe::map_view<taihe::string, ::ohos::data::relationalStore::ValueType> const &values);
std::vector<OHOS::NativeRdb::ValueObject> ArrayValuesToNative(
    taihe::array_view<::ohos::data::relationalStore::ValueType> const &values);
OHOS::NativeRdb::ValuesBuckets BucketValuesToNative(
    taihe::array_view<taihe::map<taihe::string, ::ohos::data::relationalStore::ValueType>> const &values);

OHOS::NativeRdb::RdbStoreConfig::CryptoParam CryptoParamToNative(
    ::ohos::data::relationalStore::CryptoParam const &param);
OHOS::AppDataMgrJsKit::JSUtils::RdbConfig AniGetRdbConfig(
    ::ohos::data::relationalStore::StoreConfig const &storeConfig);
std::pair<bool, OHOS::NativeRdb::RdbStoreConfig> AniGetRdbStoreConfig(ani_env *env, ani_object aniValue,
    OHOS::AppDataMgrJsKit::JSUtils::RdbConfig &rdbConfig);

bool HasDuplicateAssets(const OHOS::NativeRdb::ValueObject &value);
bool HasDuplicateAssets(const std::vector<OHOS::NativeRdb::ValueObject> &values);
bool HasDuplicateAssets(const OHOS::NativeRdb::ValuesBucket &value);
bool HasDuplicateAssets(const std::vector<OHOS::NativeRdb::ValuesBucket> &values);
bool HasDuplicateAssets(const OHOS::NativeRdb::ValuesBuckets &values);

}

#endif