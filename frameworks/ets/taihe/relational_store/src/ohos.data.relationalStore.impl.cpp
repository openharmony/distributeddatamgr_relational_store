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
#define LOG_TAG "AniRelationalStoreImpl"
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
#include "ohos.data.relationalStore.impl.h"
#include "lite_result_set_impl.h"
#include "lite_result_set_proxy.h"
#include "rdb_predicates_impl.h"
#include "rdb_store_impl.h"
#include "result_set_impl.h"
#include "result_set_proxy.h"
#include "transaction_impl.h"

using namespace taihe;
using namespace ohos::data::relationalStore;
using namespace OHOS::RelationalStoreJsKit;
using RdbSqlUtils =  OHOS::NativeRdb::RdbSqlUtils;
namespace OHOS {
namespace RdbTaihe {
using namespace OHOS;
using namespace OHOS::Rdb;
using namespace OHOS::RdbTaihe;
using ValueType = ohos::data::relationalStore::ValueType;
using ValueObject = OHOS::NativeRdb::ValueObject;

void ThrowError(std::shared_ptr<Error> err)
{
    if (err != nullptr) {
        LOG_ERROR("code[%{public}d,%{public}d][%{public}s]", err->GetNativeCode(), err->GetCode(),
            err->GetMessage().c_str());
        taihe::set_business_error(err->GetCode(), err->GetMessage());
    }
}

void ThrowInnerError(int errcode)
{
    auto innErr = std::make_shared<InnerError>(errcode);
    ThrowError(innErr);
}

// Error codes that cannot be thrown in some old scenarios need to be converted in new scenarios.
void ThrowInnerErrorExt(int errcode)
{
    auto innErr = std::make_shared<InnerErrorExt>(errcode);
    if (innErr != nullptr) {
        taihe::set_business_error(innErr->GetCode(), innErr->GetMessage());
    }
}

void ThrowNonSystemError()
{
    auto innErr = std::make_shared<NonSystemError>();
    ThrowError(innErr);
}

void ThrowParamError(const char *message)
{
    if (message == nullptr) {
        return;
    }
    auto paraErr = std::make_shared<ParamError>(message);
    ThrowError(paraErr);
}

RdbPredicates CreateRdbPredicates(string_view name)
{
    return make_holder<RdbPredicatesImpl, RdbPredicates>(std::string(name));
}

RdbStore GetRdbStoreSync(uintptr_t context, StoreConfig const &config)
{
    return make_holder<RdbStoreImpl, RdbStore>(reinterpret_cast<ani_object>(context), config);
}

void DeleteRdbStoreWithName(uintptr_t context, string_view name)
{
    ani_env *env = get_env();
    OHOS::AppDataMgrJsKit::JSUtils::RdbConfig rdbConfig;
    rdbConfig.name = std::string(name);
    auto configRet = ani_rdbutils::AniGetRdbStoreConfig(env, reinterpret_cast<ani_object>(context), rdbConfig);
    if (!configRet.first) {
        LOG_ERROR("AniGetRdbStoreConfig failed");
        return;
    }
    OHOS::NativeRdb::RdbStoreConfig storeConfig = configRet.second;

    storeConfig.SetDBType(OHOS::NativeRdb::DBType::DB_SQLITE);
    int errCodeSqlite = OHOS::NativeRdb::RdbHelper::DeleteRdbStore(storeConfig, false);
    storeConfig.SetDBType(OHOS::NativeRdb::DBType::DB_VECTOR);
    int errCodeVector = OHOS::NativeRdb::RdbHelper::DeleteRdbStore(storeConfig, false);
    LOG_INFO("deleteRdbStoreWithName sqlite %{public}d, vector %{public}d", errCodeSqlite, errCodeVector);
}

void DeleteRdbStoreWithConfig(uintptr_t context, StoreConfig const &config)
{
    ani_env *env = get_env();
    OHOS::AppDataMgrJsKit::JSUtils::RdbConfig rdbConfig = ani_rdbutils::AniGetRdbConfig(config);
    auto configRet = ani_rdbutils::AniGetRdbStoreConfig(env, reinterpret_cast<ani_object>(context), rdbConfig);
    if (!configRet.first) {
        LOG_ERROR("AniGetRdbStoreConfig failed");
        return;
    }
    OHOS::NativeRdb::RdbStoreConfig storeConfig = configRet.second;

    int errcode = OHOS::NativeRdb::RdbHelper::DeleteRdbStore(storeConfig, false);
    LOG_INFO("deleteRdbStoreWithConfig errcode %{public}d", errcode);
}

bool IsVectorSupported()
{
    return OHOS::NativeRdb::RdbHelper::IsSupportArkDataDb();
}

bool IsTokenizerSupported(ohos::data::relationalStore::Tokenizer tokenizer)
{
    return OHOS::NativeRdb::RdbHelper::IsSupportedTokenizer(ani_rdbutils::TokenizerToNative(tokenizer));
}
}
} // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateRdbPredicates(OHOS::RdbTaihe::CreateRdbPredicates);
TH_EXPORT_CPP_API_GetRdbStoreSync(OHOS::RdbTaihe::GetRdbStoreSync);
TH_EXPORT_CPP_API_DeleteRdbStoreWithName(OHOS::RdbTaihe::DeleteRdbStoreWithName);
TH_EXPORT_CPP_API_DeleteRdbStoreWithConfig(OHOS::RdbTaihe::DeleteRdbStoreWithConfig);
TH_EXPORT_CPP_API_IsVectorSupported(OHOS::RdbTaihe::IsVectorSupported);
TH_EXPORT_CPP_API_IsTokenizerSupported(OHOS::RdbTaihe::IsTokenizerSupported);
// NOLINTEND
