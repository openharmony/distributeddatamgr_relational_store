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

#define LOG_TAG "RdbNdkUtils"
#include "rdb_ndk_utils.h"

#include "logger.h"
#include "rdb_errno.h"
#include "rdb_sql_utils.h"
#include "relational_store_inner_types.h"

namespace OHOS::RdbNdk {
// caller must ensure token is valid
static OHOS::NativeRdb::Tokenizer ConvertTokenizer2Native(Rdb_Tokenizer token)
{
    if (token == Rdb_Tokenizer::RDB_NONE_TOKENIZER) {
        return OHOS::NativeRdb::Tokenizer::NONE_TOKENIZER;
    }
    if (token == Rdb_Tokenizer::RDB_ICU_TOKENIZER) {
        return OHOS::NativeRdb::Tokenizer::ICU_TOKENIZER;
    }
    if (token == Rdb_Tokenizer::RDB_CUSTOM_TOKENIZER) {
        return OHOS::NativeRdb::Tokenizer::CUSTOM_TOKENIZER;
    }
    return OHOS::NativeRdb::Tokenizer::TOKENIZER_END;
}

std::pair<int32_t, OHOS::NativeRdb::RdbStoreConfig> RdbNdkUtils::GetRdbStoreConfig(const OH_Rdb_ConfigV2 *config)
{
    if (config == nullptr || config->magicNum != RDB_CONFIG_V2_MAGIC_CODE || (config->persist &&
        ((OHOS::NativeRdb::SecurityLevel(config->securityLevel) < OHOS::NativeRdb::SecurityLevel::S1 ||
        OHOS::NativeRdb::SecurityLevel(config->securityLevel) >= OHOS::NativeRdb::SecurityLevel::LAST))) ||
        (config->area < RDB_SECURITY_AREA_EL1 || config->area > RDB_SECURITY_AREA_EL5) ||
        (config->dbType < RDB_SQLITE || config->dbType > RDB_CAYLEY) ||
        (config->token < RDB_NONE_TOKENIZER || config->token > RDB_CUSTOM_TOKENIZER)) {
        if (config != nullptr) {
            LOG_ERROR("Config magic number is not valid %{public}x or securityLevel %{public}d area %{public}d"
                      " dbType %{public}d token %{public}d persist %{public}d"
                      " readOnly %{public}d",
                config->magicNum, config->securityLevel, config->area, config->dbType, config->token,
                config->persist, config->readOnly);
        } else {
            LOG_ERROR("Config is null");
        }
        return { OHOS::NativeRdb::E_INVALID_ARGS, OHOS::NativeRdb::RdbStoreConfig("") };
    }

    std::string realPath;
    int32_t code = OHOS::NativeRdb::E_OK;
    if (config->persist) {
        std::tie(realPath, code) = OHOS::NativeRdb::RdbSqlUtils::GetDefaultDatabasePath(
            config->dataBaseDir, config->storeName, config->customDir);
    } else {
        realPath = config->dataBaseDir;
    }

    if (code != OHOS::NativeRdb::E_OK) {
        LOG_ERROR("Get database path failed from new config, ret %{public}d ", code);
        return { OHOS::NativeRdb::E_INVALID_ARGS, OHOS::NativeRdb::RdbStoreConfig("") };
    }
    OHOS::NativeRdb::RdbStoreConfig rdbStoreConfig(realPath);
    rdbStoreConfig.SetSecurityLevel(OHOS::NativeRdb::SecurityLevel(config->securityLevel));
    rdbStoreConfig.SetEncryptStatus(config->isEncrypt);
    rdbStoreConfig.SetArea(config->area - 1);
    rdbStoreConfig.SetIsVector(config->dbType == RDB_CAYLEY);
    rdbStoreConfig.SetBundleName(config->bundleName);
    rdbStoreConfig.SetName(config->storeName);
    rdbStoreConfig.SetTokenizer(ConvertTokenizer2Native(static_cast<Rdb_Tokenizer>(config->token)));
    rdbStoreConfig.SetStorageMode(
        config->persist ? OHOS::NativeRdb::StorageMode::MODE_DISK : OHOS::NativeRdb::StorageMode::MODE_MEMORY);
    rdbStoreConfig.SetCustomDir(config->customDir);
    rdbStoreConfig.SetReadOnly(config->readOnly);
    rdbStoreConfig.SetPluginLibs(config->pluginLibs);
    rdbStoreConfig.SetCryptoParam(config->cryptoParam);
    return { OHOS::NativeRdb::E_OK, rdbStoreConfig };
}
} // namespace OHOS::RdbNdk