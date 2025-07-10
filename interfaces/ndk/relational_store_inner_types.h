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

#ifndef RELATIONAL_STORE_INNER_TYPES_H
#define RELATIONAL_STORE_INNER_TYPES_H
#include <string>
#include <vector>

#include "rdb_store_config.h"
#include "relational_store.h"
constexpr int RDB_CONFIG_V2_MAGIC_CODE = 0xDBCF2ADE;
struct OH_Rdb_ConfigV2 {
    int magicNum = RDB_CONFIG_V2_MAGIC_CODE;
    std::string dataBaseDir = "";
    std::string storeName = "";
    std::string bundleName = "";
    std::string moduleName = "";
    bool isEncrypt = false;
    bool persist = true;
    int securityLevel = 0;
    int area = 0;
    int dbType = RDB_SQLITE;
    int token = RDB_NONE_TOKENIZER;
    std::string customDir = "";
    bool readOnly = false;
    std::vector<std::string> pluginLibs{};
    OHOS::NativeRdb::RdbStoreConfig::CryptoParam cryptoParam;
    bool enableSemanticIndex = false;
};
#endif // RELATIONAL_STORE_INNER_TYPES_H
