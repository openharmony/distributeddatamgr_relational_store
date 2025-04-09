/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_DATA_NATIVE_GDB_GDB_UTILS_H
#define OHOS_DISTRIBUTED_DATA_NATIVE_GDB_GDB_UTILS_H
#include <string>

#include "rdb_visibility.h"

namespace OHOS::DistributedDataAip {
class API_EXPORT GdbUtils {
public:
    static bool IsTransactionGql(const std::string &gql);
    static int CreateDirectory(const std::string &databaseDir);
    static std::string Anonymous(const std::string &srcFile);
    static void ClearAndZeroString(std::string &str);
    static std::string GetConfigStr(const std::vector<uint8_t> &keys, bool isEncrypt);
    static const char *GetEncryptKey(const std::vector<uint8_t> &encryptedKey, char outBuff[], size_t outBufSize);
private:
    static constexpr int DIR_RWXRWS__X = 0771;
    static constexpr const char *GRD_OPEN_CONFIG_STR =
        R"("pageSize": 4, "crcCheckEnable": 0, "defaultIsolationLevel": 3, "redoFlushByTrx": 1, metaInfoBak": 1)";
    static std::string GetAnonymousName(const std::string& fileName);
    static std::string AnonyDigits(const std::string& fileName);
};
}

#endif