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

#define LOG_TAG "RdbGqlUtils"
#include "gdb_utils.h"

#include <algorithm>
#include <securec.h>
#include <sys/stat.h>
#include <unistd.h>

#include "aip_errors.h"

namespace OHOS::DistributedDataAip {
constexpr int32_t CONTINUOUS_DIGITS_MINI_SIZE = 5;
constexpr int32_t FILE_PATH_MINI_SIZE = 6;
constexpr int32_t AREA_MINI_SIZE = 4;
constexpr int32_t AREA_OFFSET_SIZE = 5;
constexpr int32_t PRE_OFFSET_SIZE = 1;

int GdbUtils::CreateDirectory(const std::string &databaseDir)
{
    std::string tempDirectory = databaseDir;
    std::vector<std::string> directories;

    size_t pos = tempDirectory.find('/');
    while (pos != std::string::npos) {
        std::string directory = tempDirectory.substr(0, pos);
        directories.push_back(directory);
        tempDirectory = tempDirectory.substr(pos + 1);
        pos = tempDirectory.find('/');
    }
    directories.push_back(tempDirectory);

    std::string databaseDirectory;
    for (const std::string &directory : directories) {
        databaseDirectory += "/" + directory;
        if (access(databaseDirectory.c_str(), F_OK) != 0) {
            if (mkdir(databaseDirectory.c_str(), DIR_RWXRWS__X)) {
                return E_CREATE_FOLDER_FAIT;
            }
        }
    }
    return E_OK;
}

std::string GdbUtils::Anonymous(const std::string &srcFile)
{
    auto pre = srcFile.find("/");
    auto end = srcFile.rfind("/");
    if (pre == std::string::npos || end - pre < FILE_PATH_MINI_SIZE) {
        return GetAnonymousName(srcFile);
    }
    auto path = srcFile.substr(pre, end - pre);
    auto area = path.find("/el");
    if (area == std::string::npos || area + AREA_MINI_SIZE > path.size()) {
        path = "";
    } else if (area + AREA_OFFSET_SIZE < path.size()) {
        path = path.substr(area, AREA_MINI_SIZE) + "/***";
    } else {
        path = path.substr(area, AREA_MINI_SIZE);
    }
    std::string fileName = srcFile.substr(end); // rdb file name
    fileName = GetAnonymousName(fileName);
    return srcFile.substr(0, pre + PRE_OFFSET_SIZE) + "***" + path + fileName;
}

std::string GdbUtils::GetAnonymousName(const std::string &fileName)
{
    std::vector<std::string> alnum;
    std::vector<std::string> noAlnum;
    std::string alnumStr;
    std::string noAlnumStr;
    for (const auto &letter : fileName) {
        if (isxdigit(letter)) {
            if (!noAlnumStr.empty()) {
                noAlnum.push_back(noAlnumStr);
                noAlnumStr.clear();
                alnum.push_back("");
            }
            alnumStr += letter;
        } else {
            if (!alnumStr.empty()) {
                alnum.push_back(alnumStr);
                alnumStr.clear();
                noAlnum.push_back("");
            }
            noAlnumStr += letter;
        }
    }
    if (!alnumStr.empty()) {
        alnum.push_back(alnumStr);
        noAlnum.push_back("");
    }
    if (!noAlnumStr.empty()) {
        noAlnum.push_back(alnumStr);
        alnum.push_back("");
    }
    std::string res = "";
    for (size_t i = 0; i < alnum.size(); ++i) {
        res += (AnonyDigits(alnum[i]) + noAlnum[i]);
    }
    return res;
}

std::string GdbUtils::AnonyDigits(const std::string &fileName)
{
    std::string::size_type digitsNum = fileName.size();
    if (digitsNum < CONTINUOUS_DIGITS_MINI_SIZE) {
        return fileName;
    }
    constexpr std::string::size_type longDigits = 7;
    std::string::size_type endDigitsNum = 4;
    std::string::size_type shortEndDigitsNum = 3;
    std::string name = fileName;
    std::string last = "";
    if (digitsNum >= CONTINUOUS_DIGITS_MINI_SIZE && digitsNum < longDigits) {
        last = name.substr(name.size() - shortEndDigitsNum);
    } else {
        last = name.substr(name.size() - endDigitsNum);
    }

    return "***" + last;
}

void GdbUtils::ClearAndZeroString(std::string &str)
{
    str.clear();
    std::fill(str.begin(), str.end(), char(0));
}

std::string GdbUtils::GetConfigStr(const std::vector<uint8_t> &keys, bool isEncrypt)
{
    std::string config = "{";
    if (isEncrypt) {
        const size_t keyBuffSize = keys.size() * 2 + 1; // 2 hex number can represent a uint8_t, 1 is for '\0'
        std::vector<char> keyBuff(keyBuffSize);
        config += "\"isEncrypted\":1,";
        config += "\"hexPassword\":\"";
        config += GetEncryptKey(keys, keyBuff.data(), keyBuffSize);
        config += "\",";
        keyBuff.assign(keyBuffSize, 0);
    }
    config += GRD_OPEN_CONFIG_STR;
    config += "}";
    return config;
}

const char *GdbUtils::GetEncryptKey(const std::vector<uint8_t> &encryptedKey, char outBuff[], size_t outBufSize)
{
    char *buffer = nullptr;
    auto keySize = encryptedKey.size();
    for (size_t i = 0; i < keySize; i++) {
        buffer = (char *)(outBuff + i * 2); // each uint8_t will convert to 2 hex char
        // each uint8_t will convert to 2 hex char
        errno_t err = snprintf_s(buffer, outBufSize - i * 2, outBufSize - i * 2, "%02x", encryptedKey[i]);
        if (err < 0) {
            return nullptr;
        }
    }
    return outBuff;
}
} // namespace OHOS::DistributedDataAip
