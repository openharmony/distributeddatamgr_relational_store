/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "string_utils.h"

namespace OHOS {
namespace NativeRdb {
std::string StringUtils::SurroundWithQuote(const std::string &value, const std::string &quote)
{
    if (value.empty()) {
        return value;
    }
    return quote + value + quote;
}

// Join array members as parameters of a function call.
std::string StringUtils::SurroundWithFunction(
    const std::string &function, const std::string &separator, const std::vector<std::string> &array)
{
    std::string builder(function);
    builder += "(";
    bool isFirst = true;
    for (const auto &text : array) {
        if (!isFirst) {
            builder = builder + " " + separator + " ";
        } else {
            isFirst = false;
        }
        builder += text;
    }
    builder += ")";
    return builder;
}

std::vector<std::string> StringUtils::Split(const std::string &str, const std::string &delim)
{
    std::vector<std::string> res;
    size_t pos = 0;
    while (pos < str.size()) {
        size_t found = str.find(delim, pos);
        if (found == std::string::npos) {
            res.push_back(str.substr(pos));
            break;
        }
        res.push_back(str.substr(pos, found - pos));
        pos = found + delim.size();
    }
    return res;
}

std::string StringUtils::ExtractFilePath(const std::string &fileFullName)
{
    return std::string(fileFullName).substr(0, fileFullName.rfind("/") + 1);
}

std::string StringUtils::ExtractFileName(const std::string &fileFullName)
{
    return std::string(fileFullName).substr(fileFullName.rfind("/") + 1, fileFullName.size());
}

std::string StringUtils::TruncateAfterFirstParen(const std::string &str)
{
    size_t pos = str.find('(');
    return (pos != std::string::npos) ? str.substr(0, pos) : str;
}

std::string StringUtils::GetParentPath(const std::string &path)
{
    size_t pos = path.find_last_of("/\\");
    if (pos == std::string::npos) {
        return "";
    }
    if (pos == 0) {
        return "/";
    }
    return path.substr(0, pos);
}

StringUtils::StringUtils()
{
}

StringUtils::~StringUtils()
{
}
} // namespace NativeRdb
} // namespace OHOS