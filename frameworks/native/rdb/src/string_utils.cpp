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
std::string StringUtils::SurroundWithFunction(const std::string &function, const std::string &separator,
    const std::vector<std::string> &array)
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

StringUtils::StringUtils() {}
StringUtils::~StringUtils() {}
} // namespace NativeRdb
} // namespace OHOS