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

#include "rdb_file.h"

#include <filesystem>
#include <vector>

namespace OHOS {
namespace NativeRdb {
std::vector<std::string> RdbFile::GetEntries(const std::string &path)
{
    std::vector<std::string> paths;
    std::error_code ec;
    for (const auto &entry : std::filesystem::recursive_directory_iterator(path, ec)) {
        if (ec) {
            ec.clear();
            continue;
        }
        paths.push_back(entry.path().string());
    }

    return paths;
}

std::pair<size_t, int32_t> RdbFile::RemoveAll(const std::string &path)
{
    std::error_code ec;
    size_t count =  std::filesystem::remove_all(path, ec);
    return std::make_pair(count, ec.value());
}

} // namespace NativeRdb
} // namespace OHOS