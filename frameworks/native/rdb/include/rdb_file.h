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
#ifndef RDB_FILES_H
#define RDB_FILES_H

#include <vector>
namespace OHOS {
namespace NativeRdb {
class RdbFile {
public:
    static std::vector<std::string> GetEntries(const std::string &path);
    static std::pair<size_t, int32_t> RemoveAll(const std::string &path);
};
} // namespace NativeRdb
} // namespace OHOS
#endif // RD_UTILS_H