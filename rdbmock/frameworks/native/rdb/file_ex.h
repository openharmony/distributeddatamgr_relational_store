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

#ifndef MOCK_UTILS_BASE_FILE_EX_H
#define MOCK_UTILS_BASE_FILE_EX_H

#include <string>
#include <vector>

static bool SaveBufferToFile(const std::string& filePath, const std::vector<char>& content, bool truncated = true)
{
    return true;
}

static bool LoadBufferFromFile(const std::string& filePath, std::vector<char>& content)
{
    return true;
}

#endif  /* MOCK_UTILS_BASE_FILE_EX_H */

