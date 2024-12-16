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

#include <windows.h>

#include <iostream>
#include <string>

constexpr int32_t LIB_SIZE = 3;
constexpr int32_t LIBSO_SIZE = 8;
void *dlopen(const char *pathName, int mode)
{
    std::string fileName(pathName);
    if (fileName.length() > LIBSO_SIZE) {
        std::string dllName = fileName.substr(LIB_SIZE, fileName.length() - LIBSO_SIZE) + ".dll";
        return reinterpret_cast<void *>(LoadLibrary(dllName));
    }
};

void *dlsym(void *handle, const char *funcName)
{
    return reinterpret_cast<void *>(GetProcAddress(handle, funcName));
};