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

#ifndef RDB_CONFIG_VERSION_DEFINE_H
#define RDB_CONFIG_VERSION_DEFINE_H
#ifndef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    int selfSize;
    const char *dataBaseDir;
    const char *storeName;
    const char *bundleName;
    const char *moduleName;
    bool isEncrypt;
    int securityLevel;
} RdbConfigV0;

typedef struct {
    int selfSize;
    const char *dataBaseDir;
    const char *storeName;
    const char *bundleName;
    const char *moduleName;
    bool isEncrypt;
    int securityLevel;
    int area;
} RdbConfigV1;

#define RDB_CONFIG_SIZE_V0 sizeof(RdbConfigV0)
#define RDB_CONFIG_SIZE_V1 sizeof(RdbConfigV1)

#ifndef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif // RDB_CONFIG_VERSION_DEFINE_H
