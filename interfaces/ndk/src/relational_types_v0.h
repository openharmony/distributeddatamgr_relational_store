/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef RELATIONAL_TYPES_V0_H
#define RELATIONAL_TYPES_V0_H
#ifndef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
#define TABLE_DETAIL_V0 1
typedef struct Statistic_V0 {
    int total;
    int successful;
    int failed;
    int remained;
} Statistic_V0;

typedef struct TableDetails_V0 {
    const char *table;
    Statistic_V0 upload;
    Statistic_V0 download;
} TableDetails_V0;

#define DISTRIBUTED_CONFIG_V0 1
typedef struct DistributedConfig_V0 {
    int version;
    bool isAutoSync;
} DistributedConfig_V0;
#ifndef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif // RELATIONAL_TYPES_V0_H
