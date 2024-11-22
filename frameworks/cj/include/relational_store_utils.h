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

#ifndef RELATIONAL_STORE_UTILS_H
#define RELATIONAL_STORE_UTILS_H

#include "rdb_store.h"
#include "rdb_types.h"
#include "securec.h"
#include "value_object.h"

namespace OHOS {
namespace Relational {
char *MallocCString(const std::string &origin);

struct StoreConfig {
    char *name;
    int32_t securityLevel;
    bool encrypt;
    char *dataGroupId;
    char *customDir;
    bool isSearchable;
    bool autoCleanDirtyData;
};

struct Asset {
    const char *name;
    const char *uri;
    const char *path;
    const char *createTime;
    const char *modifyTime;
    const char *size;
    int32_t status;
};

struct Assets {
    Asset *head;
    int64_t size;
};

struct CArrUI8 {
    uint8_t *head;
    int64_t size;
};

struct CArrStr {
    char **head;
    int64_t size;
};

CArrStr VectorToCArrStr(const std::vector<std::string> &devices);

std::vector<std::string> CArrStrToVector(CArrStr carr);

struct ValueType {
    int64_t integer;
    double dou;
    char *string;
    bool boolean;
    CArrUI8 Uint8Array;
    Asset asset;
    Assets assets;
    uint8_t tag;
};

enum TagType { TYPE_NULL, TYPE_INT, TYPE_DOU, TYPE_STR, TYPE_BOOL, TYPE_BLOB, TYPE_ASSET, TYPE_ASSETS };

struct ValuesBucket {
    char **key;
    ValueType *value;
    int64_t size;
};

NativeRdb::ValueObject ValueTypeToValueObject(const ValueType &value);

struct CArrInt32 {
    int32_t *head;
    int64_t size;
};

struct CArrSyncResult {
    char **str;
    int32_t *num;
    int64_t size;
};

ValueType ValueObjectToValueType(const NativeRdb::ValueObject &object);

struct RetPRIKeyType {
    int64_t integer;
    double dou;
    char *string;
    uint8_t tag;
};

std::variant<std::monostate, std::string, int64_t, double> RetPRIKeyTypeToVariant(RetPRIKeyType &value);

RetPRIKeyType VariantToRetPRIKeyType(const std::variant<std::monostate, std::string, int64_t, double> &value);

struct CArrPRIKeyType {
    RetPRIKeyType *head;
    int64_t size;
};

std::vector<NativeRdb::RdbStore::PRIKey> CArrPRIKeyTypeToPRIKeyArray(CArrPRIKeyType &cPrimaryKeys);

struct ModifyTime {
    RetPRIKeyType *key;
    uint64_t *value;
    int64_t size;
};

ModifyTime MapToModifyTime(std::map<NativeRdb::RdbStore::PRIKey, NativeRdb::RdbStore::Date> &map, int32_t &errCode);

struct RetChangeInfo {
    char *table;
    int32_t type;
    CArrPRIKeyType inserted;
    CArrPRIKeyType updated;
    CArrPRIKeyType deleted;
};

struct CArrRetChangeInfo {
    RetChangeInfo *head;
    int64_t size;
};

CArrPRIKeyType VectorToCArrPRIKeyType(std::vector<DistributedRdb::RdbStoreObserver::PrimaryKey> arr);

RetChangeInfo ToRetChangeInfo(
    const DistributedRdb::Origin &origin, DistributedRdb::RdbStoreObserver::ChangeInfo::iterator info);

CArrRetChangeInfo ToCArrRetChangeInfo(const DistributedRdb::Origin &origin,
    const DistributedRdb::RdbStoreObserver::PrimaryFields &fields,
    DistributedRdb::RdbStoreObserver::ChangeInfo &&changeInfo);

struct CStatistic {
    uint32_t total;
    uint32_t successful;
    uint32_t failed;
    uint32_t remained;
};

CStatistic ToStatistic(DistributedRdb::Statistic statistic);

struct CTableDetails {
    CStatistic upload;
    CStatistic download;
};

CTableDetails ToCTableDetails(DistributedRdb::TableDetail detail);

struct CDetails {
    char **key;
    CTableDetails *value;
    int64_t size;
};

CDetails ToCDetails(DistributedRdb::TableDetails details);

struct CProgressDetails {
    int32_t schedule;
    int32_t code;
    CDetails details;
};

CProgressDetails ToCProgressDetails(const DistributedRdb::Details &details);

struct RetDistributedConfig {
    bool autoSync;
};
} // namespace Relational
} // namespace OHOS
#endif