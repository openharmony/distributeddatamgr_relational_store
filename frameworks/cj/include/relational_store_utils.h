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

#include "value_object.h"
#include "securec.h"

namespace OHOS {
namespace Relational {
    char* MallocCString(const std::string& origin);

    struct StoreConfig {
        char* name;
        int32_t securityLevel;
        bool encrypt;
        char* dataGroupId;
        char* customDir;
        bool isSearchable;
        bool autoCleanDirtyData;
    };

    struct Asset {
        const char* name;
        const char* uri;
        const char* path;
        const char* createTime;
        const char* modifyTime;
        const char* size;
        int32_t status;
    };

    struct Assets {
        Asset* head;
        int64_t size;
    };

    struct CArrUI8 {
        uint8_t* head;
        int64_t size;
    };

    struct CArrStr {
        char** head;
        int64_t size;
    };
    
    struct ValueType {
        int64_t integer;
        double dou;
        char* string;
        bool boolean;
        CArrUI8 Uint8Array;
        Asset asset;
        Assets assets;
        uint8_t tag;
    };

    enum TagType {
        TYPE_NULL, TYPE_INT, TYPE_DOU, TYPE_STR, TYPE_BOOL, TYPE_BLOB, TYPE_ASSET, TYPE_ASSETS
    };

    struct ValuesBucket {
        char** key;
        ValueType* value;
        int64_t size;
    };

    NativeRdb::ValueObject ValueTypeToValueObject(const ValueType& value);

    struct CArrInt32 {
        int32_t* head;
        int64_t size;
    };

    struct CArrSyncResult {
        char** str;
        int32_t* num;
        int64_t size;
    };

    ValueType ValueObjectToValueType(const NativeRdb::ValueObject& object);
}
}
#endif