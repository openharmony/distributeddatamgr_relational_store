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

#include "relational_store_utils.h"
#include "native_log.h"

namespace OHOS {
namespace Relational {
    char* MallocCString(const std::string& origin)
    {
        if (origin.empty()) {
            return nullptr;
        }
        auto len = origin.length() + 1;
        char* res = static_cast<char*>(malloc(sizeof(char) * len));
        if (res == nullptr) {
            return nullptr;
        }
        return std::char_traits<char>::copy(res, origin.c_str(), len);
    }

    NativeRdb::ValueObject ValueTypeToValueObjectBlob(const ValueType& value)
    {
        std::vector<uint8_t> blob = std::vector<uint8_t>();
        for (int64_t j = 0; j < value.Uint8Array.size; j++) {
            blob.push_back(value.Uint8Array.head[j]);
        }
        return NativeRdb::ValueObject(blob);
    }

    NativeRdb::ValueObject ValueTypeToValueObjectAsset(const ValueType& value)
    {
        std::string modifyTime = value.asset.modifyTime;
        std::string size = value.asset.size;
        NativeRdb::ValueObject::Asset asset = {
            .status = value.asset.status,
            .name = value.asset.name,
            .uri = value.asset.uri,
            .createTime = value.asset.createTime,
            .modifyTime = modifyTime,
            .size = size,
            .hash = modifyTime + "_" + size,
            .path = value.asset.path
        };
        return NativeRdb::ValueObject(asset);
    }

    NativeRdb::ValueObject ValueTypeToValueObjectAssets(const ValueType& value)
    {
        std::vector<NativeRdb::ValueObject::Asset> assets = std::vector<NativeRdb::ValueObject::Asset>();
        for (int64_t j = 0; j < value.assets.size; j++) {
            Asset asset = value.assets.head[j];
            std::string modifyTime = asset.modifyTime;
            std::string size = asset.size;
            NativeRdb::ValueObject::Asset nativeAsset = {
                .status = asset.status,
                .name = asset.name,
                .uri = asset.uri,
                .createTime = asset.createTime,
                .modifyTime = modifyTime,
                .size = size,
                .hash = modifyTime + "_" + size,
                .path = asset.path
            };
            assets.push_back(nativeAsset);
        }
        return NativeRdb::ValueObject(assets);
    }

    NativeRdb::ValueObject ValueTypeToValueObject(const ValueType& value)
    {
        NativeRdb::ValueObject valueObject;
        switch (value.tag) {
            case TYPE_NULL: {
                valueObject = NativeRdb::ValueObject();
                break;
            }
            case TYPE_INT: {
                valueObject = NativeRdb::ValueObject(value.integer);
                break;
            }
            case TYPE_DOU: {
                valueObject = NativeRdb::ValueObject(value.dou);
                break;
            }
            case TYPE_STR: {
                valueObject = NativeRdb::ValueObject(value.string);
                break;
            }
            case TYPE_BOOL: {
                valueObject = NativeRdb::ValueObject(value.boolean);
                break;
            }
            case TYPE_BLOB: {
                valueObject = ValueTypeToValueObjectBlob(value);
                break;
            }
            case TYPE_ASSET: {
                valueObject = ValueTypeToValueObjectAsset(value);
                break;
            }
            case TYPE_ASSETS: {
                valueObject = ValueTypeToValueObjectAssets(value);
                break;
            }
            default:
                valueObject = NativeRdb::ValueObject();
                break;
        }
        return valueObject;
    }

    ValueType ValueObjectToValueTypeAsset(const NativeRdb::ValueObject& object)
    {
        NativeRdb::ValueObject::Asset val;
        object.GetAsset(val);
        Asset asset = Asset {
            .name = MallocCString(val.name),
            .uri = MallocCString(val.uri),
            .path = MallocCString(val.path),
            .createTime = MallocCString(val.createTime),
            .modifyTime = MallocCString(val.modifyTime),
            .size = MallocCString(val.size),
            .status = val.status
        };
        return ValueType {.asset = asset, .tag = TYPE_ASSET};
    }

    ValueType ValueObjectToValueTypeAssets(const NativeRdb::ValueObject& object)
    {
        NativeRdb::ValueObject::Assets val;
        object.GetAssets(val);
        Assets assets = Assets {.head = static_cast<Asset*>(malloc(val.size() * sizeof(Asset))), .size = val.size()};
        if (assets.head == nullptr) {
            return ValueType {.assets = Assets{nullptr, -1}, .tag = TYPE_ASSETS};
        }
        for (std::size_t i = 0; i < val.size(); i++) {
            assets.head[i] = Asset {
                .name = MallocCString(val[i].name),
                .uri = MallocCString(val[i].uri),
                .path = MallocCString(val[i].path),
                .createTime = MallocCString(val[i].createTime),
                .modifyTime = MallocCString(val[i].modifyTime),
                .size = MallocCString(val[i].size),
                .status = static_cast<int32_t>(val[i].status)
            };
        }
        return ValueType {.assets = assets, .tag = TYPE_ASSETS};
    }

    ValueType ValueObjectToValueType(const NativeRdb::ValueObject& object)
    {
        switch (object.GetType()) {
            case NativeRdb::ValueObject::TYPE_NULL:
                return ValueType {.tag = TYPE_NULL};
            case NativeRdb::ValueObject::TYPE_INT: {
                int64_t val;
                object.GetLong(val);
                return ValueType {.integer = val, .tag = TYPE_INT};
            }
            case NativeRdb::ValueObject::TYPE_DOUBLE: {
                double val;
                object.GetDouble(val);
                return ValueType {.dou = val, .tag = TYPE_DOU};
            }
            case NativeRdb::ValueObject::TYPE_STRING: {
                std::string val;
                object.GetString(val);
                return ValueType {.string = MallocCString(val), .tag = TYPE_STR};
            }
            case NativeRdb::ValueObject::TYPE_BOOL: {
                bool val;
                object.GetBool(val);
                return ValueType {.boolean = val, .tag = TYPE_BOOL};
            }
            case NativeRdb::ValueObject::TYPE_BLOB: {
                std::vector<uint8_t> val;
                object.GetBlob(val);
                CArrUI8 arr = CArrUI8 {.head = static_cast<uint8_t*>(malloc(val.size() * sizeof(uint8_t))),
                    .size = val.size()};
                if (arr.head == nullptr) {
                    return ValueType {.Uint8Array = CArrUI8 {nullptr, -1}, .tag = TYPE_BLOB};
                }
                return ValueType {.Uint8Array = arr, .tag = TYPE_BLOB};
            }
            case NativeRdb::ValueObject::TYPE_ASSET: {
                return ValueObjectToValueTypeAsset(object);
            }
            case NativeRdb::ValueObject::TYPE_ASSETS: {
                return ValueObjectToValueTypeAssets(object);
            }
            case NativeRdb::ValueObject::TYPE_BUTT:
                return ValueType {.tag = 128};
            default:
                return ValueType {.tag = TYPE_NULL};
        }
    }
}
}