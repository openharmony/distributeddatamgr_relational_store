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

#include <regex>
#include "native_log.h"
#include "rdb_errno.h"
#include "rdb_sql_utils.h"
#include "rdb_store.h"

#ifndef PATH_SPLIT
#define PATH_SPLIT '/'
#endif

using ContextParam = OHOS::AppDataMgrJsKit::JSUtils::ContextParam;
using RdbConfig = OHOS::AppDataMgrJsKit::JSUtils::RdbConfig;

const int64_t UI64TOUI8 = 8;
const int64_t BITNUMOFUI64 = 64;
static constexpr size_t MAX_TABLE_NAME_LENGTH = 256;
static constexpr size_t MAX_COLUMNS = 2000;
static constexpr int32_t MAX_ROWS_COUNT = 32766;

namespace OHOS {
namespace Relational {

bool IsValidTableName(const std::string &table)
{
    if (table.empty() || table.length() > MAX_TABLE_NAME_LENGTH) {
        return false;
    }
    std::regex validName("^[a-zA-Z0-9_]*$");
    return std::regex_match(table, validName);
}

OHOS::NativeRdb::RdbStoreConfig::CryptoParam ToCCryptoParam(CryptoParam param)
{
    auto cryptoParam = OHOS::NativeRdb::RdbStoreConfig::CryptoParam();
    cryptoParam.iterNum = param.iterNum;
    cryptoParam.encryptAlgo = param.encryptAlgo;
    cryptoParam.hmacAlgo = param.hmacAlgo;
    cryptoParam.kdfAlgo = param.kdfAlgo;
    cryptoParam.cryptoPageSize = param.cryptoPageSize;
    cryptoParam.encryptKey_ = CArrUI8ToVector(param.encryptKey);
    return cryptoParam;
}

char *MallocCString(const std::string& origin)
{
    if (origin.empty()) {
        return nullptr;
    }
    auto len = origin.length() + 1;
    char *res = static_cast<char*>(malloc(sizeof(char) * len));
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

NativeRdb::ValueObject ValueTypeExToValueObjectBlob(const ValueTypeEx& value)
{
    std::vector<uint8_t> blob = std::vector<uint8_t>();
    for (int64_t j = 0; j < value.uint8Array.size; j++) {
        blob.push_back(value.uint8Array.head[j]);
    }
    return NativeRdb::ValueObject(blob);
}

NativeRdb::ValueObject ValueTypeExToValueObjectAsset(const ValueTypeEx& value)
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

NativeRdb::ValueObject ValueTypeExToValueObjectAssets(const ValueTypeEx& value)
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

NativeRdb::ValueObject ValueTypeExToValueObjectFloatArr(const ValueTypeEx& value)
{
    std::vector<float> arr = std::vector<float>();
    for (int64_t j = 0; j < value.floatArray.size; j++) {
        arr.push_back(value.floatArray.head[j]);
    }
    return NativeRdb::ValueObject(arr);
}

NativeRdb::ValueObject ValueTypeExToValueObjectBigInt(const ValueTypeEx& value)
{
    std::vector<uint64_t> arr = std::vector<uint64_t>();
    int64_t firstSize = (value.bigInt.value.size % UI64TOUI8 == 0) ? UI64TOUI8 :
        (value.bigInt.value.size % UI64TOUI8);
    for (int64_t i = 0; i < ((value.bigInt.value.size + UI64TOUI8 - 1) / UI64TOUI8); i++) {
        uint64_t tempValue = 0;
        if (i == 0) {
            for (int64_t j = 0; j < firstSize; j++) {
                tempValue |=
                    (static_cast<uint64_t>(value.bigInt.value.head[j]) << (UI64TOUI8 * (firstSize -j - 1)));
            }
        } else {
            for (int64_t j = 0; j < UI64TOUI8; j++) {
                tempValue |=
                    (static_cast<uint64_t>(value.bigInt.value.head[UI64TOUI8 * (i - 1) + firstSize + j]) <<
                    (UI64TOUI8 * ((value.bigInt.value.size - (UI64TOUI8 * (i - 1) + firstSize + j) - 1) %
                    UI64TOUI8)));
            }
        }
        arr.push_back(tempValue);
    }
    return NativeRdb::ValueObject(NativeRdb::ValueObject::BigInt(static_cast<int32_t>(value.bigInt.sign),
        std::move(arr)));
}

NativeRdb::ValueObject ValueTypeExToValueObject(const ValueTypeEx& value)
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
            valueObject = ValueTypeExToValueObjectBlob(value);
            break;
        }
        case TYPE_ASSET: {
            valueObject = ValueTypeExToValueObjectAsset(value);
            break;
        }
        case TYPE_ASSETS: {
            valueObject = ValueTypeExToValueObjectAssets(value);
            break;
        }
        case TYPE_FLOATARR: {
            valueObject = ValueTypeExToValueObjectFloatArr(value);
            break;
        }
        case TYPE_BIGINT: {
            valueObject = ValueTypeExToValueObjectBigInt(value);
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
    if (val.size() == 0) {
        return ValueType {.assets = Assets{ nullptr, -1 }, .tag = TYPE_ASSETS};
    }
    Assets assets = Assets {.head = static_cast<Asset*>(malloc(val.size() * sizeof(Asset))), .size = val.size()};
    if (assets.head == nullptr) {
        return ValueType {.assets = Assets{ nullptr, -1 }, .tag = TYPE_ASSETS};
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
            if (val.size() == 0) {
                return ValueType {.Uint8Array = CArrUI8 { nullptr, -1 }, .tag = TYPE_BLOB};
            }
            CArrUI8 arr = CArrUI8 {.head = static_cast<uint8_t*>(malloc(val.size() * sizeof(uint8_t))),
                .size = val.size()};
            if (arr.head == nullptr) {
                return ValueType {.Uint8Array = CArrUI8 { nullptr, -1 }, .tag = TYPE_BLOB};
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
            return ValueType {.tag = TYPE_BUTT_TAG};
        default:
            return ValueType {.tag = TYPE_NULL};
    }
}

ValueTypeEx ValueObjectToValueTypeExBlob(const NativeRdb::ValueObject& object)
{
    std::vector<uint8_t> val = static_cast<std::vector<uint8_t>>(object);
    auto size = val.size();
    if (size == 0) {
        return ValueTypeEx {.uint8Array = CArrUI8 { nullptr, ERROR_VALUE }, .tag = TYPE_BLOB};
    }
    CArrUI8 arr = CArrUI8 {.head = static_cast<uint8_t*>(malloc(size * sizeof(uint8_t))),
        .size = size};
    if (arr.head == nullptr) {
        return ValueTypeEx {.uint8Array = CArrUI8 { nullptr, ERROR_VALUE }, .tag = TYPE_BLOB};
    }
    for (size_t i = 0; i < size; i++) {
        arr.head[i] = val[i];
    }
    return ValueTypeEx {.uint8Array = arr, .tag = TYPE_BLOB};
}

ValueTypeEx ValueObjectToValueTypeExAsset(const NativeRdb::ValueObject& object)
{
    NativeRdb::ValueObject::Asset val = static_cast<NativeRdb::ValueObject::Asset>(object);
    Asset asset = Asset {
        .name = MallocCString(val.name),
        .uri = MallocCString(val.uri),
        .path = MallocCString(val.path),
        .createTime = MallocCString(val.createTime),
        .modifyTime = MallocCString(val.modifyTime),
        .size = MallocCString(val.size),
        .status = val.status
    };
    return ValueTypeEx {.asset = asset, .tag = TYPE_ASSET};
}

ValueTypeEx ValueObjectToValueTypeExAssets(const NativeRdb::ValueObject& object)
{
    NativeRdb::ValueObject::Assets val = static_cast<NativeRdb::ValueObject::Assets>(object);
    if (val.size() == 0) {
        return ValueTypeEx {.assets = Assets{ nullptr, ERROR_VALUE }, .tag = TYPE_ASSETS};
    }
    Assets assets = Assets {.head = static_cast<Asset*>(malloc(val.size() * sizeof(Asset))), .size = val.size()};
    if (assets.head == nullptr) {
        return ValueTypeEx {.assets = Assets{ nullptr, ERROR_VALUE }, .tag = TYPE_ASSETS};
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
    return ValueTypeEx {.assets = assets, .tag = TYPE_ASSETS};
}

ValueTypeEx ValueObjectToValueTypeExFloatArray(const NativeRdb::ValueObject& object)
{
    std::vector<float> val = static_cast<std::vector<float>>(object);
    auto size = val.size();
    if (size == 0) {
        return ValueTypeEx {.floatArray = CArrFloat { nullptr, ERROR_VALUE }, .tag = TYPE_FLOATARR};
    }
    CArrFloat arr = CArrFloat {.head = static_cast<float*>(malloc(size * sizeof(float))),
        .size = size};
    if (arr.head == nullptr) {
        return ValueTypeEx {.floatArray = CArrFloat { nullptr, ERROR_VALUE }, .tag = TYPE_FLOATARR};
    }
    for (size_t i = 0; i < size; i++) {
        arr.head[i] = val[i];
    }
    return ValueTypeEx {.floatArray = arr, .tag = TYPE_FLOATARR};
}

ValueTypeEx ValueObjectToValueTypeExBigInt(const NativeRdb::ValueObject& object)
{
    NativeRdb::ValueObject::BigInt bigInt = static_cast<NativeRdb::ValueObject::BigInt>(object);
    int32_t sign = bigInt.Sign();
    std::vector<uint64_t> value = bigInt.Value();
    size_t size = value.size();
    if (size == 0) {
        return ValueTypeEx {.bigInt = BigInt { CArrUI8 { nullptr, ERROR_VALUE }, ERROR_VALUE }, .tag = TYPE_BIGINT};
    }
    uint8_t *head = static_cast<uint8_t*>(calloc(UI64TOUI8 * size, sizeof(uint8_t)));
    if (head == nullptr) {
        return ValueTypeEx {.bigInt = BigInt { CArrUI8 { nullptr, ERROR_VALUE }, ERROR_VALUE }, .tag = TYPE_BIGINT};
    }
    for (size_t i = 0; i < size; i++) {
        for (size_t j = 0; j < UI64TOUI8; j++) {
            head[UI64TOUI8 * i + j] |= (value[i] >> (BITNUMOFUI64 - (UI64TOUI8 * (j + 1))));
        }
    }
    return ValueTypeEx {.bigInt = BigInt {CArrUI8 {head, UI64TOUI8 * size}, sign}, .tag = TYPE_BIGINT};
}

ValueTypeEx ValueObjectToValueTypeEx(const NativeRdb::ValueObject& object)
{
    switch (object.GetType()) {
        case NativeRdb::ValueObject::TYPE_NULL:
            return ValueTypeEx {.tag = TYPE_NULL};
        case NativeRdb::ValueObject::TYPE_INT: {
            return ValueTypeEx {.integer = static_cast<int64_t>(object), .tag = TYPE_INT};
        }
        case NativeRdb::ValueObject::TYPE_DOUBLE: {
            return ValueTypeEx {.dou = static_cast<double>(object), .tag = TYPE_DOU};
        }
        case NativeRdb::ValueObject::TYPE_STRING: {
            return ValueTypeEx {.string = MallocCString(static_cast<std::string>(object)), .tag = TYPE_STR};
        }
        case NativeRdb::ValueObject::TYPE_BOOL: {
            return ValueTypeEx {.boolean = static_cast<bool>(object), .tag = TYPE_BOOL};
        }
        case NativeRdb::ValueObject::TYPE_BLOB: {
            return ValueObjectToValueTypeExBlob(object);
        }
        case NativeRdb::ValueObject::TYPE_ASSET: {
            return ValueObjectToValueTypeExAsset(object);
        }
        case NativeRdb::ValueObject::TYPE_ASSETS: {
            return ValueObjectToValueTypeExAssets(object);
        }
        case NativeRdb::ValueObject::TYPE_VECS: {
            return ValueObjectToValueTypeExFloatArray(object);
        }
        case NativeRdb::ValueObject::TYPE_BIGINT: {
            return ValueObjectToValueTypeExBigInt(object);
        }
        case NativeRdb::ValueObject::TYPE_BUTT:
            return ValueTypeEx {.tag = TYPE_BUTT_TAG};
        default:
            return ValueTypeEx {.tag = TYPE_NULL};
    }
}

ValuesBucketEx RowEntityToValuesBucketEx(const NativeRdb::RowEntity &rowEntity)
{
    const std::map<std::string, NativeRdb::ValueObject> map = rowEntity.Get();
    size_t size = map.size();
    if (size == 0) {
        return ValuesBucketEx{ nullptr, nullptr, 0 };
    }
    if (size > MAX_COLUMNS) {
        LOGE("RowEntityToValuesBucketEx size %{public}zu exceeds limit", size);
        return ValuesBucketEx{ nullptr, nullptr, ERROR_VALUE };
    }
    ValuesBucketEx result = ValuesBucketEx{
        .key = static_cast<char **>(malloc(sizeof(char *) * size)),
        .value = static_cast<ValueTypeEx *>(malloc(sizeof(ValueTypeEx) * size)),
        .size = static_cast<int64_t>(size)
    };
    if (result.key == nullptr || result.value == nullptr) {
        free(result.key);
        free(result.value);
        return ValuesBucketEx{ nullptr, nullptr, ERROR_VALUE };
    }
    int64_t i = 0;
    for (auto &t : map) {
        result.key[i] = MallocCString(t.first);
        result.value[i] = ValueObjectToValueTypeEx(t.second);
        i++;
    }
    return result;
}

CArrStr VectorToCArrStr(const std::vector<std::string> &devices)
{
    CArrStr cArrStr = { nullptr, 0 };
    if (devices.empty()) {
        return cArrStr;
    }
    cArrStr.head = static_cast<char **>(malloc(sizeof(char *) * devices.size()));
    if (cArrStr.head == nullptr) {
        return cArrStr;
    }
    for (size_t i = 0; i < devices.size(); i++) {
        cArrStr.head[i] = MallocCString(devices[i]);
    }
    cArrStr.size = static_cast<int64_t>(devices.size());
    return cArrStr;
}

std::vector<std::string> CArrStrToVector(CArrStr carr)
{
    std::vector<std::string> arr;
    for (int i = 0; i < carr.size; i++) {
        if (carr.head[i] != nullptr) {
            arr.push_back(carr.head[i]);
        } else {
            arr.push_back(std::string());
        }
    }
    return arr;
}

std::vector<uint8_t> CArrUI8ToVector(CArrUI8 carr)
{
    std::vector<std::uint8_t> arr;
    for (int i = 0; i < carr.size; i++) {
        arr.push_back(carr.head[i]);
    }
    return arr;
}

std::variant<std::monostate, std::string, int64_t, double> RetPRIKeyTypeToVariant(RetPRIKeyType &value)
{
    switch (value.tag) {
        case NativeRdb::ValueObject::TYPE_INT:
            return std::variant<std::monostate, std::string, int64_t, double>(value.integer);
        case NativeRdb::ValueObject::TYPE_DOUBLE:
            return std::variant<std::monostate, std::string, int64_t, double>(value.dou);
        case NativeRdb::ValueObject::TYPE_STRING:
            return std::variant<std::monostate, std::string, int64_t, double>(value.string);
        default:
            return std::variant<std::monostate, std::string, int64_t, double>(0);
    }
}

RetPRIKeyType VariantToRetPRIKeyType(const std::variant<std::monostate, std::string, int64_t, double> &value)
{
    if (std::holds_alternative<int64_t>(value)) {
        return RetPRIKeyType{ .integer = std::get<int64_t>(value), .dou = 0.0,
            .string = nullptr, .tag = NativeRdb::ValueObject::TYPE_INT };
    } else if (std::holds_alternative<double>(value)) {
        return RetPRIKeyType{ .integer = 0, .dou = std::get<double>(value),
            .string = nullptr, .tag = NativeRdb::ValueObject::TYPE_DOUBLE };
    } else if (std::holds_alternative<std::string>(value)) {
        return RetPRIKeyType{ .integer = 0, .dou = 0.0,
            .string = MallocCString(std::get<std::string>(value)), .tag = NativeRdb::ValueObject::TYPE_STRING };
    } else {
        return RetPRIKeyType{ 0 };
    }
}

std::vector<NativeRdb::RdbStore::PRIKey> CArrPRIKeyTypeToPRIKeyArray(CArrPRIKeyType &cPrimaryKeys)
{
    std::vector<NativeRdb::RdbStore::PRIKey> res = std::vector<NativeRdb::RdbStore::PRIKey>();
    for (int64_t i = 0; i < cPrimaryKeys.size; i++) {
        res.push_back(RetPRIKeyTypeToVariant(cPrimaryKeys.head[i]));
    }
    return res;
}

ModifyTime MapToModifyTime(std::map<NativeRdb::RdbStore::PRIKey, NativeRdb::RdbStore::Date> &map, int32_t &errCode)
{
    ModifyTime modifyTime{ 0 };
    modifyTime.size = static_cast<int64_t>(map.size());
    if (modifyTime.size == 0) {
        return ModifyTime{ 0 };
    }
    modifyTime.key = static_cast<RetPRIKeyType*>(malloc(sizeof(RetPRIKeyType) * modifyTime.size));
    modifyTime.value = static_cast<uint64_t*>(malloc(sizeof(uint64_t) * modifyTime.size));
    if (modifyTime.key == nullptr || modifyTime.value == nullptr) {
        free(modifyTime.key);
        free(modifyTime.value);
        errCode = -1;
        return ModifyTime{ 0 };
    }
    int64_t index = 0;
    for (auto it = map.begin(); it != map.end(); ++it) {
        modifyTime.key[index] = VariantToRetPRIKeyType(it->first);
        modifyTime.value[index] = static_cast<uint64_t>((it->second).date);
        index++;
    }
    return modifyTime;
}

CArrPRIKeyType VectorToCArrPRIKeyType(std::vector<DistributedRdb::RdbStoreObserver::PrimaryKey> arr)
{
    CArrPRIKeyType types{ 0 };
    if (arr.size() == 0) {
        return types;
    }
    types.head = static_cast<RetPRIKeyType*>(malloc(sizeof(RetPRIKeyType) * arr.size()));
    if (types.head == nullptr) {
        return types;
    }
    for (size_t i = 0; i < arr.size(); i++) {
        types.head[i] = VariantToRetPRIKeyType(arr[i]);
    }
    types.size = static_cast<int64_t>(arr.size());
    return types;
}

RetChangeInfo ToRetChangeInfo(const DistributedRdb::Origin &origin,
    DistributedRdb::RdbStoreObserver::ChangeInfo::iterator info)
{
    RetChangeInfo retInfo{ 0 };
    retInfo.table = MallocCString(info->first);
    retInfo.type = origin.dataType;
    retInfo.inserted = VectorToCArrPRIKeyType(info->
        second[DistributedRdb::RdbStoreObserver::ChangeType::CHG_TYPE_INSERT]);
    retInfo.updated = VectorToCArrPRIKeyType(info->
        second[DistributedRdb::RdbStoreObserver::ChangeType::CHG_TYPE_UPDATE]);
    retInfo.deleted = VectorToCArrPRIKeyType(info->
        second[DistributedRdb::RdbStoreObserver::ChangeType::CHG_TYPE_DELETE]);
    return retInfo;
}

CArrRetChangeInfo ToCArrRetChangeInfo(const DistributedRdb::Origin &origin,
    const DistributedRdb::RdbStoreObserver::PrimaryFields &fields,
    DistributedRdb::RdbStoreObserver::ChangeInfo &&changeInfo)
{
    CArrRetChangeInfo infos{ 0 };
    if (changeInfo.size() == 0) {
        return infos;
    }
    infos.head = static_cast<RetChangeInfo*>(malloc(sizeof(RetChangeInfo) * changeInfo.size()));
    if (infos.head == nullptr) {
        return CArrRetChangeInfo{ 0 };
    }
    int64_t index = 0;
    for (auto it = changeInfo.begin(); it != changeInfo.end(); ++it) {
        infos.head[index] = ToRetChangeInfo(origin, it);
        index++;
    }
    infos.size = static_cast<int64_t>(changeInfo.size());
    return infos;
}

CStatistic ToStatistic(DistributedRdb::Statistic statistic)
{
    return CStatistic{ .total = statistic.total, .successful = statistic.success,
        .failed = statistic.failed, .remained = statistic.untreated };
}

CTableDetails ToCTableDetails(DistributedRdb::TableDetail detail)
{
    return CTableDetails{ .upload = ToStatistic(detail.upload), .download = ToStatistic(detail.download) };
}

CDetails ToCDetails(DistributedRdb::TableDetails details)
{
    if (details.size() == 0) {
        return CDetails{ 0 };
    }
    char **key = static_cast<char **>(malloc(sizeof(char *) * details.size()));
    CTableDetails *value = static_cast<CTableDetails*>(malloc(sizeof(CTableDetails) * details.size()));
    if (key == nullptr || value == nullptr) {
        free(key);
        free(value);
        return CDetails{ 0 };
    }
    int64_t index = 0;
    for (auto it = details.begin(); it != details.end(); ++it) {
        key[index] = MallocCString(it->first);
        value[index] = ToCTableDetails(it->second);
        index++;
    }
    return CDetails{ .key = key, .value = value, .size = details.size() };
}

CProgressDetails ToCProgressDetails(const DistributedRdb::Details &details)
{
    if (details.empty()) {
        return CProgressDetails{ 0 };
    }
    DistributedRdb::ProgressDetail detail = details.begin() ->second;
    return CProgressDetails{ .schedule = detail.progress, .code = detail.code,
        .details = ToCDetails(detail.details) };
}

void FreeReturningResult(ReturningResult *result)
{
    if (result == nullptr) {
        return;
    }
}

NativeRdb::ReturningConfig CReturningConfigToNative(const ReturningConfig &config)
{
    NativeRdb::ReturningConfig nativeConfig;
    nativeConfig.defaultRowIndex = NativeRdb::ReturningConfig::DEFAULT_ROW_INDEX;
    if (config.columns != nullptr && config.columnsSize > 0) {
        for (int64_t i = 0; i < config.columnsSize; ++i) {
            nativeConfig.columns.push_back(config.columns[i]);
        }
    }
    if (config.hasMaxCount) {
        nativeConfig.maxReturningCount = config.maxReturningCount;
    }
    return nativeConfig;
}

CArrValuesBucket ValuesBucketExVectorToCArrValuesBucket(const std::vector<NativeRdb::ValuesBucket> &valuesBuckets)
{
    CArrValuesBucket result{ nullptr, 0 };
    if (valuesBuckets.empty()) {
        return result;
    }
    result.size = static_cast<int64_t>(valuesBuckets.size());
    result.head = static_cast<ValuesBucketEx *>(malloc(sizeof(ValuesBucketEx) * result.size));
    if (result.head == nullptr) {
        return result;
    }
    for (int64_t i = 0; i < result.size; ++i) {
        const auto &bucket = valuesBuckets[i];
        auto map = bucket.GetAll();
        result.head[i].size = static_cast<int64_t>(map.size());
        result.head[i].key = static_cast<char **>(malloc(sizeof(char *) * result.head[i].size));
        result.head[i].value = static_cast<ValueTypeEx *>(malloc(sizeof(ValueTypeEx) * result.head[i].size));
        if (result.head[i].key == nullptr || result.head[i].value == nullptr) {
            for (int64_t j = 0; j < i; ++j) {
                free(result.head[j].key);
                free(result.head[j].value);
            }
            free(result.head);
            result.head = nullptr;
            result.size = 0;
            return result;
        }
        int64_t k = 0;
        for (const auto &pair : map) {
            result.head[i].key[k] = MallocCString(pair.first);
            result.head[i].value[k] = ValueObjectToValueTypeEx(pair.second);
            ++k;
        }
    }
    return result;
}

RowDataEx ValueObjectVectorToRowDataEx(const std::vector<NativeRdb::ValueObject> &values)
{
    RowDataEx result{ nullptr, 0 };
    if (values.size() == 0) {
        return result;
    }
    if (values.size() > MAX_COLUMNS) {
        LOGE("ValueObjectVectorToRowDataEx size %{public}zu exceeds limit %{public}zu", values.size(), MAX_COLUMNS);
        return result;
    }
    result.size = static_cast<int64_t>(values.size());
    result.head = static_cast<ValueTypeEx *>(malloc(sizeof(ValueTypeEx) * result.size));
    if (result.head == nullptr) {
        return result;
    }
    for (int64_t i = 0; i < result.size; i++) {
        result.head[i] = ValueObjectToValueTypeEx(values[i]);
    }
    return result;
}

RowsDataEx RowDataExVectorToRowsDataEx(const std::vector<std::vector<NativeRdb::ValueObject>> &rows)
{
    RowsDataEx result{ nullptr, 0 };
    if (rows.size() == 0) {
        return result;
    }
    if (rows.size() > MAX_ROWS_COUNT) {
        LOGE("RowDataExVectorToRowsDataEx size %{public}zu exceeds limit %{public}d", rows.size(), MAX_ROWS_COUNT);
        return result;
    }
    result.size = static_cast<int64_t>(rows.size());
    result.head = static_cast<RowDataEx *>(malloc(sizeof(RowDataEx) * result.size));
    if (result.head == nullptr) {
        return result;
    }
    for (int64_t i = 0; i < result.size; i++) {
        result.head[i] = ValueObjectVectorToRowDataEx(rows[i]);
    }
    return result;
}

int32_t GetRealPath(
    RdbConfig &rdbConfig, const ContextParam &param, std::shared_ptr<OHOS::AppDataMgrJsKit::Context> abilityContext)
{
    if (rdbConfig.name.find(PATH_SPLIT) != std::string::npos) {
        LOGE("Parameter error. The StoreConfig.name must be a file name without path.");
        return RelationalStoreJsKit::E_PARAM_ERROR;
    }

    if (!rdbConfig.customDir.empty()) {
        if (rdbConfig.customDir.find_first_of(PATH_SPLIT) == 0) {
            LOGE("Parameter error. The customDir must be a relative directory.");
            return RelationalStoreJsKit::E_PARAM_ERROR;
        }
        if (rdbConfig.customDir.length() > MAX_CUSTOM_DIR_LENGTH) {
            LOGE("Parameter error. The customDir length must be less than or equal to 128 bytes.");
            return RelationalStoreJsKit::E_PARAM_ERROR;
        }
    }

    std::string baseDir = param.baseDir;
    if (!rdbConfig.dataGroupId.empty()) {
        if (!param.isStageMode) {
            return RelationalStoreJsKit::E_NOT_STAGE_MODE;
        }
        std::string groupDir;
        int errCode = abilityContext->GetSystemDatabaseDir(rdbConfig.dataGroupId, groupDir);
        if (errCode != NativeRdb::E_OK && groupDir.empty()) {
            return RelationalStoreJsKit::E_DATA_GROUP_ID_INVALID;
        }
        baseDir = groupDir;
    }

    auto [realPath, errorCode] =
        NativeRdb::RdbSqlUtils::GetDefaultDatabasePath(baseDir, rdbConfig.name, rdbConfig.customDir);
    if (errorCode != NativeRdb::E_OK || realPath.length() > MAX_DATABASE_PATH_LENGTH) {
        LOGE("Parameter error. The database path must be a valid path.");
        return RelationalStoreJsKit::E_PARAM_ERROR;
    }
    rdbConfig.path = realPath;
    return NativeRdb::E_OK;
}

void initContextParam(ContextParam &param, std::shared_ptr<OHOS::AppDataMgrJsKit::Context> abilityContext)
{
    param.bundleName = abilityContext->GetBundleName();
    param.moduleName = abilityContext->GetModuleName();
    param.baseDir = abilityContext->GetDatabaseDir();
    param.area = abilityContext->GetArea();
    param.isSystemApp = abilityContext->IsSystemAppCalled();
    param.isStageMode = abilityContext->IsStageMode();
}

void initRdbConfig(RdbConfig &rdbConfig, StoreConfig &config)
{
    rdbConfig.isEncrypt = config.encrypt;
    rdbConfig.isSearchable = config.isSearchable;
    rdbConfig.isAutoClean = config.autoCleanDirtyData;
    rdbConfig.securityLevel = static_cast<NativeRdb::SecurityLevel>(config.securityLevel);
    rdbConfig.dataGroupId = config.dataGroupId;
    rdbConfig.name = config.name;
    rdbConfig.customDir = config.customDir;
}

void initRdbConfigEx(RdbConfig &rdbConfig, const StoreConfigEx &config)
{
    rdbConfig.isEncrypt = config.encrypt;
    rdbConfig.isSearchable = config.isSearchable;
    rdbConfig.isAutoClean = config.autoCleanDirtyData;
    rdbConfig.securityLevel = static_cast<NativeRdb::SecurityLevel>(config.securityLevel);
    rdbConfig.dataGroupId = config.dataGroupId;
    rdbConfig.name = config.name;
    rdbConfig.customDir = config.customDir;
    rdbConfig.rootDir = config.rootDir;
    rdbConfig.vector = config.vector;
    rdbConfig.allowRebuild = config.allowRebuild;
    rdbConfig.isReadOnly = config.isReadOnly;
    rdbConfig.pluginLibs = CArrStrToVector(config.pluginLibs);
    rdbConfig.cryptoParam = ToCCryptoParam(config.cryptoParam);
    rdbConfig.tokenizer = static_cast<OHOS::NativeRdb::Tokenizer>(config.tokenizer);
    rdbConfig.persist = config.persist;
}

NativeRdb::RdbStoreConfig getRdbStoreConfig(const RdbConfig &rdbConfig, const ContextParam &param)
{
    NativeRdb::RdbStoreConfig rdbStoreConfig(rdbConfig.path);
    rdbStoreConfig.SetEncryptStatus(rdbConfig.isEncrypt);
    rdbStoreConfig.SetSearchable(rdbConfig.isSearchable);
    rdbStoreConfig.SetIsVector(rdbConfig.vector);
    rdbStoreConfig.SetAutoClean(rdbConfig.isAutoClean);
    rdbStoreConfig.SetSecurityLevel(rdbConfig.securityLevel);
    rdbStoreConfig.SetDataGroupId(rdbConfig.dataGroupId);
    rdbStoreConfig.SetName(rdbConfig.name);
    rdbStoreConfig.SetCustomDir(rdbConfig.customDir);
    rdbStoreConfig.SetAllowRebuild(rdbConfig.allowRebuild);

    if (!param.bundleName.empty()) {
        rdbStoreConfig.SetBundleName(param.bundleName);
    }
    rdbStoreConfig.SetModuleName(param.moduleName);
    rdbStoreConfig.SetArea(param.area);
    return rdbStoreConfig;
}

NativeRdb::RdbStoreConfig getRdbStoreConfigEx(const RdbConfig &rdbConfig, const ContextParam &param)
{
    NativeRdb::RdbStoreConfig rdbStoreConfig(rdbConfig.path);
    rdbStoreConfig.SetEncryptStatus(rdbConfig.isEncrypt);
    rdbStoreConfig.SetSearchable(rdbConfig.isSearchable);
    rdbStoreConfig.SetIsVector(rdbConfig.vector);
    rdbStoreConfig.SetDBType(rdbConfig.vector ? NativeRdb::DB_VECTOR : NativeRdb::DB_SQLITE);
    rdbStoreConfig.SetStorageMode(
        rdbConfig.persist ? NativeRdb::StorageMode::MODE_DISK : NativeRdb::StorageMode::MODE_MEMORY);
    rdbStoreConfig.SetAutoClean(rdbConfig.isAutoClean);
    rdbStoreConfig.SetSecurityLevel(rdbConfig.securityLevel);
    rdbStoreConfig.SetDataGroupId(rdbConfig.dataGroupId);
    rdbStoreConfig.SetName(rdbConfig.name);
    rdbStoreConfig.SetCustomDir(rdbConfig.customDir);
    rdbStoreConfig.SetAllowRebuild(rdbConfig.allowRebuild);
    rdbStoreConfig.SetReadOnly(rdbConfig.isReadOnly);
    rdbStoreConfig.SetIntegrityCheck(NativeRdb::IntegrityCheck::NONE);
    rdbStoreConfig.SetTokenizer(rdbConfig.tokenizer);

    if (!param.bundleName.empty()) {
        rdbStoreConfig.SetBundleName(param.bundleName);
    }
    rdbStoreConfig.SetModuleName(param.moduleName);
    rdbStoreConfig.SetArea(param.area);
    rdbStoreConfig.SetPluginLibs(rdbConfig.pluginLibs);
    rdbStoreConfig.SetHaMode(rdbConfig.haMode);

    rdbStoreConfig.SetCryptoParam(rdbConfig.cryptoParam);
    return rdbStoreConfig;
}
} // namespace Relational
} // namespace OHOS