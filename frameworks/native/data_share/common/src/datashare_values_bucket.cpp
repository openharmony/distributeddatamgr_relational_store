/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "datashare_values_bucket.h"

namespace OHOS {
namespace DataShare {
DataShareValuesBucket::DataShareValuesBucket()
{
}

DataShareValuesBucket::DataShareValuesBucket(std::map<std::string, DataShareValueObject> &valuesMap)
    : valuesMap(valuesMap)
{
}

DataShareValuesBucket::~DataShareValuesBucket()
{
}

void DataShareValuesBucket::PutString(const std::string &columnOrKeyName, const std::string &value)
{
    valuesMap.insert(std::make_pair(columnOrKeyName, DataShareValueObject(value)));
}

void DataShareValuesBucket::PutInt(const std::string &columnOrKeyName, int value)
{
    valuesMap.insert(std::make_pair(columnOrKeyName, DataShareValueObject(value)));
}

void DataShareValuesBucket::PutLong(const std::string &columnOrKeyName, int64_t value)
{
    valuesMap.insert(std::make_pair(columnOrKeyName, DataShareValueObject(value)));
}

void DataShareValuesBucket::PutDouble(const std::string &columnOrKeyName, double value)
{
    valuesMap.insert(std::make_pair(columnOrKeyName, DataShareValueObject(value)));
}

void DataShareValuesBucket::PutBool(const std::string &columnOrKeyName, bool value)
{
    valuesMap.insert(std::make_pair(columnOrKeyName, DataShareValueObject(value)));
}

void DataShareValuesBucket::PutBlob(const std::string &columnOrKeyName, const std::vector<uint8_t> &value)
{
    valuesMap.insert(std::make_pair(columnOrKeyName, DataShareValueObject(value)));
}

void DataShareValuesBucket::PutNull(const std::string &columnOrKeyName)
{
    valuesMap.insert(std::make_pair(columnOrKeyName, DataShareValueObject()));
}

void DataShareValuesBucket::Delete(const std::string &columnOrKeyName)
{
    valuesMap.erase(columnOrKeyName);
}

void DataShareValuesBucket::Clear()
{
    valuesMap.clear();
}

int DataShareValuesBucket::Size() const
{
    return valuesMap.size();
}

bool DataShareValuesBucket::IsEmpty() const
{
    return valuesMap.empty();
}

bool DataShareValuesBucket::HasColumnOrKey(const std::string &columnOrKeyName) const
{
    auto iter = valuesMap.find(columnOrKeyName);
    if (iter == valuesMap.end()) {
        return false;
    }
    return true;
}

bool DataShareValuesBucket::GetObject(const std::string &columnOrKeyName, DataShareValueObject &value) const
{
    auto iter = valuesMap.find(columnOrKeyName);
    if (iter == valuesMap.end()) {
        return false;
    }
    value = iter->second;
    return true;
}

void DataShareValuesBucket::GetAll(std::map<std::string, DataShareValueObject> &outValuesMap) const
{
    outValuesMap = valuesMap;
}

bool DataShareValuesBucket::Marshalling(Parcel &parcel) const
{
    parcel.WriteInt32(valuesMap.size());
    for (auto &it : valuesMap) {
        parcel.WriteString(it.first);
        parcel.WriteParcelable(&it.second);
    }
    return true;
}

DataShareValuesBucket *DataShareValuesBucket::Unmarshalling(Parcel &parcel)
{
    int mapSize = parcel.ReadInt32();
    std::map<std::string, DataShareValueObject> valuesMap;
    for (int i = 0; i < mapSize; i++) {
        std::string key = parcel.ReadString();
        DataShareValueObject *value = parcel.ReadParcelable<DataShareValueObject>();
        valuesMap.insert(std::make_pair(key, *value));
    }
    return new DataShareValuesBucket(valuesMap);
}
} // namespace DataShare
} // namespace OHOS
