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
void DataShareValuesBucket::PutString(const std::string &columnName, const std::string &value)
{
    valuesMap.insert(std::make_pair(columnName, DataShareValueObject(value)));
}

void DataShareValuesBucket::PutInt(const std::string &columnName, int value)
{
    valuesMap.insert(std::make_pair(columnName, DataShareValueObject(value)));
}

void DataShareValuesBucket::PutLong(const std::string &columnName, int64_t value)
{
    valuesMap.insert(std::make_pair(columnName, DataShareValueObject(value)));
}

void DataShareValuesBucket::PutDouble(const std::string &columnName, double value)
{
    valuesMap.insert(std::make_pair(columnName, DataShareValueObject(value)));
}

void DataShareValuesBucket::PutBool(const std::string &columnName, bool value)
{
    valuesMap.insert(std::make_pair(columnName, DataShareValueObject(value)));
}

void DataShareValuesBucket::PutBlob(const std::string &columnName, const std::vector<uint8_t> &value)
{
    valuesMap.insert(std::make_pair(columnName, DataShareValueObject(value)));
}

void DataShareValuesBucket::PutNull(const std::string &columnName)
{
    valuesMap.insert(std::make_pair(columnName, DataShareValueObject()));
}

void DataShareValuesBucket::Delete(const std::string &columnName)
{
    valuesMap.erase(columnName);
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

bool DataShareValuesBucket::HasColumn(const std::string &columnName) const
{
    auto iter = valuesMap.find(columnName);
    if (iter == valuesMap.end()) {
        return false;
    }
    return true;
}

bool DataShareValuesBucket::GetObject(const std::string &columnName, DataShareValueObject &value) const
{
    auto iter = valuesMap.find(columnName);
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

bool DataShareValuesBucket::Marshalling(const DataShareValuesBucket &valuesBucket, Parcel &parcel)
{
    parcel.WriteInt32(valuesMap.size());
    for (auto &it : valuesMap) {
        parcel.WriteString(it.first);
        DataShareValueObject::Marshalling(it.second, parcel);
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
