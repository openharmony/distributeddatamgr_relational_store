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

#include "datashare_predicates.h"
#include "datashare_predicates_utils.h"

namespace OHOS {
namespace DataShare {
int g_invalidObjectFlag = 0;
int g_validObjectFlag = 1;
int g_defaultSelectArgNumber = 8;
bool DataSharePredicates::result = false;
DataSharePredicates::DataSharePredicates()
{
    this->isRawSelection = false;
}

DataSharePredicates::DataSharePredicates(std::string rawSelection)
{
    DataShareAbsPredicates::SetWhereClause(rawSelection);
    this->isRawSelection = true;
}

DataSharePredicates::DataSharePredicates(OHOS::Parcel *source)
{
    if (source == nullptr) {
        this->judgeSource = false;
    } else {
        this->isRawSelection = source->ReadBool();
        std::string whereClause = (source->ReadInt32() != g_invalidObjectFlag) ? source->ReadString() : "";
        std::vector<std::string> whereArgs;
        if (source->ReadInt32() != g_invalidObjectFlag) {
            source->ReadStringVector(&whereArgs);
        }
        bool isDistinct = source->ReadBool();
        std::string index = (source->ReadInt32() != g_invalidObjectFlag) ? source->ReadString() : "";
        std::string group = (source->ReadInt32() != g_invalidObjectFlag) ? source->ReadString() : "";
        std::string order = (source->ReadInt32() != g_invalidObjectFlag) ? source->ReadString() : "";
        int limit = (source->ReadInt32() != g_invalidObjectFlag) ? source->ReadInt32() : -1;
        int offset = (source->ReadInt32() != g_invalidObjectFlag) ? source->ReadInt32() : -1;
        DataSharePredicatesUtils::SetWhereClauseAndArgs(this, whereClause, whereArgs);
        DataSharePredicatesUtils::SetAttributes(this, isDistinct, index, group, order, limit, offset);
    }
}
/**
 * Obtain value of variable isRawSelection.
 */
bool DataSharePredicates::IsRawSelection() const
{
    return isRawSelection;
}

bool DataSharePredicates::GetJudgeSource() const
{
    return judgeSource;
}

/**
 * Write DataSharePredicates object to Parcel.
 */
bool DataSharePredicates::Marshalling(OHOS::Parcel &parcel) const
{
    parcel.WriteBool(this->isRawSelection);
    MarshallingString(GetWhereClause(), parcel);
    MarshallingStringList(GetWhereArgs(), parcel);
    parcel.WriteBool(IsDistinct());
    MarshallingString(GetIndex(), parcel);
    MarshallingString(GetGroup(), parcel);
    MarshallingString(GetOrder(), parcel);

    int limit = GetLimit();
    int offset = GetOffset();
    if (limit != -1) {
        parcel.WriteInt32(g_validObjectFlag);
        parcel.WriteInt32(limit);
    } else {
        parcel.WriteInt32(g_invalidObjectFlag);
    }
    if (offset != -1) {
        parcel.WriteInt32(g_validObjectFlag);
        parcel.WriteInt32(offset);
    } else {
        parcel.WriteInt32(g_invalidObjectFlag);
    }

    return true;
}
/**
 * Read from Parcel object.
 */
DataSharePredicates* DataSharePredicates::Unmarshalling(OHOS::Parcel &parcel)
{
    result = true;
    return new DataSharePredicates(&parcel);
}

void DataSharePredicates::MarshallingString(std::string value, OHOS::Parcel &parcel) const
{
    if (value.length() != 0) {
        parcel.WriteInt32(g_validObjectFlag);
        parcel.WriteString(value);
    } else {
        parcel.WriteInt32(g_invalidObjectFlag);
    }
}

void DataSharePredicates::MarshallingStringList(std::vector<std::string> list, OHOS::Parcel &parcel) const
{
    if (list.size() != 0) {
        parcel.WriteInt32(g_validObjectFlag);
        parcel.WriteStringVector(list);
    } else {
        parcel.WriteInt32(g_invalidObjectFlag);
    }
}

DataSharePredicates::~DataSharePredicates() {}
} // namespace DataShare
} // namespace OHOS