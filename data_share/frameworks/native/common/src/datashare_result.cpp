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

#include "datashare_result.h"

#include "datashare_log.h"
#include "parcel_macro.h"

namespace OHOS {
namespace DataShare {
using namespace AppExecFwk;
/**
 * @brief A constructor used to create a DataShareResult instance
 * with the input parameter count specified.
 */
DataShareResult::DataShareResult(int count) : uri_("")
{
    count_ = count;
}

/**
 * @brief A constructor used to create a DataShareResult instance
 * with a Parcel object specified.
 */
DataShareResult::DataShareResult(Parcel &parcel) : uri_(""), count_(0)
{
    ReadFromParcel(parcel);
}

/**
 * @brief A constructor used to create a DataShareResult instance
 * with the input parameter uri specified
 */
DataShareResult::DataShareResult(const Uri &uri) : uri_(uri.ToString()), count_(0)
{}

/**
 * @brief A constructor used to create a DataShareResult instance
 * with input parameters uri, count, and failure specified.
 */
DataShareResult::DataShareResult(const Uri &uri, int count) : uri_(uri.ToString())
{
    count_ = count;
}

DataShareResult::~DataShareResult()
{}

/**
 * @brief Obtains the Uri object corresponding to the operation.
 * @return Obtains the Uri object corresponding to the operation.
 */
Uri DataShareResult::GetUri()
{
    return uri_;
}

/**
 * @brief Obtains the number of rows affected by the operation.
 * @return Returns the number of rows affected by the operation.
 */
int DataShareResult::GetCount()
{
    return count_;
}

/**
 * @brief Creates a DataShareResult instance based on the given Parcel object.
 * Used to transfer DataShareResult object using Parcel.
 * @param parcel Indicates the Parcel object.
 * @return Returns the DataShareResult object.
 */
DataShareResult *DataShareResult::CreateFromParcel(Parcel &parcel)
{
    DataShareResult *dataShareResult = new (std::nothrow) DataShareResult(parcel);
    if (dataShareResult == nullptr) {
        LOG_ERROR("DataShareResult::CreateFromParcel dataShareResult is nullptr");
    }
    return dataShareResult;
}

/**
 * @brief Prints out a string containing the class object information.
 * @return Returns object information.
 */
std::string DataShareResult::ToString()
{
    std::string stringBuilder = "DataShareResult(";
    stringBuilder.append("uri=").append(uri_.ToString()).append(" ");
    stringBuilder.append("count=").append(std::to_string(count_)).append(" ");
    stringBuilder.erase(stringBuilder.length() - 1, 1);
    stringBuilder.append(")");
    return stringBuilder;
}

/**
 * @brief Marshals a DataShareResult object into a Parcel.
 * @param parcel Indicates the Parcel object for marshalling.
 * @return Returns true if the marshalling is successful; returns false otherwise.
 */
bool DataShareResult::Marshalling(Parcel &parcel) const
{
    // uri_
    if (uri_.ToString().empty()) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, VALUE_NULL);
    } else {
        if (!parcel.WriteInt32(VALUE_OBJECT)) {
            return false;
        }
        if (!parcel.WriteParcelable(&uri_)) {
            return false;
        }
    }

    // count_
    if (!parcel.WriteInt32(count_)) {
        return false;
    }

    return true;
}

/**
 * @brief Unmarshals a DataShareResult object from a Parcel.
 * @param parcel Indicates the Parcel object for unmarshalling.
 * @return Returns true if the unmarshalling is successful; returns false otherwise.
 */
DataShareResult *DataShareResult::Unmarshalling(Parcel &parcel)
{
    DataShareResult *dataShareResult = new (std::nothrow) DataShareResult(0);
    if (dataShareResult != nullptr) {
        if (!dataShareResult->ReadFromParcel(parcel)) {
            delete dataShareResult;
            dataShareResult = nullptr;
        }
    }

    return dataShareResult;
}

bool DataShareResult::ReadFromParcel(Parcel &parcel)
{
    // uri_
    int32_t empty = VALUE_NULL;
    if (!parcel.ReadInt32(empty)) {
        return false;
    }

    if (empty == VALUE_OBJECT) {
        auto uri = parcel.ReadParcelable<Uri>();
        if (uri != nullptr) {
            uri_ = *uri;
            delete uri;
            uri = nullptr;
        } else {
            return false;
        }
    }

    // count_
    if (!parcel.ReadInt32(count_)) {
        return false;
    }

    return true;
}
}  // namespace DataShare
}  // namespace OHOS
