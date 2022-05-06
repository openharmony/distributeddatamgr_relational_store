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

#ifndef DATASHARE_RESULT_H
#define DATASHARE_RESULT_H

#include "parcel.h"
#include "uri.h"

using Uri = OHOS::Uri;

namespace OHOS {
namespace DataShare {
class DataShareResult final : public Parcelable {
public:
    /**
     * @brief A constructor used to create a DataShareResult instance
     * with the input parameter count specified.
     */
    explicit DataShareResult(int count);

    /**
     * @brief A constructor used to create a DataShareResult instance
     * with the input parameter uri specified
     */
    explicit DataShareResult(const Uri &uri);

    /**
     * @brief A constructor used to create a DataShareResult instance
     * with a Parcel object specified.
     */
    explicit DataShareResult(Parcel &parcel);

    /**
     * @brief A constructor used to create a DataShareResult instance
     * with input parameters uri, count, and failure specified.
     */
    DataShareResult(const Uri &uri, int count);

    ~DataShareResult();

    /**
     * @brief Obtains the Uri object corresponding to the operation.
     * @return Obtains the Uri object corresponding to the operation.
     */
    Uri GetUri();

    /**
     * @brief Obtains the number of rows affected by the operation.
     * @return Returns the number of rows affected by the operation.
     */
    int GetCount();

    /**
     * @brief Prints out a string containing the class object information.
     * @return Returns object information.
     */
    std::string ToString();

    /**
     * @brief Marshals a DataShareResult object into a Parcel.
     * @param parcel Indicates the Parcel object for marshalling.
     * @return Returns true if the marshalling is successful; returns false otherwise.
     */
    virtual bool Marshalling(Parcel &parcel) const;

    /**
     * @brief Unmarshals a DataShareResult object from a Parcel.
     * @param parcel Indicates the Parcel object for unmarshalling.
     * @return Returns true if the unmarshalling is successful; returns false otherwise.
     */
    static DataShareResult *Unmarshalling(Parcel &parcel);

    /**
     * @brief Creates a DataShareResult instance based on the given Parcel object.
     * Used to transfer DataShareResult object using Parcel.
     * @param parcel Indicates the Parcel object.
     * @return Returns the DataShareResult object.
     */
    static DataShareResult *CreateFromParcel(Parcel &parcel);

private:
    Uri uri_;
    int count_;

    bool ReadFromParcel(Parcel &parcel);
    // no object in parcel
    static constexpr int VALUE_NULL = -1;
    // object exist in parcel
    static constexpr int VALUE_OBJECT = 1;
};
}  // namespace DataShare
}  // namespace OHOS
#endif  // DATASHARE_RESULT_H
