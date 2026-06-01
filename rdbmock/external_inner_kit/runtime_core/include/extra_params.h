/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#ifndef OHOS_ABILITY_BASE_EXTRA_PARAMS_H
#define OHOS_ABILITY_BASE_EXTRA_PARAMS_H

#include <string>

#include "parcel.h"

using string = std::string;

namespace OHOS {
namespace AppExecFwk {
class ExtraParams : public Parcelable {
public:
    /**
     * @brief A default constructor used to create an empty {@code ExtraParams} instance.
     * @param none
     */
    ExtraParams();
    /**
     * @brief A copy constructor used to create an empty {@code ExtraParams} instance.
     * @param other indicates object instance.
     */
    ExtraParams(const ExtraParams &other);
    /**
     * @brief Overloading assignment operators to create the same object instance.
     * @param other Indicates object instance.
     */
    ExtraParams &operator=(const ExtraParams &other);

    /**
     * @brief Judge whether the parameter of extraparam instance is equal to that of other instance parameter
     * @param other Indicates object instance.
     * @return returns true the parameter of extraparam instance is equal to that of other instance parameter
     *  otherwise false
     */
    bool operator==(const ExtraParams &other) const;

    /**
     * @brief A constructor used to create an {@code ExtraParams} instance based on the input parameters{@code devType},
     * {@code targetBundleName}, and {@code description}.
     *
     * @param devType Indicates the type of devices to be matched. This parameter can be any combination of
     * {@link #DEVICETYPE_SMART_PHONE}, {@link #DEVICETYPE_SMART_PAD}, {@link #DEVICETYPE_SMART_WATCH}, and
     * {@link #DEVICETYPE_SMART_TV}.
     *
     * @param targetBundleName Indicates the bundle name of the target application where the ability will be migrated.
     *
     * @param description Indicates the description used for device filtering.
     *
     * @param jsonParams Indicates the custom JSON parameters to be used as filter conditions.
     *
     * @return none
     */
    ExtraParams(const std::vector<string> &devType, const string &targetBundleName, const string &description,
        const string &jsonParams);

    /**
     * @brief A destructor release an empty {@code ExtraParams} instance.
     * @param none
     */
    ~ExtraParams();

    /**
     * @brief Sets the list of device types.
     *
     * @param devType Indicates the type of devices to be matched. This parameter can be any combination of
     * {@link #DEVICETYPE_SMART_PHONE}, {@link #DEVICETYPE_SMART_PAD}, {@link #DEVICETYPE_SMART_WATCH}, and
     * {@link #DEVICETYPE_SMART_TV}.
     *
     * @return none
     */
    void SetDevType(const std::vector<string> &devType);

    /**
     * @brief Obtains the list of device types.
     *
     * @param none
     *
     * @return Returns the list of device types.
     */
    std::vector<string> GetDevType() const;

    /**
     * @brief Sets the bundle name of the target application where ability will be migrated.
     *
     * @param targetBundleName Indicates the bundle name of the target application to set.
     *
     * @return none
     */
    void SetTargetBundleName(const string &targetBundleName);

    /**
     * @brief Obtains the bundle name of the target application where the ability will be migrated.
     *
     * @return Returns the bundle name of the target application.
     *
     * @return none
     */
    string GetTargetBundleName() const;

    /**
     * @brief Sets the description used for device filtering.
     *
     * @param jsonParams Indicates the device description to set.
     *
     * @return none
     */
    void SetJsonParams(const string &jsonParams);

    /**
     * @brief Obtains the custom JSON parameters used as filter conditions.
     *
     * @param none
     *
     * @return Returns the custom JSON parameters.
     */
    string GetJsonParams() const;

    /**
     * @brief Sets the custom JSON parameters to be used as filter conditions.
     *
     * @param description Indicates the custom JSON parameters to set.
     *
     */
    void SetDescription(const string &description);

    /**
     * @brief Obtains the description used for device filtering.
     *
     * @param none
     *
     * @return Returns the description used for device filtering.
     */
    string GetDescription() const;

    /**
     * @brief Marshals this {@code ExtraParams} object into a {@link ohos.utils.Parcel} object.
     *
     * @param parcel Indicates the {@code Parcel} object for marshalling.
     *
     * @return Returns {@code true} if the marshalling is successful; returns {@code false} otherwise.
     */
    virtual bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Unmarshals this {@code ExtraParams} object from a {@link ohos.utils.Parcel} object.
     *
     * @param parcel Indicates the {@code Parcel} object for unmarshalling.
     *
     * @return Returns {@code true} if the unmarshalling is successful; returns {@code false} otherwise.
     */
    static ExtraParams *Unmarshalling(Parcel &parcel);

public:
    // Indicates a smart speaker.
    static constexpr char DEVICETYPE_SMART_SPEAKER[] = "00A";

    // Indicates a desktop pad.
    static constexpr char DEVICETYPE_DESKTOP_PAD[] = "00B";

    // Indicates a laptop.
    static constexpr char DEVICETYPE_LAPTOP[] = "00C";

    // Indicates a smartphone.
    static constexpr char DEVICETYPE_SMART_PHONE[] = "00E";

    // Indicates a tablet.
    static constexpr char DEVICETYPE_SMART_PAD[] = "011";

    // Indicates a smart watch.
    static constexpr char DEVICETYPE_SMART_WATCH[] = "06D";

    // Indicates a smart car.
    static constexpr char DEVICETYPE_SMART_CAR[] = "083";

    // Indicates a kids smart watch.
    static constexpr char DEVICETYPE_CHILDREN_WATCH[] = "085";

    // Indicates a smart TV.
    static constexpr char DEVICETYPE_SMART_TV[] = "09C";

private:
    string targetBundleName_;
    string description_;
    string jsonParams_;
    std::vector<string> devType_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_BASE_EXTRA_PARAMS_H
