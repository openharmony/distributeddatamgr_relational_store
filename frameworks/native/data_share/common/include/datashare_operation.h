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

#ifndef DATASHARE_OPERATION_H
#define DATASHARE_OPERATION_H

#include <map>
#include <memory>
#include "datashare_operation_builder.h"
#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "uri.h"
#include "parcel.h"

using Uri = OHOS::Uri;

namespace OHOS {
namespace DataShare {
class DataShareOperationBuilder;
class DataShareOperation final : public Parcelable, public std::enable_shared_from_this<DataShareOperation> {
public:
    ~DataShareOperation();

    DataShareOperation(
        const std::shared_ptr<DataShareOperation> &dataAbilityOperation, const std::shared_ptr<Uri> &withUri);
    DataShareOperation(Parcel &in);
    DataShareOperation(const std::shared_ptr<DataShareOperationBuilder> &builder);
    DataShareOperation();
    /**
     * @brief Creates an operation for inserting data.
     * @param uri Indicates the path of data to operate.
     * @return Returns an insert DataShareOperationBuilder object.
     */
    static std::shared_ptr<DataShareOperationBuilder> NewInsertBuilder(const std::shared_ptr<Uri> &uri);
    /**
     * @brief Creates an operation for updating data.
     * @param uri Indicates the path of data to operate.
     * @return Returns an update DataShareOperationBuilder object.
     */
    static std::shared_ptr<DataShareOperationBuilder> NewUpdateBuilder(const std::shared_ptr<Uri> &uri);
    /**
     * @brief Creates an operation for deleting data.
     * @param uri Indicates the path of data to operate.
     * @return Returns an delete DataShareOperationBuilder object.
     */
    static std::shared_ptr<DataShareOperationBuilder> NewDeleteBuilder(const std::shared_ptr<Uri> &uri);
    /**
     * @brief Creates an operation for asserting data.
     * @param uri Indicates the path of data to operate.
     * @return Returns an assert DataShareOperationBuilder object.
     */
    static std::shared_ptr<DataShareOperationBuilder> NewAssertBuilder(const std::shared_ptr<Uri> &uri);
    /**
     * @brief Obtains the value of the type attribute included in this DataShareOperation.
     * @return Returns the type included in this DataShareOperation.
     */
    int GetType() const;
    /**
     * @brief Obtains the value of the uri attribute included in this DataShareOperation.
     * @return Returns the uri included in this DataShareOperation.
     */
    std::shared_ptr<Uri> GetUri() const;
    /**
     * @brief Obtains the value of the databaseValuesBucket attribute included in this DataShareOperation.
     * @return Returns the databaseValuesBucket included in this DataShareOperation.
     */
    std::shared_ptr<DataShareValuesBucket> GetValuesBucket() const;
    /**
     * @brief Obtains the value of the expectedCount attribute included in this DataShareOperation.
     * @return Returns the expectedCount included in this DataShareOperation.
     */
    int GetExpectedCount() const;
    /**
     * @brief Obtains the value of the dataBasePredicates attribute included in this DataShareOperation.
     * @return Returns the dataBasePredicates included in this DataShareOperation.
     */
    std::shared_ptr<DataSharePredicates> GetDataAbilityPredicates() const;
    /**
     * @brief Obtains the value of the valuesBucketReferences attribute included in this DataShareOperation.
     * @return Returns the valuesBucketReferences included in this DataShareOperation.
     */
    std::shared_ptr<DataShareValuesBucket> GetValuesBucketReferences() const;
    /**
     * @brief Obtains the value of the dataAbilityPredicatesBackReferences attribute included in this
     * DataShareOperation.
     * @return Returns the dataAbilityPredicatesBackReferences included in this DataShareOperation.
     */
    std::map<int, int> GetDataAbilityPredicatesBackReferences() const;
    /**
     * @brief Checks whether an insert operation is created.
     * @return Returns true if it is an insert operation; returns false otherwise.
     */
    bool IsInsertOperation() const;
    /**
     * @brief Checks whether an delete operation is created.
     * @return Returns true if it is an delete operation; returns false otherwise.
     */
    bool IsDeleteOperation() const;
    /**
     * @brief Checks whether an update operation is created.
     * @return Returns true if it is an update operation; returns false otherwise.
     */
    bool IsUpdateOperation() const;
    /**
     * @brief Checks whether an assert operation is created.
     * @return Returns true if it is an assert operation; returns false otherwise.
     */
    bool IsAssertOperation() const;
    /**
     * @brief Checks whether an operation can be interrupted.
     * @return Returns true if the operation can be interrupted; returns false otherwise.
     */
    bool IsInterruptionAllowed() const;

    bool operator==(const DataShareOperation &other) const;
    DataShareOperation &operator=(const DataShareOperation &other);
    bool Marshalling(Parcel &out) const;
    static DataShareOperation *Unmarshalling(Parcel &in);

    /**
     * @brief Creates a DataShareOperation instance based on the given Parcel object
     * @param in Indicates the Parcel object.
     * @return Returns the DataShareOperation object.
     */
    static std::shared_ptr<DataShareOperation> CreateFromParcel(Parcel &in);

public:
    static constexpr int TYPE_INSERT = 1;
    static constexpr int TYPE_UPDATE = 2;
    static constexpr int TYPE_DELETE = 3;
    static constexpr int TYPE_ASSERT = 4;

private:
    void PutMap(Parcel &in);
    bool ReadFromParcel(Parcel &in);

private:
    // no object in parcel
    static constexpr int VALUE_NULL = 0;
    // object exist in parcel
    static constexpr int VALUE_OBJECT = 1;
    static constexpr int REFERENCE_THRESHOLD = 3 * 1024 * 1024;
    int type_ = -1;
    int expectedCount_ = 0;
    bool interrupted_ = false;
    std::shared_ptr<Uri> uri_ = nullptr;
    std::shared_ptr<DataShareValuesBucket> valuesBucket_ = nullptr;
    std::shared_ptr<DataSharePredicates> dataAbilityPredicates_ = nullptr;
    std::shared_ptr<DataShareValuesBucket> valuesBucketReferences_ = nullptr;
    std::map<int, int> dataAbilityPredicatesBackReferences_;
};
}  // namespace DataShare
}  // namespace OHOS
#endif  // DATASHARE_OPERATION_H