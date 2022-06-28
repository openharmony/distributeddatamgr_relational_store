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

#ifndef DATASHARE_OPERATION_BUILDER_H
#define DATASHARE_OPERATION_BUILDER_H

#include <map>
#include <memory>
#include "datashare_operation.h"
#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "uri.h"
#include "parcel.h"

using Uri = OHOS::Uri;
namespace OHOS {
namespace DataShare {
class DataShareOperation;
class DataShareOperationBuilder final : public std::enable_shared_from_this<DataShareOperationBuilder> {
    friend class DataShareOperation;

public:
    DataShareOperationBuilder(const int type, const std::shared_ptr<Uri> &uri);
    ~DataShareOperationBuilder();
    /**
     * @brief Creates a DataShareOperation object.
     * @return Returns the DataShareOperation object.
     */
    std::shared_ptr<DataShareOperation> Build();
    /**
     * @brief Sets the data records to be inserted or updated.
     * @param values Indicates the data values to be set.
     * @return Returns a DataShareOperationBuilder object containing the given values parameter.
     */
    std::shared_ptr<DataShareOperationBuilder> WithValuesBucket(std::shared_ptr<DataShareValuesBucket> &values);
    /**
     * @brief Sets filter criteria used for deleting updating or assert query data.
     * @param predicates Indicates the filter criteria to set. If this parameter is null, all data records will be
     * operated by default.
     * @return Returns an object containing the given filter criteria.
     */
    std::shared_ptr<DataShareOperationBuilder> WithPredicates(std::shared_ptr<DataSharePredicates> &predicates);
    /**
     * @brief Sets the expected number of rows to update ,delete or assert query.
     * @param count Indicates the expected number of rows to update or delete.
     * @return Returns a DataShareOperationBuilder object containing the given count parameter.
     */
    std::shared_ptr<DataShareOperationBuilder> WithExpectedCount(int count);
    /**
     * @brief Adds a back reference to be used as a filter criterion in withPredicates(DataSharePredicates).
     * @param requestArgIndex Indicates the index referencing the predicate parameter whose value is to be replaced.
     * @param previousResult Indicates the index referencing the historical DataShareResult used to replace the value
     * of the specified predicate parameter.
     * @return Returns a DataShareOperationBuilder object containing the given requestArgIndex and previousResult
     * parameters.
     */
    std::shared_ptr<DataShareOperationBuilder> WithPredicatesBackReference(int requestArgIndex, int previousResult);
    /**
     * @brief Adds a back reference to be used in withValuesBucket(DataShareValuesBucket).
     * @param backReferences Indicates the DataShareValuesBucket object containing a set of key-value pairs.
     * In each pair, the key specifies the value to be updated and the value specifies.
     * In each pair, the replace the specified value. This parameter cannot be null.
     * @return Returns a DataShareOperationBuilder object containing the given backReferences parameter.
     */
    std::shared_ptr<DataShareOperationBuilder> WithValueBackReferences(
            std::shared_ptr<DataShareValuesBucket> &backReferences);
    /**
     * @brief Sets an interrupt flag bit for a batch operation, which can be insert, update, delete, or assert.
     * @param interrupted Specifies whether a batch operation can be interrupted. The value true indicates that the
     * operation can be interrupted, and false indicates the opposite.
     * @return Returns a DataShareOperationBuilder object containing the given interrupted parameter.
     */
    std::shared_ptr<DataShareOperationBuilder> WithInterruptionAllowed(bool interrupted);

private:
    int type_;
    int expectedCount_;
    bool interrupted_;
    std::shared_ptr<Uri> uri_;
    std::shared_ptr<DataShareValuesBucket> valuesBucket_;
    std::shared_ptr<DataSharePredicates> dataSharePredicates_;
    std::shared_ptr<DataShareValuesBucket> valuesBucketReferences_;
    std::map<int, int> dataSharePredicatesBackReferences_;
};
}  // namespace DataShare
}  // namespace OHOS
#endif  // DATASHARE_OPERATION_BUILDER_H