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

/**
 * @addtogroup RDB
 * @{
 *
 * @brief The relational database (RDB) store manages data based on relational models.
 * With the underlying SQLite database, the RDB store provides a complete mechanism for managing local databases.
 * To satisfy different needs in complicated scenarios, the RDB store offers a series of APIs for performing operations
 * such as adding, deleting, modifying, and querying data, and supports direct execution of SQL statements.
 *
 * @since 10
 */

/**
 * @file oh_data_values_buckets.h
 *
 * @brief Provides functions and enumerations related to the data value buckets.
 *
 * @kit ArkData
 * @library libnative_rdb_ndk.z.so
 * @syscap SystemCapability.DistributedDataManager.RelationalStore.Core
 *
 * @since 16
 */


#ifndef OH_VALUES_BUCKETS_H
#define OH_VALUES_BUCKETS_H
#include "oh_values_bucket.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Define the OH_Data_VBuckets structure type.
 *
 * @since 16
 */
typedef struct OH_Data_VBuckets OH_Data_VBuckets;

/**
 * @brief Creates an OH_Data_VBuckets instance object.
 *
 * @return Returns a pointer to OH_Data_VBuckets instance when the execution is successful.
 * Otherwise, nullptr is returned. The memory must be released through the OH_VBuckets_Destroy
 * interface after the use is complete.
 * @see OH_VBuckets_Destroy.
 * @since 16
 */
OH_Data_VBuckets *OH_VBuckets_Create(void);

/**
 * @brief Destroys an OH_Data_VBuckets instance object.
 *
 * @param buckets Represents a pointer to an instance of OH_Data_VBuckets.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_VBuckets_Destroy(OH_Data_VBuckets *buckets);

/**
 * @brief Add an OH_VBucket to OH_Data_VBuckets object.
 *
 * @param buckets Represents a pointer to an instance of OH_Data_VBuckets.
 * @param row Represents a pointer to an instance of OH_VBucket.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_VBuckets_PutRow(OH_Data_VBuckets *buckets, const OH_VBucket *row);

/**
 * @brief Add an OH_Data_VBuckets to OH_Data_VBuckets object.
 *
 * @param buckets Represents a pointer to an instance of OH_Data_VBuckets.
 * @param rows Represents a pointer to an instance of OH_Data_VBuckets.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_VBuckets_PutRows(OH_Data_VBuckets *buckets, const OH_Data_VBuckets *rows);

/**
 * @brief Gets the number of rows in OH_Data_VBuckets object.
 *
 * @param buckets Represents a pointer to an instance of OH_Data_VBuckets.
 * @param count Represents the count of OH_VBucket in OH_Data_VBuckets. It is an output parameter.
 * @return Returns the error code.
 *         Returns {@link RDB_OK} if the execution is successful.
 *         Returns {@link RDB_E_INVALID_ARGS} if invalid input parameter.
 * @since 16
 */
int OH_VBuckets_RowCount(OH_Data_VBuckets *buckets, size_t *count);

#ifdef __cplusplus
};
#endif
#endif
/** @} */
