/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef RELATIONAL_VALUES_BUCKET_H
#define RELATIONAL_VALUES_BUCKET_H

/**
 * @addtogroup relationalStore
 * @{
 *
 * @brief RelationalStore module provides a series of external interfaces for insert data, delete data, update date,
 * and select data, as well as data encryption, hierarchical data protection, backup, and recovery functions.
 *
 * @syscap SystemCapability.DistributedDataManager.RelationalStore.Core
 * @since 10
 * @version 1.0
 */

/**
 * @file relational_values_bucket.h
 *
 * @brief Define the type of stored key value pairs.
 *
 * @since 10
 * @version 1.0
 */

#include <cstdint>
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Define OH_Rdb_VBucket type.
 *
 * @since 10
 * @version 1.0
 */
typedef struct {
    /** The id used to uniquely identify the OH_Rdb_VBucket struct. */
    int64_t id;
    /** Indicates the capability of OH_Rdb_VBucket. */
    uint16_t capability;
} OH_Rdb_VBucket;

/**
 * @brief Create an {@link OH_Rdb_VBucket} object.
 *
 * @return If the creation is successful, a pointer to the instance of the @link OH_Rdb_VBucket} structure is returned,
 * otherwise NULL is returned.
 * @see OH_Rdb_VBucket.
 * @since 10
 * @version 1.0
 */
OH_Rdb_VBucket *OH_Rdb_CreateValuesBucket();

/**
 * @brief Destroy the {@link OH_Rdb_VBucket} object and reclaim the memory occupied by the object.
 *
 * @param bucket Represents a pointer to an {@link OH_Rdb_VBucket} instance.
 * @return Returns the status code of the execution. Successful execution returns RDB_ERR_OK,
 * while failure returns a specific error code. Specific error codes can be referenced {@link OH_Rdb_ErrCode}.
 * @see OH_Rdb_VBucket.
 * @since 10
 * @version 1.0
 */
int OH_Rdb_DestroyValuesBucket(OH_Rdb_VBucket *bucket);

/**
 * @brief Put the const char * value to this {@link OH_Rdb_VBucket} object for the given column name.
 *
 * @param bucket Represents a pointer to an {@link OH_Rdb_VBucket} instance.
 * @param field Indicates the name of the column.
 * @param value Indicates the const char * value.
 * @return Returns the status code of the execution. Successful execution returns RDB_ERR_OK,
 * while failure returns a specific error code. Specific error codes can be referenced {@link OH_Rdb_ErrCode}.
 * @see OH_Rdb_VBucket.
 * @since 10
 * @version 1.0
 */
int OH_VBucket_PutText(OH_Rdb_VBucket *bucket, const char *field, const char *value);

/**
 * @brief Put the int64 value to this {@link OH_Rdb_VBucket} object for the given column name.
 *
 * @param bucket Represents a pointer to an {@link OH_Rdb_VBucket} instance.
 * @param field Indicates the name of the column.
 * @param value Indicates the int64 value.
 * @return Returns the status code of the execution. Successful execution returns RDB_ERR_OK,
 * while failure returns a specific error code. Specific error codes can be referenced {@link OH_Rdb_ErrCode}.
 * @see OH_Rdb_VBucket.
 * @since 10
 * @version 1.0
 */
int OH_VBucket_PutInt64(OH_Rdb_VBucket *bucket, const char *field, int64_t value);

/**
 * @brief Put the double value to this {@link OH_Rdb_VBucket} object for the given column name.
 *
 * @param bucket Represents a pointer to an {@link OH_Rdb_VBucket} instance.
 * @param field Indicates the name of the column.
 * @param value Indicates the double value.
 * @return Returns the status code of the execution. Successful execution returns RDB_ERR_OK,
 * while failure returns a specific error code. Specific error codes can be referenced {@link OH_Rdb_ErrCode}.
 * @see OH_Rdb_VBucket.
 * @since 10
 * @version 1.0
 */
int OH_VBucket_PutReal(OH_Rdb_VBucket *bucket, const char *field, double value);

/**
 * @brief Put the const uint8_t * value to this {@link OH_Rdb_VBucket} object for the given column name.
 *
 * @param bucket Represents a pointer to an {@link OH_Rdb_VBucket} instance.
 * @param field Indicates the name of the column.
 * @param value Indicates the const uint8_t * value.
 * @param size Indicates the size of value.
 * @return Returns the status code of the execution. Successful execution returns RDB_ERR_OK,
 * while failure returns a specific error code. Specific error codes can be referenced {@link OH_Rdb_ErrCode}.
 * @see OH_Rdb_VBucket.
 * @since 10
 * @version 1.0
 */
int OH_VBucket_PutBlob(OH_Rdb_VBucket *bucket, const char *field, const uint8_t *value, uint32_t size);

/**
 * @brief Put NULL to this {@link OH_Rdb_VBucket} object for the given column name.
 *
 * @param bucket Represents a pointer to an {@link OH_Rdb_VBucket} instance.
 * @param field Indicates the name of the column.
 * @return Returns the status code of the execution. Successful execution returns RDB_ERR_OK,
 * while failure returns a specific error code. Specific error codes can be referenced {@link OH_Rdb_ErrCode}.
 * @see OH_Rdb_VBucket.
 * @since 10
 * @version 1.0
 */
int OH_VBucket_PutNull(OH_Rdb_VBucket *bucket, const char *field);

/**
 * @brief Clear the {@link OH_Rdb_VBucket} object's values.
 *
 * @param bucket Represents a pointer to an {@link OH_Rdb_VBucket} instance.
 * @return Returns the status code of the execution. Successful execution returns RDB_ERR_OK,
 * while failure returns a specific error code. Specific error codes can be referenced {@link OH_Rdb_ErrCode}.
 * @see OH_Rdb_VBucket.
 * @since 10
 * @version 1.0
 */
int OH_VBucket_Clear(OH_Rdb_VBucket *bucket);
#ifdef __cplusplus
};
#endif

#endif // RELATIONAL_VALUES_BUCKET_H
