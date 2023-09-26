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

#ifndef OH_ASSET_H
#define OH_ASSET_H
/**
 * @addtogroup RDB
 * @{
 *
 * @brief The relational database (RDB) store manages data based on relational models.
 * With the underlying SQLite database, the RDB store provides a complete mechanism for managing local databases.
 * To satisfy different needs in complicated scenarios, the RDB store offers a series of APIs for performing operations
 * such as adding, deleting, modifying, and querying data, and supports direct execution of SQL statements.
 *
 * @syscap SystemCapability.DistributedDataManager.RelationalStore.Core
 * @since 11
 */

/**
 * @file oh_asset.h
 *
 * @brief Provides the data type of asset.
 *
 * @since 11
 */
#include <cstddef>
#ifdef __cplusplus
extern "C" {
#endif
/**
 * @brief Indicates max length of the asset name.
 *
 * @since 11
 */
#define MAX_NAME_SIZE 1024

/**
 * @brief Indicates max length of the asset uri.
 *
 * @since 11
 */
#define MAX_URI_SIZE 2048

/**
 * @brief Indicates max length of the asset path.
 *
 * @since 11
 */
#define MAX_PATH_SIZE 1024

/**
 * @brief Indicates max length of the asset size.
 *
 * @since 11
 */
#define MAX_HASH_SIZE 64
/**
 * @brief Describes the status of asset.
 *
 * @since 11
 */
typedef enum OH_AssetStatus {
    /**
     * @brief Means the status of asset is null.
     */
    ASSET_NULL,

    /**
     * @brief Means the status of asset is normal.
     */
    ASSET_NORMAL,

    /**
     * @brief Means the asset needs to be inserted.
     */
    ASSET_INSERT,

    /**
     * @brief Means the asset needs to be updated.
     */
    ASSET_UPDATE,

    /**
     * @brief Means the asset needs to be deleted.
     */
    ASSET_DELETE,

    /**
     * @brief Means the status of asset is abnormal.
     */
    ASSET_ABNORMAL,

    /**
     * @brief Means the status of asset is downloading.
     */
    ASSET_DOWNLOADING
} OH_AssetStatus;

/**
 * @brief Indicates version of {@link OH_Asset}
 *
 * @since 11
 */
#define DISTRIBUTED_ASSET_VERSION 1
/**
 * @brief Define the OH_Asset structure type.
 *
 * Provides information of an asset.
 *
 * @since 11
 */
typedef struct OH_Asset {
    /**
     * The version used to uniquely identify the OH_Asset struct.
     */
    int version;

    /**
     * The name of the asset. Max length is 1024 bytes.
     */
    char name[MAX_NAME_SIZE];

    /**
     * The uri of the asset. Max length is 2 * 1024 bytes.
     */
    char uri[MAX_URI_SIZE];

    /**
     * The path of the asset. Max length is 1024 bytes.
     */
    char path[MAX_PATH_SIZE];

    /**
     * The create time of the asset.
     */
    int64_t createTime;

    /**
     * The most recently modified time of the asset.
     */
    int64_t modifyTime;

    /**
     * The size of the asset.
     */
    size_t size;

    /**
     * The status of the asset.
     */
    int32_t status;

    /**
     * The hash code of the asset.
     */
    char hash[MAX_HASH_SIZE];
} OH_Asset;

#ifdef __cplusplus
};
#endif
#endif //OH_ASSET_H
