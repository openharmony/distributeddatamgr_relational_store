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
#define LOG_TAG "RelationalAsset"
#include "relational_asset.h"

#include "logger.h"
#include "relational_store_error_code.h"
#include "securec.h"
#include <cstdlib>

using namespace OHOS::RdbNdk;
constexpr int ASSET_TRANSFORM_BASE = 10;
int OH_Data_Asset_SetName(Data_Asset *asset, const char *name)
{
    if (asset == nullptr || name == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    asset->asset_.name = name;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Data_Asset_SetUri(Data_Asset *asset, const char *uri)
{
    if (asset == nullptr || uri == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }

    asset->asset_.uri = uri;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Data_Asset_SetPath(Data_Asset *asset, const char *path)
{
    if (asset == nullptr || path == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }

    asset->asset_.path = path;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Data_Asset_SetCreateTime(Data_Asset *asset, int64_t createTime)
{
    if (asset == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }

    asset->asset_.createTime = std::to_string(createTime);
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Data_Asset_SetModifyTime(Data_Asset *asset, int64_t modifyTime)
{
    if (asset == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }

    asset->asset_.modifyTime = std::to_string(modifyTime);
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Data_Asset_SetSize(Data_Asset *asset, size_t size)
{
    if (asset == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }

    asset->asset_.size = std::to_string(size);
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Data_Asset_SetStatus(Data_Asset *asset, Data_AssetStatus status)
{
    if (asset == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }

    asset->asset_.status = status;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Data_Asset_GetName(Data_Asset *asset, char *name, size_t *length)
{
    if (asset == nullptr) {
        LOG_ERROR("Asset get name error: asset is NULL ? %{public}d.", (asset == nullptr));
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    size_t nameLength = asset->asset_.name.size();
    if (nameLength >= *length) {
        LOG_ERROR("Asset get name error: length is too small ? %{public}d.", (nameLength >= *length));
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    errno_t result = strcpy_s(name, *length, asset->asset_.name.c_str());
    if (result != EOK) {
        LOG_ERROR("strcpy_s failed, result is %{public}d", result);
        return OH_Rdb_ErrCode::RDB_ERR;
    }
    *length = nameLength;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Data_Asset_GetUri(Data_Asset *asset, char *uri, size_t *length)
{
    if (asset == nullptr) {
        LOG_ERROR("Asset get uri error: asset is NULL ? %{public}d.", (asset == nullptr));
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    size_t uriLength = asset->asset_.uri.size();
    if (uriLength >= *length) {
        LOG_ERROR("Asset get uri error: length is too small ? %{public}d.", (uriLength >= *length));
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }

    errno_t result = strcpy_s(uri, *length, asset->asset_.uri.c_str());
    if (result != EOK) {
        LOG_ERROR("strcpy_s failed, result is %{public}d", result);
        return OH_Rdb_ErrCode::RDB_ERR;
    }
    *length = uriLength;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Data_Asset_GetPath(Data_Asset *asset, char *path, size_t *length)
{
    if (asset == nullptr) {
        LOG_ERROR("Asset get path error: asset is NULL ? %{public}d.", (asset == nullptr));
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    size_t pathLength = asset->asset_.path.size();
    if (pathLength >= *length) {
        LOG_ERROR("Asset get path error: length is too small ? %{public}d.", (pathLength >= *length));
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    errno_t result = strcpy_s(path, *length, asset->asset_.path.c_str());
    if (result != EOK) {
        LOG_ERROR("strcpy_s failed, result is %{public}d", result);
        return OH_Rdb_ErrCode::RDB_ERR;
    }
    *length = pathLength;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Data_Asset_GetCreateTime(Data_Asset *asset, int64_t *createTime)
{
    if (asset == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    char *endPtr;
    *createTime = strtol(asset->asset_.createTime.c_str(), &endPtr, ASSET_TRANSFORM_BASE);
    if (*endPtr != '\0') {
        LOG_ERROR("GetCreateTime failed");
        return OH_Rdb_ErrCode::RDB_ERR;
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Data_Asset_GetModifyTime(Data_Asset *asset, int64_t *modifyTime)
{
    if (asset == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    char *endPtr;
    *modifyTime = strtol(asset->asset_.modifyTime.c_str(), &endPtr, ASSET_TRANSFORM_BASE);
    if (*endPtr != '\0') {
        LOG_ERROR("GetModifyTime failed");
        return OH_Rdb_ErrCode::RDB_ERR;
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Data_Asset_GetSize(Data_Asset *asset, size_t *size)
{
    if (asset == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    char *endPtr;
    *size = strtol(asset->asset_.size.c_str(), &endPtr, ASSET_TRANSFORM_BASE);
    if (*endPtr != '\0') {
        LOG_ERROR("GetModifyTime failed");
        return OH_Rdb_ErrCode::RDB_ERR;
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Data_Asset_GetStatus(Data_Asset *asset, Data_AssetStatus *status)
{
    if (asset == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    *status = static_cast<Data_AssetStatus>(asset->asset_.status);
    return OH_Rdb_ErrCode::RDB_OK;
}

Data_Asset *OH_Data_Asset_CreateOne()
{
    return new (std::nothrow) Data_Asset();
}

int OH_Data_Asset_DestroyOne(Data_Asset *asset)
{
    delete asset;
    asset = nullptr;
    return OH_Rdb_ErrCode::RDB_OK;
}

Data_Asset **OH_Data_Asset_CreateMultiple(uint32_t count)
{
    auto assets = new Data_Asset *[count];
    for (uint32_t i = 0; i < count; ++i) {
        assets[i] = new Data_Asset();
    }
    return assets;
}

int OH_Data_Asset_DestroyMultiple(Data_Asset **assets, uint32_t count)
{
    for (uint32_t i = 0; i < count; ++i) {
        delete assets[i];
    }
    delete[] assets;
    assets = nullptr;
    return OH_Rdb_ErrCode::RDB_OK;
}
