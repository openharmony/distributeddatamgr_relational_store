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
#include "relational_asset.h"

#include "logger.h"
#include "relational_store_error_code.h"
#include "securec.h"
namespace OHOS::RdbNdk {
RelationalAsset::RelationalAsset(AssetValue &asset) : asset_(std::move(asset)) {}

RelationalAsset *RelationalAsset::GetSelf(OH_Asset *asset)
{
    if (asset == nullptr) {
        LOG_ERROR("Parameters set error:asset is NULL ? %{public}d", (asset == nullptr));
        return nullptr;
    }
    return static_cast<RelationalAsset *>(asset);
}

AssetValue &RelationalAsset::Get()
{
    return asset_;
}
} // namespace OHOS::RdbNdk

using namespace OHOS::RdbNdk;
int OH_Asset_SetName(OH_Asset *asset, char *name, size_t length)
{
    auto rdbAsset = RelationalAsset::GetSelf(asset);
    if (rdbAsset == nullptr || name == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto innerAsset = rdbAsset->Get();
    innerAsset.name = name;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Asset_SetUri(OH_Asset *asset, char *uri, size_t length)
{
    auto rdbAsset = RelationalAsset::GetSelf(asset);
    if (rdbAsset == nullptr || uri == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto innerAsset = rdbAsset->Get();
    innerAsset.uri = uri;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Asset_SetPath(OH_Asset *asset, char *path, size_t length)
{
    auto rdbAsset = RelationalAsset::GetSelf(asset);
    if (rdbAsset == nullptr || path == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto innerAsset = rdbAsset->Get();
    innerAsset.path = path;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Asset_SetCreateTime(OH_Asset *asset, int64_t createTime)
{
    auto rdbAsset = RelationalAsset::GetSelf(asset);
    if (rdbAsset == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto innerAsset = rdbAsset->Get();
    innerAsset.createTime = std::to_string(createTime);
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Asset_SetModifyTime(OH_Asset *asset, int64_t modifyTime)
{
    auto rdbAsset = RelationalAsset::GetSelf(asset);
    if (rdbAsset == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto innerAsset = rdbAsset->Get();
    innerAsset.modifyTime = std::to_string(modifyTime);
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Asset_SetSize(OH_Asset *asset, size_t size)
{
    auto rdbAsset = RelationalAsset::GetSelf(asset);
    if (rdbAsset == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto innerAsset = rdbAsset->Get();
    innerAsset.size = std::to_string(size);
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Asset_SetStatus(OH_Asset *asset, OH_AssetStatus status)
{
    auto rdbAsset = RelationalAsset::GetSelf(asset);
    if (rdbAsset == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto innerAsset = rdbAsset->Get();
    innerAsset.status = status;
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Asset_GetName(OH_Asset *asset, char *name, size_t *length)
{
    auto rdbAsset = RelationalAsset::GetSelf(asset);
    if (rdbAsset == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto innerAsset = rdbAsset->Get();
    *length = innerAsset.path.size();
    errno_t result = memcpy_s(name, *length + 1, innerAsset.name.c_str(), innerAsset.name.length() + 1);
    if (result != EOK) {
        LOG_ERROR("memcpy_s failed, result is %{public}d", result);
        return OH_Rdb_ErrCode::RDB_ERR;
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Asset_GetUri(OH_Asset *asset, char *name, size_t *length)
{
    auto rdbAsset = RelationalAsset::GetSelf(asset);
    if (rdbAsset == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto innerAsset = rdbAsset->Get();
    *length = innerAsset.path.size();
    errno_t result = memcpy_s(name, *length + 1, innerAsset.uri.c_str(), *length + 1);
    if (result != EOK) {
        LOG_ERROR("memcpy_s failed, result is %{public}d", result);
        return OH_Rdb_ErrCode::RDB_ERR;
    }
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Asset_GetPath(OH_Asset *asset, char *name, size_t *length)
{
    auto rdbAsset = RelationalAsset::GetSelf(asset);
    if (rdbAsset == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto innerAsset = rdbAsset->Get();
    *length = innerAsset.path.size();
    errno_t result = memcpy_s(name, *length + 1, innerAsset.path.c_str(), *length + 1);
    if (result != EOK) {
        LOG_ERROR("memcpy_s failed, result is %{public}d", result);
        return OH_Rdb_ErrCode::RDB_ERR;
    }
    return OH_Rdb_ErrCode::RDB_OK;
}
int OH_Asset_GetCreateTime(OH_Asset *asset, int64_t *createTime)
{
    auto rdbAsset = RelationalAsset::GetSelf(asset);
    if (rdbAsset == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto innerAsset = rdbAsset->Get();
    *createTime = std::stoll(innerAsset.createTime);
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Asset_GetModifyTime(OH_Asset *asset, int64_t *modifyTime)
{
    auto rdbAsset = RelationalAsset::GetSelf(asset);
    if (rdbAsset == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto innerAsset = rdbAsset->Get();
    *modifyTime = std::stoll(innerAsset.modifyTime);
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Asset_GetSize(OH_Asset *asset, size_t *size)
{
    auto rdbAsset = RelationalAsset::GetSelf(asset);
    if (rdbAsset == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto innerAsset = rdbAsset->Get();
    *size = std::stoll(innerAsset.size);
    return OH_Rdb_ErrCode::RDB_OK;
}

int OH_Asset_GetStatus(OH_Asset *asset, OH_AssetStatus *status)
{
    auto rdbAsset = RelationalAsset::GetSelf(asset);
    if (rdbAsset == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    auto innerAsset = rdbAsset->Get();
    status = reinterpret_cast<OH_AssetStatus *>(innerAsset.status);
    return OH_Rdb_ErrCode::RDB_OK;
}

OH_Asset *OH_Asset_CreateOne()
{
    return new (std::nothrow) RelationalAsset();
}

int OH_Asset_DestroyOne(OH_Asset *asset)
{
    auto self = RelationalAsset::GetSelf(asset);
    if (self == nullptr) {
        return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
    }
    delete self;
    return OH_Rdb_ErrCode::RDB_OK;
}

OH_Asset **OH_Asset_CreateMultiple(uint32_t count)
{
    auto assets = new OH_Asset *[count];
    for (int i = 0; i < count; ++i) {
        assets[i] = new RelationalAsset();
    }
    return assets;
}

int OH_Asset_DestroyMultiple(OH_Asset **assets, uint32_t count)
{
    for (int i = 0; i < count; ++i) {
        auto self = RelationalAsset::GetSelf(assets[i]);
        if (self == nullptr) {
            return OH_Rdb_ErrCode::RDB_E_INVALID_ARGS;
        }
        delete self;
    }
    delete[] assets;
    return OH_Rdb_ErrCode::RDB_OK;
}
