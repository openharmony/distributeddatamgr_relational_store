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
namespace OHOS::RdbNdk {

RelationalAsset::RelationalAsset(AssetValue &asset) : OH_Asset(), asset_(std::move(asset))
{
    version = DISTRIBUTED_ASSET_VERSION;
}
RelationalAsset *RelationalAsset::GetSelf(OH_Asset *asset)
{
    if (asset == nullptr || asset->version != DISTRIBUTED_ASSET_VERSION) {
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
