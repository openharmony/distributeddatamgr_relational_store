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
#ifndef RELATIONAL_ASSET_IMPL_H
#define RELATIONAL_ASSET_IMPL_H

#include "asset_value.h"
#include "asset.h"
struct Data_Asset {};
namespace OHOS::RdbNdk {
using AssetValue = OHOS::NativeRdb::AssetValue;
class RelationalAsset : public Data_Asset {
public:
    RelationalAsset() = default;
    explicit RelationalAsset(AssetValue &asset);
    static RelationalAsset *GetSelf(Data_Asset *asset);
    AssetValue &Get();
    void ConvertAsset(Data_Asset *value, NativeRdb::AssetValue *asset) {}

private:
    AssetValue asset_;
};
} // namespace OHOS::RdbNdk

#endif // RELATIONAL_ASSET_IMPL_H
