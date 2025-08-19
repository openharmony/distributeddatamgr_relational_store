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
#include "data_asset.h"
using AssetValue = OHOS::NativeRdb::AssetValue;
constexpr int32_t DATA_ASSET_V0 = 10002451;
struct Data_Asset {
    int32_t cid = DATA_ASSET_V0;
    AssetValue asset_;
};

#endif // RELATIONAL_ASSET_IMPL_H
