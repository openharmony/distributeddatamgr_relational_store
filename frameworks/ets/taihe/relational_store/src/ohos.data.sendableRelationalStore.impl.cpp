/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "ohos.data.sendableRelationalStore.proj.hpp"
#include "ohos.data.sendableRelationalStore.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"


namespace {

::ohos::data::sendableRelationalStore::NonSendableBucket FromSendableValuesBucket(
    ::ohos::data::sendableRelationalStore::ValuesBucket const &valuesBucket)
{
    TH_THROW(std::runtime_error, "FromSendableValuesBucket not implemented");
}

::ohos::data::sendableRelationalStore::ValuesBucket ToSendableValuesBucket(
    ::ohos::data::sendableRelationalStore::NonSendableBucket const &valuesBucket)
{
    TH_THROW(std::runtime_error, "ToSendableValuesBucket not implemented");
}

::ohos::data::sendableRelationalStore::NonSendableAsset FromSendableAsset(
    ::ohos::data::sendableRelationalStore::Asset const &asset)
{
    TH_THROW(std::runtime_error, "FromSendableAsset not implemented");
}

::ohos::data::sendableRelationalStore::Asset ToSendableAsset(
    ::ohos::data::sendableRelationalStore::NonSendableAsset const &asset)
{
    TH_THROW(std::runtime_error, "ToSendableAsset not implemented");
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_FromSendableValuesBucket(FromSendableValuesBucket);
TH_EXPORT_CPP_API_ToSendableValuesBucket(ToSendableValuesBucket);
TH_EXPORT_CPP_API_FromSendableAsset(FromSendableAsset);
TH_EXPORT_CPP_API_ToSendableAsset(ToSendableAsset);
// NOLINTEND
