#include "ohos.data.sendableRelationalStore.proj.hpp"
#include "ohos.data.sendableRelationalStore.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"


namespace {
// To be implemented.

::ohos::data::sendableRelationalStore::NonSendableBucket FromSendableValuesBucket(::ohos::data::sendableRelationalStore::ValuesBucket const &valuesBucket) {
    TH_THROW(std::runtime_error, "FromSendableValuesBucket not implemented");
}

::ohos::data::sendableRelationalStore::ValuesBucket ToSendableValuesBucket(::ohos::data::sendableRelationalStore::NonSendableBucket const &valuesBucket) {
    TH_THROW(std::runtime_error, "ToSendableValuesBucket not implemented");
}

::ohos::data::sendableRelationalStore::NonSendableAsset FromSendableAsset(::ohos::data::sendableRelationalStore::Asset const &asset) {
    TH_THROW(std::runtime_error, "FromSendableAsset not implemented");
}

::ohos::data::sendableRelationalStore::Asset ToSendableAsset(::ohos::data::sendableRelationalStore::NonSendableAsset const &asset) {
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
