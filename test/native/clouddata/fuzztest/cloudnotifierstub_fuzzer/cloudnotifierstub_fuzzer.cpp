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
#include <fuzzer/FuzzedDataProvider.h>

#include "cloud_notifier_stub.h"

using namespace OHOS;
using namespace OHOS::CloudData;
namespace OHOS {
const std::u16string INTERFACE_TOKEN = u"OHOS.CloudData.ICloudNotifier";
constexpr uint32_t CODE_MIN = 0;
constexpr uint32_t CODE_MAX = 2;

bool OnRemoteRequestFuzz(FuzzedDataProvider &provider)
{
    auto syncCompleteHandler = [](uint32_t, Details &&) {};
    std::shared_ptr<CloudNotifierStub> notifierStub = std::make_shared<CloudNotifierStub>(syncCompleteHandler);
    uint32_t code = provider.ConsumeIntegralInRange<uint32_t>(CODE_MIN, CODE_MAX);
    std::vector<uint8_t> remainingData = provider.ConsumeRemainingBytes<uint8_t>();
    MessageParcel request;
    request.WriteInterfaceToken(INTERFACE_TOKEN);
    request.WriteBuffer(static_cast<void *>(remainingData.data()), remainingData.size());
    request.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    notifierStub->OnRemoteRequest(code, request, reply, option);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::OnRemoteRequestFuzz(provider);
    return 0;
}