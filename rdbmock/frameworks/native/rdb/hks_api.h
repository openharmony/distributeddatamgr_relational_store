/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MOCK_STORE_HKS_API_H
#define MOCK_STORE_HKS_API_H

#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Init operation
 * @param keyAlias key alias
 * @param paramSet required parameter set
 * @param handle operation handle
 * @param token token
 * @return error code, see hks_type.h
 */
static int32_t HksInit(
    const struct HksBlob *keyAlias, const struct HksParamSet *paramSet, struct HksBlob *handle, struct HksBlob *token)
{
    return HKS_SUCCESS;
}

/**
 * @brief Update operation
 * @param handle operation handle
 * @param paramSet required parameter set
 * @param inData the data to update
 * @param outData output data
 * @return error code, see hks_type.h
 */
static int32_t HksUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    return HKS_SUCCESS;
}

/**
 * @brief Finish operation
 * @param handle operation handle
 * @param paramSet required parameter set
 * @param inData the data to update
 * @param outData output data
 * @return error code, see hks_type.h
 */
static int32_t HksFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    return HKS_SUCCESS;
}

/**
 * @brief Generate key
 * @param keyAlias key alias
 * @param paramSetIn required parameter set
 * @param paramSetOut output parameter set
 * @return error code, see hks_type.h
 */
static int32_t HksGenerateKey(
    const struct HksBlob *keyAlias, const struct HksParamSet *paramSetIn, struct HksParamSet *paramSetOut)
{
    return HKS_SUCCESS;
}

/**
 * @brief Check whether the key exists
 * @param keyAlias key alias
 * @param paramSetIn required parameter set
 * @param paramSetOut output parameter set
 * @return error code, see hks_type.h
 */
static int32_t HksKeyExist(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet)
{
    return HKS_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif /* MOCK_STORE_HKS_API_H */
