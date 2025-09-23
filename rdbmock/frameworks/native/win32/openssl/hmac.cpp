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

#include "hmac.h"

#include <cstring>
unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len, const unsigned char *d, size_t n,
    unsigned char *md, unsigned int *md_len)
{
    *md_len = 32;
    memset(md, 0, 32);
    return nullptr;
};

const EVP_MD *EVP_sha256()
{
    return nullptr;
}