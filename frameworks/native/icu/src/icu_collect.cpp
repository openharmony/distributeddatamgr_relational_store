/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#define LOG_TAG "ICUCollect"
#include "icu_collect.h"

#include <sqlite3sym.h>
#include <unicode/ucol.h>
#include <unicode/uclean.h>

#include "ohos/init_data.h"
#include "logger.h"
#include "rdb_errno.h"
#include "rdb_visibility.h"
#include "sqlite3.h"

API_EXPORT int32_t ConfigICULocale(sqlite3 *, const std::string &str) asm("ConfigICULocale");
API_EXPORT int32_t CleanUp() asm("CleanUp");
int32_t ConfigICULocale(sqlite3 *handle, const std::string &str)
{
    return OHOS::NativeRdb::ICUCollect::Locale(handle, str);
}

int32_t CleanUp()
{
    u_cleanup();
    return OHOS::NativeRdb::E_OK;
}

namespace OHOS::NativeRdb {
using namespace OHOS::Rdb;

int ICUCollect::Collate8Compare(void *p, int n1, const void *v1, int n2, const void *v2)
{
    UCollator *coll = reinterpret_cast<UCollator *>(p);
    UCharIterator i1;
    UCharIterator i2;
    UErrorCode status = U_ZERO_ERROR;

    uiter_setUTF8(&i1, (const char *)v1, n1);
    uiter_setUTF8(&i2, (const char *)v2, n2);

    UCollationResult result = ucol_strcollIter(coll, &i1, &i2, &status);

    if (U_FAILURE(status)) {
        LOG_ERROR("Ucol strcoll error.");
    }

    if (result == UCOL_LESS) {
        return -1;
    } else if (result == UCOL_GREATER) {
        return 1;
    }
    return 0;
}

void ICUCollect::LocalizedCollatorDestroy(void *collator)
{
    ucol_close(reinterpret_cast<UCollator *>(collator));
}

int32_t ICUCollect::Locale(sqlite3 *dbHandle, const std::string &str)
{
    UErrorCode status = U_ZERO_ERROR;
    SetHwIcuDirectory();

    UCollator *collator = ucol_open(str.c_str(), &status);
    if (U_FAILURE(status)) {
        LOG_ERROR("Can not open collator, status:%{public}d.", status);
        return E_ERROR;
    }
    ucol_setAttribute(collator, UCOL_STRENGTH, UCOL_PRIMARY, &status);
    if (U_FAILURE(status)) {
        LOG_ERROR("Set attribute of collator failed, status:%{public}d.", status);
        ucol_close(collator);
        return E_ERROR;
    }
    int err = sqlite3_create_collation_v2(dbHandle, "LOCALES", SQLITE_UTF8, collator, ICUCollect::Collate8Compare,
        (void (*)(void *))ICUCollect::LocalizedCollatorDestroy);
    if (err != SQLITE_OK) {
        LOG_ERROR("SCreate collator in sqlite3 failed err:%{public}d.", err);
        ucol_close(collator);
        return err;
    }
    return E_OK;
}

} // namespace OHOS::NativeRdb
