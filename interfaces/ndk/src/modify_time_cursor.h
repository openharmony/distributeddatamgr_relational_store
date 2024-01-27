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

#ifndef RELATIONAL_MODIFY_TIME_CURSOR_H
#define RELATIONAL_MODIFY_TIME_CURSOR_H
#include "relational_cursor.h"
#include "rdb_store.h"
#include "result_set.h"
namespace OHOS::RdbNdk {
class ModifyTimeCursor : public RelationalCursor {
public:
    using ResultSet = OHOS::NativeRdb::ResultSet;
    using ModifyTime = OHOS::NativeRdb::RdbStore::ModifyTime;
    using PRIKey = OHOS::NativeRdb::RdbStore::PRIKey;
    explicit ModifyTimeCursor(ModifyTime &&modifyTime);
    ~ModifyTimeCursor() override = default;

protected:
    int GetSize(int32_t columnIndex, size_t *size) override;
    int GetText(int32_t columnIndex, char *value, int length) override;
    int GetInt64(int32_t columnIndex, int64_t *value) override;
    int GetReal(int32_t columnIndex, double *value) override;

private:
    inline PRIKey ConvertPRIKey()
    {
        std::vector<uint8_t> hash;
        std::shared_ptr<ResultSet> result = modifyTime_;
        if (result == nullptr) {
            return PRIKey();
        }
        result->GetBlob(0, hash);
        return modifyTime_.GetOriginKey(hash);
    }

    ModifyTime modifyTime_;
};
} // namespace OHOS::RdbNdk
#endif // RELATIONAL_MODIFY_TIME_CURSOR_H
