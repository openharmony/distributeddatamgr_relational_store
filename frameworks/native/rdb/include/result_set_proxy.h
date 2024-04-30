/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef NATIVE_RDB_RESULT_SET_PROXY_H
#define NATIVE_RDB_RESULT_SET_PROXY_H

#include "iremote_proxy.h"
#include "iresult_set.h"

namespace OHOS::NativeRdb {
class ResultSetProxy : public IRemoteProxy<IResultSet> {
public:
    explicit ResultSetProxy(const sptr<IRemoteObject> &impl);
    ~ResultSetProxy();
    int GetColumnCount(int &count) override;
    int GetColumnType(int columnIndex, ColumnType &columnType) override;
    int GetRowCount(int &count) override;
    int GetRowIndex(int &position) const override;
    int GoTo(int offset) override;
    int GoToRow(int position) override;
    int GoToFirstRow() override;
    int GoToLastRow() override;
    int GoToNextRow() override;
    int GoToPreviousRow() override;
    int IsEnded(bool &result) override;
    int IsStarted(bool &result) const override;
    int IsAtFirstRow(bool &result) const override;
    int IsAtLastRow(bool &result) override;
    int Get(int32_t col, ValueObject &value) override;
    int GetSize(int columnIndex, size_t &size) override;
    int Close() override;

protected:
    std::pair<int, std::vector<std::string>> GetColumnNames() override;

private:
    // the max capacity for ipc is 800KB.
    static const size_t MAX_IPC_CAPACITY = 800 * 1024;
    template<typename... T>
    int Send(uint32_t code, T &...output) const;

    template<typename... T>
    int SendRequest(uint32_t code, MessageParcel &reply, const T &...input) const;

    sptr<IRemoteObject> remote_;
};
} // namespace OHOS::NativeRdb
#endif // NATIVE_RDB_RESULT_SET_PROXY_H
