/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export default namespace relationalStore {
    loadLibrary("result_set_ani")

    export interface ResultSet {
        /**
        * Obtains the column index based on the specified column name.
        * The column name is passed as an input parameter.
        *
        * @param { string } columnName - Indicates the name of the specified column in the result set.
        * @returns { number } The index of the specified column.
        * @syscap SystemCapability.DistributedDataManager.RelationalStore.Core
        * @crossplatform
        * @since 12
        */
        getColumnIndex(columnName: string): number;

        /**
        * Obtains the value of the specified column in the current row as string.
        * The implementation class determines whether to throw an exception if the value of the specified column
        * in the current row is null or the specified column is not of the string type.
        *
        * @param { number } columnIndex - Indicates the specified column index, which starts from 0.
        * @returns { string } The value of the specified column as a string.
        * @syscap SystemCapability.DistributedDataManager.RelationalStore.Core
        * @crossplatform
        * @since 12
        */
        getString(columnIndex: number): string;

        /**
        * Obtains the value of the specified column in the current row as long.
        * The implementation class determines whether to throw an exception if the value of the specified column
        * in the current row is null, the specified column is not of the integer type.
        *
        * @param { number } columnIndex - Indicates the specified column index, which starts from 0.
        * @returns { number } The value of the specified column as a long.
        * @syscap SystemCapability.DistributedDataManager.RelationalStore.Core
        * @crossplatform
        * @since 12
        */
        getLong(columnIndex: number): number;
    }

    class ResultSetInner implements ResultSet {
        private nativePtr: long = 0;

        native getColumnIndex(columnName: string): number;
        native getString(columnIndex: number): string;
        native getLong(columnIndex: number): number;
    }
}
