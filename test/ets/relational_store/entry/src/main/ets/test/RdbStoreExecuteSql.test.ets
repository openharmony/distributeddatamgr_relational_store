/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from 'deccjsunit/index'
import relationalStore from '@ohos.data.relationalStore'

let context = globalThis.abilityContext;

const TAG = "[RELATIONAL_STORE_TRANSACTION_JSKITS_TEST]"

const STORE_CONFIG = {
  name: "executeSqlTest.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}

let rdbStore: relationalStore.RdbStore | undefined;

export default function ExecuteSqlTest() {
  describe('executeSqlTest', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
    })

    beforeEach(async () => {
      console.info(TAG + 'beforeEach')
    })

    afterEach(async () => {
      console.info(TAG + 'afterEach')
    })

    afterAll(async () => {
      console.info(TAG + 'afterAll')
      rdbStore = undefined;
      await relationalStore.deleteRdbStore(context, "executeSqlTest.db");
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.number concurrentExecuteDDLSQLTest0001
     * @tc.name Normal test case of executeSql, create table in multi-threaded environment
     * @tc.desc execute DDL by executeSql
     */
    it('concurrentExecuteDDLSQLTest0001', 0, async () => {
      console.log(TAG + "************* concurrentExecuteDDLSQLTest0001 start *************");
      const CREATE_TABLE = "CREATE TABLE IF NOT EXISTS test";
      const CREATE_TABLE_COLUMN = "(id INTEGER PRIMARY KEY, name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB)";
      const CREATE_INDEX = "CREATE INDEX IF NOT EXISTS indexTest";
      const CREATE_INDEX_TABLE = "ON test";
      const CREATE_INDEX_COLUMN = "(age)";

      try {
        await Promise.all(new Array<number>(50).fill(0).map(async (value, index) => {
          if (rdbStore == undefined) {
            expect(null).assertFail();
            return;
          }
          await rdbStore.executeSql(CREATE_TABLE + index + " " + CREATE_TABLE_COLUMN);
          await rdbStore.executeSql(CREATE_INDEX + index + " " + CREATE_INDEX_TABLE + index + " " + CREATE_INDEX_COLUMN);
        }))
        expect(true).assertTrue();
      } catch (error) {
        console.error(`${TAG} error in concurrentExecuteDDLSQLTest0001, code: ${error?.code} message: ${error?.message}`);
        expect(null).assertFail();
      }
      console.log(TAG + "************* concurrentExecuteDDLSQLTest0001 end *************");
    })
    console.log(TAG + "*************Unit Test End*************");
  })
} 
