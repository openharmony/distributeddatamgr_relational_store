/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from "@ohos/hypium";
import data_relationalStore from '@ohos.data.relationalStore';
import abilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';

let context = abilityDelegatorRegistry.getAbilityDelegator().getAppContext().getApplicationContext();
const TAG = "[RdbErrMsgRange]";
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" +
  "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB)";
const STORE_CONFIG: data_relationalStore.StoreConfig = {
  name: "RdbErrMsgRange.db",
  securityLevel: data_relationalStore.SecurityLevel.S1,
};

let rdbStore: data_relationalStore.RdbStore;
export default function rdbErrMsgRangeTest() {
  describe('rdbErrMsgRangeTest', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
    })
    beforeEach(async (done: Function) => {
      console.info(TAG + 'beforeEach')
      try {
        rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG);
        await rdbStore.executeSql(CREATE_TABLE_TEST);
        await rdbStore.executeSql("DELETE FROM test");
        const valueBucket: data_relationalStore.ValuesBucket = {
          "name": "zhangsan",
          "age": 18,
          "salary": 100.5,
          "blobType": new Uint8Array([1, 2, 3]),
        }
        await rdbStore.insert("test", valueBucket);
      } catch (err) {
        console.log(`${TAG} beforeEach error code:${err.code}, message:${err.message}`);
      }
      done();
    })
    afterEach(async (done: Function) => {
      console.info(TAG + 'afterEach')
      try {
        await rdbStore.close();
      } catch (err) {
        console.log(`${TAG} afterEach close error code:${err.code}, message:${err.message}`);
      }
      await data_relationalStore.deleteRdbStore(context, "RdbErrMsgRange.db");
      done();
    })
    afterAll(async () => {
      console.info(TAG + 'afterAll')
    })

    console.log(TAG + "*************Unit Test Begin*************");

    // ===== 14800013 (column index out of range) =====
    // IMPORTANT: value getters check the row position first, so we must goToNextRow()
    // to a valid row before passing an out-of-range column index; otherwise the native
    // getter returns row-out-of-range (14800012) before it ever checks the column.
    // Table has 5 columns (valid index 0..4); 99 is out of range.
    // code is compared with == (loose): a normal ResultSet throws a string code
    // (RDB_NAPI_ASSERT), a LiteResultSet throws an int code (RDB_NAPI_ASSERT_INT).
    function assertColumnRange(e: any): void {
      console.log(`${TAG} 14800013 code:${e.code}, message:${e.message}`);
      expect(e.code == 14800013).assertTrue();
      expect(e.message.includes("The column index is")).assertTrue();
      expect(e.message.includes("column count is")).assertTrue();
    }

    async function rsAtFirstRow(sql: string): Promise<data_relationalStore.ResultSet> {
      let rs = await rdbStore.querySql(sql);
      rs.goToNextRow();
      return rs;
    }

    it('ErrMsg_14800013_GetLong_ColumnRange_001', 0, async (done: Function) => {
      console.log(TAG + "************* 001 start *************");
      try {
        (await rsAtFirstRow("SELECT * FROM test")).getLong(99);
        expect(true).assertFail();
      } catch (e) { assertColumnRange(e); }
      done();
    })

    it('ErrMsg_14800013_GetString_ColumnRange_002', 0, async (done: Function) => {
      console.log(TAG + "************* 002 start *************");
      try {
        (await rsAtFirstRow("SELECT * FROM test")).getString(99);
        expect(true).assertFail();
      } catch (e) { assertColumnRange(e); }
      done();
    })

    it('ErrMsg_14800013_GetBlob_ColumnRange_003', 0, async (done: Function) => {
      console.log(TAG + "************* 003 start *************");
      try {
        (await rsAtFirstRow("SELECT * FROM test")).getBlob(99);
        expect(true).assertFail();
      } catch (e) { assertColumnRange(e); }
      done();
    })

    it('ErrMsg_14800013_GetDouble_ColumnRange_004', 0, async (done: Function) => {
      console.log(TAG + "************* 004 start *************");
      try {
        (await rsAtFirstRow("SELECT * FROM test")).getDouble(99);
        expect(true).assertFail();
      } catch (e) { assertColumnRange(e); }
      done();
    })

    it('ErrMsg_14800013_IsColumnNull_ColumnRange_005', 0, async (done: Function) => {
      console.log(TAG + "************* 005 start *************");
      try {
        (await rsAtFirstRow("SELECT * FROM test")).isColumnNull(99);
        expect(true).assertFail();
      } catch (e) { assertColumnRange(e); }
      done();
    })

    it('ErrMsg_14800013_GetValue_ColumnRange_006', 0, async (done: Function) => {
      console.log(TAG + "************* 006 start *************");
      try {
        (await rsAtFirstRow("SELECT * FROM test")).getValue(99);
        expect(true).assertFail();
      } catch (e) { assertColumnRange(e); }
      done();
    })

    it('ErrMsg_14800013_GetAsset_ColumnRange_030', 0, async (done: Function) => {
      console.log(TAG + "************* 030 start *************");
      try {
        (await rsAtFirstRow("SELECT * FROM test")).getAsset(99);
        expect(true).assertFail();
      } catch (e) { assertColumnRange(e); }
      done();
    })

    it('ErrMsg_14800013_GetAssets_ColumnRange_031', 0, async (done: Function) => {
      console.log(TAG + "************* 031 start *************");
      try {
        (await rsAtFirstRow("SELECT * FROM test")).getAssets(99);
        expect(true).assertFail();
      } catch (e) { assertColumnRange(e); }
      done();
    })

    it('ErrMsg_14800013_GetFloat32Array_ColumnRange_032', 0, async (done: Function) => {
      console.log(TAG + "************* 032 start *************");
      try {
        (await rsAtFirstRow("SELECT * FROM test")).getFloat32Array(99);
        expect(true).assertFail();
      } catch (e) { assertColumnRange(e); }
      done();
    })

    // ===== 14800013 on LiteResultSet (querySqlWithoutRowCount) =====
    async function liteRsAtFirstRow(sql: string): Promise<data_relationalStore.ResultSet> {
      let rs = await rdbStore.querySqlWithoutRowCount(sql);
      rs.goToNextRow();
      return rs;
    }

    it('ErrMsg_14800013_Lite_GetLong_ColumnRange_010', 0, async (done: Function) => {
      console.log(TAG + "************* 010 start *************");
      try {
        (await liteRsAtFirstRow("SELECT * FROM test")).getLong(99);
        expect(true).assertFail();
      } catch (e) { assertColumnRange(e); }
      done();
    })

    it('ErrMsg_14800013_Lite_GetString_ColumnRange_033', 0, async (done: Function) => {
      console.log(TAG + "************* 033 start *************");
      try {
        (await liteRsAtFirstRow("SELECT * FROM test")).getString(99);
        expect(true).assertFail();
      } catch (e) { assertColumnRange(e); }
      done();
    })

    /**
     * getColumnName does not depend on row position, so no goToNextRow is needed.
     */
    it('ErrMsg_14800013_Lite_GetColumnName_ColumnRange_034', 0, async (done: Function) => {
      console.log(TAG + "************* 034 start *************");
      try {
        let rs = await rdbStore.querySqlWithoutRowCount("SELECT * FROM test");
        rs.getColumnName(99);
        expect(true).assertFail();
      } catch (e) { assertColumnRange(e); }
      done();
    })

    // ===== 14800012 (row index out of range) on an empty ResultSet =====
    function assertRowRange(e: any): void {
      console.log(`${TAG} 14800012 code:${e.code}, message:${e.message}`);
      expect(e.code == 14800012).assertTrue();
      expect(e.message.includes("The row index is")).assertTrue();
      expect(e.message.includes("row count is")).assertTrue();
    }

    it('ErrMsg_14800012_GetRow_Empty_020', 0, async (done: Function) => {
      console.log(TAG + "************* 020 start *************");
      try {
        let rs = await rdbStore.querySql("SELECT * FROM test WHERE id = 999999");
        rs.getRow();
        expect(true).assertFail();
      } catch (e) { assertRowRange(e); }
      done();
    })

    it('ErrMsg_14800012_GetSendableRow_Empty_035', 0, async (done: Function) => {
      console.log(TAG + "************* 035 start *************");
      try {
        let rs = await rdbStore.querySql("SELECT * FROM test WHERE id = 999999");
        rs.getSendableRow();
        expect(true).assertFail();
      } catch (e) { assertRowRange(e); }
      done();
    })
  })
}
