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
import relationalStore from '@ohos.data.relationalStore';
import ability_featureAbility from '@ohos.ability.featureAbility'

var context = ability_featureAbility.getContext();
let rdbStore;
const TAG = "[QuerWithCrud]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)";

const STORE_CONFIG = {
  name: "CrudTest.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}
describe('QueryWithCrudTest', function () {
    beforeAll(async function () {
      console.info(TAG + 'beforeAll');
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
    })

    beforeEach(async function () {
      console.info(TAG + 'beforeEach');
      await rdbStore.executeSql(CREATE_TABLE_TEST);
    })

    afterEach(async function () {
      console.info(TAG + 'afterEach');
      await rdbStore.executeSql("DROP TABLE IF EXISTS test");
    })

    afterAll(async function () {
      console.info(TAG + 'afterAll');
      await relationalStore.deleteRdbStore(context, STORE_CONFIG.name);
    })

    /**
     * @tc.name Concurrent query and delet test
     * @tc.number QueryWithDelete001
     * @tc.desc 10 records with a total of less than 2M data,
     * delete 3 records, rowCount equals 7 records.
     */
    it('QueryWithDelete001', 0, async function (done) {
      console.log(TAG + "************* QueryWithDelete001 start *************");
      let u8 = new Uint8Array(Array(1).fill(1));
      for (let i = 0; i < 10; i++) {
        const valueBucket = {
          "name": "zhangsan" + String(i),
          "age": i,
          "salary": 100.5,
          "blobType": u8,
        };
        await rdbStore.insert("test", valueBucket);
      }
      let predicates = new relationalStore.RdbPredicates("test");
      let resultSet = await rdbStore.query(predicates);
      predicates.between('age', 5, 7);
      let deleteRows = await rdbStore.delete(predicates);
      expect(deleteRows).assertEqual(3);
      try {
        while (resultSet.goToNextRow()) {
          const age = resultSet.getString(resultSet.getColumnIndex("age"));
          console.log(TAG + "age:" + age);
        }
      } catch (err) {
        console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message);
        done();
        expect().assertFail();
      }
      expect(resultSet.rowCount).assertEqual(7);
      done();
      console.log(TAG + "************* QueryWithDelete001 end   *************");
    })

    /**
     * @tc.name Concurrent query and delet test
     * @tc.number QueryWithDelete002
     * @tc.desc 10 pieces of 1M data, delete 3 pieces, rowCount equals 7 pieces.
     */
    it('QueryWithDelete002', 0, async function (done) {
      console.log(TAG + "************* QueryWithDelete002 start *************");
      let u8 = new Uint8Array(Array(1024 * 1024).fill(1));
      for (let i = 0; i < 10; i++) {
        const valueBucket = {
          "name": "zhangsan" + String(i),
          "age": i,
          "salary": 100.5,
          "blobType": u8,
        };
        await rdbStore.insert("test", valueBucket);
      }
      let predicates = new relationalStore.RdbPredicates("test");
      let resultSet = await rdbStore.query(predicates);
      predicates.between('age', 5, 7);
      let deleteRows = await rdbStore.delete(predicates);
      expect(deleteRows).assertEqual(3);
      try {
        while (resultSet.goToNextRow()) {
          const age = resultSet.getString(resultSet.getColumnIndex("age"));
          console.log(TAG + "age:" + age);
        }
      } catch (err) {
        console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message);
        done();
        expect().assertFail();
      }
      expect(resultSet.rowCount).assertEqual(7);
      done();
      console.log(TAG + "************* QueryWithDelete002 end   *************");
    })

    /**
     * @tc.name Concurrent query and delet test
     * @tc.number QueryWithDelete003
     * @tc.desc Single data exceeding 2M can return an error normally
     */
    it('QueryWithDelete003', 0, async function (done) {
      console.log(TAG + "************* QueryWithDelete003 start *************");
      let u8 = new Uint8Array(Array(1024 * 1024 * 2).fill(1));
        for (let i = 0; i < 2; i++) {
          const valueBucket = {
            "name": "zhangsan" + String(i),
            "age": i,
            "salary": 100.5,
            "blobType": u8,
          };
          await rdbStore.insert("test", valueBucket);
        }
        let predicates = new relationalStore.RdbPredicates("test");
        let resultSet = await rdbStore.query(predicates);
        predicates.equalTo('age', 1)
        let deleteRows = await rdbStore.delete(predicates);
        expect(deleteRows).assertEqual(1);
      try {
        while (resultSet.goToNextRow()) {
          const age = resultSet.getString(resultSet.getColumnIndex("age"));
          console.log(TAG + "age:" + age);
          expect().assertFail();
        }
      } catch (err) {
        console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message);
        expect(err.code).assertEqual('14800000');
        done();
      }
      console.log(TAG + "rowCount:" + resultSet.rowCount);
      done();
      console.log(TAG + "************* QueryWithDelete003 end   *************");
    })

    /**
     * @tc.name Concurrent query and delet test
     * @tc.number QueryWithDelete004
     * @tc.desc 2 pieces of single 2M data, delete 2 pieces, rowCount equals 0.
     */
    it('QueryWithDelete004', 0, async function (done) {
      console.log(TAG + "************* QueryWithDelete004 start *************");
      let u8 = new Uint8Array(Array(1024 * 1024 * 2).fill(1));
      for (let i = 0; i < 2; i++) {
        const valueBucket = {
          "name": "zhangsan" + String(i),
          "age": i,
          "salary": 100.5,
          "blobType": u8,
        };
        await rdbStore.insert("test", valueBucket);
      }
      let predicates = new relationalStore.RdbPredicates("test");
      let resultSet = await rdbStore.query(predicates);
      predicates.between('age',0,1)
      let deleteRows = await rdbStore.delete(predicates);
      expect(deleteRows).assertEqual(2);
      try {
        while (resultSet.goToNextRow()) {
          const age = resultSet.getString(resultSet.getColumnIndex("age"));
          console.log(TAG + "age:" + age);
        }
      } catch (err) {
        console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message);
        done();
        expect().assertFail();
      }
      expect(resultSet.rowCount).assertEqual(0);
      done();
      console.log(TAG + "************* QueryWithDelete004 end   *************");
    })

    /**
     * @tc.name Concurrent query and delet test
     * @tc.number QueryWithDelete005
     * @tc.desc 10 pieces of data, one of which is greater than 2M, the other 1M,
     * delete 9 pieces of data less than 1M, expect an error.
     */
    it('QueryWithDelete005', 0, async function (done) {
      console.log(TAG + "************* QueryWithDelete005 start *************");
      let bigU8 = new Uint8Array(Array(1024 * 1024 * 2).fill(1));
      let u8 = new Uint8Array(Array(2).fill(1));
      for (let i = 0; i < 9; i++) {
        const valueBucket = {
          "name": "zhangsan" + String(i),
          "age": i,
          "salary": 100.5,
          "blobType": u8,
        };
        await rdbStore.insert("test", valueBucket);
      }
      const value = {
        "name": "lisi",
        "age": 30,
        "salary": 100.5,
        "blobType": bigU8,
      };
      await rdbStore.insert("test", value);
      let predicates = new relationalStore.RdbPredicates("test");
      let resultSet = await rdbStore.query(predicates);
      predicates.between('age', 0, 8);
      let deleteRows = await rdbStore.delete(predicates);
      expect(deleteRows).assertEqual(9);
      try {
        while (resultSet.goToNextRow()) {
          const age = resultSet.getString(resultSet.getColumnIndex("age"));
          console.log(TAG + "age:" + age);
          expect().assertFail();
        }
      } catch (err) {
        console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message);
        expect(err.code).assertEqual('14800000');
        done();
      }
      done();
      console.log(TAG + "************* QueryWithDelete005 end   *************");
    })

    /**
     * @tc.name Concurrent query and delet test
     * @tc.number QueryWithDelete006
     * @tc.desc 10 pieces of data, one of which is greater than 2M, the other 1M,
     * delete data greater than 2M, rowCount is 9.
     */
    it('QueryWithDelete006', 0, async function (done) {
      console.log(TAG + "************* QueryWithDelete006 start *************");
      let bigU8 = new Uint8Array(Array(1024 * 1024 * 2).fill(1));
      let u8 = new Uint8Array(Array(2).fill(1));
      for (let i = 0; i < 9; i++) {
        const valueBucket = {
          "name": "zhangsan" + String(i),
          "age": i,
          "salary": 100.5,
          "blobType": u8,
        };
        await rdbStore.insert("test", valueBucket);
      }
      const value = {
        "name": "lisi",
        "age": 30,
        "salary": 100.5,
        "blobType": bigU8,
      };
      await rdbStore.insert("test", value);
      let predicates = new relationalStore.RdbPredicates("test");
      let resultSet = await rdbStore.query(predicates);
      predicates.equalTo('age', 30);
      let deleteRows = await rdbStore.delete(predicates);
      expect(deleteRows).assertEqual(1);
      try {
        while (resultSet.goToNextRow()) {
          const age = resultSet.getString(resultSet.getColumnIndex("age"));
          console.log(TAG + "age:" + age);
        }
      } catch (err) {
        console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message);
        done();
        expect().assertFail();
      }
      expect(resultSet.rowCount).assertEqual(9);
      done();
      console.log(TAG + "************* QueryWithDelete006 end   *************");
    })

    /**
     * @tc.name Concurrent query and insert test
     * @tc.number QueryWithInsert001
     * @tc.desc 10 pieces of data with a total size less than 2M, delete 4 pieces,
     * insert 1 piece of data with a single size less than 1M, rowCount is equal to 7.
     */
    it('QueryWithInsert001', 0, async function (done) {
      console.log(TAG + "************* QueryWithInsert001 start *************");
      let u8 = new Uint8Array(Array(1).fill(1));
      for (let i = 0; i < 10; i++) {
        const valueBucket = {
          "name": "zhangsan" + String(i),
          "age": i,
          "salary": 100.5,
          "blobType": u8,
        };
        await rdbStore.insert("test", valueBucket);
      }
      let predicates = new relationalStore.RdbPredicates("test");
      let resultSet = await rdbStore.query(predicates);
      predicates.between('age', 1, 4);
      let deleteRows = await rdbStore.delete(predicates);
      expect(deleteRows).assertEqual(4);
      const value = {
        "name": "lisi",
        "age": 30,
        "salary": 100.5,
        "blobType": u8,
      };
      let rowId = await rdbStore.insert('test', value);
      expect(rowId).assertEqual(11);
      try {
        while (resultSet.goToNextRow()) {
          const age = resultSet.getString(resultSet.getColumnIndex("age"));
          console.log(TAG + "age:" + age);
        }
      } catch (err) {
        console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message);
        done();
        expect().assertFail();
      }
      expect(resultSet.rowCount).assertEqual(7);
      done();
      console.log(TAG + "************* QueryWithInsert001 end   *************");
    })

    /**
     * @tc.name Concurrent query and insert test
     * @tc.number QueryWithInsert002
     * @tc.desc 10 pieces of data with a total size less than 2M, delete 4 pieces,
     * insert 3 pieces of data with a single size less than 2M, rowCount is equal to 9.
     */
    it('QueryWithInsert002', 0, async function (done) {
      console.log(TAG + "************* QueryWithInsert002 start *************");
      let u8 = new Uint8Array(Array(1024 * 1024).fill(1));
      for (let i = 0; i < 10; i++) {
        const valueBucket = {
          "name": "zhangsan" + String(i),
          "age": i,
          "salary": 100.5,
          "blobType": u8,
        };
        await rdbStore.insert("test", valueBucket);
      }
      let predicates = new relationalStore.RdbPredicates("test");
      let resultSet = await rdbStore.query(predicates);
      predicates.between('age', 1, 4);
      let deleteRows = await rdbStore.delete(predicates);
      expect(deleteRows).assertEqual(4);
      const value = Array(3).fill(0).map(() => {
        return {
          "name": "zhangsan",
          "age": 20,
          "salary": 100.5,
          "blobType": u8,
        };
      });
      let insertRows = await rdbStore.batchInsert('test', value);
      expect(insertRows).assertEqual(3);
      try {
        while (resultSet.goToNextRow()) {
          const age = resultSet.getString(resultSet.getColumnIndex("age"));
          console.log(TAG + "age:" + age);
        }
      } catch (err) {
        console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message);
        done();
        expect().assertFail();
      }
      expect(resultSet.rowCount).assertEqual(9);
      done();
      console.log(TAG + "************* QueryWithInsert002 end   *************");
    })

    /**
     * @tc.name Concurrent query and insert test
     * @tc.number QueryWithInsert003
     * @tc.desc 3 pieces of data larger than 2M, delete 2 pieces,
     * insert 1 piece of data smaller than 1M, expect an error.
     */
    it('QueryWithInsert003', 0, async function (done) {
      console.log(TAG + "************* QueryWithInsert003 start *************");
      let bigU8 = new Uint8Array(Array(1024 * 1024 * 2).fill(1));
      let u8 = new Uint8Array(Array(2).fill(1));
      for (let i = 0; i < 3; i++) {
        const valueBucket = {
          "name": "zhangsan" + String(i),
          "age": i,
          "salary": 100.5,
          "blobType": bigU8,
        };
        await rdbStore.insert("test", valueBucket);
      }
      let predicates = new relationalStore.RdbPredicates("test");
      let resultSet = await rdbStore.query(predicates);
      predicates.between('age', 0, 1);
      let deleteRows = await rdbStore.delete(predicates);
      expect(deleteRows).assertEqual(2);
      const value = {
        "name": "zhangsan",
        "age": 30,
        "salary": 100.5,
        "blobType": u8,
      };
      let insertRows = await rdbStore.insert('test', value);
      expect(insertRows).assertEqual(4);
      try {
        while (resultSet.goToNextRow()) {
          const age = resultSet.getString(resultSet.getColumnIndex("age"));
          console.log(TAG + "age:" + age);
          expect().assertFail();
        }
      } catch (err) {
        console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message);
        expect(err.code).assertEqual('14800000');
        done();
      }
      done();
      console.log(TAG + "************* QueryWithInsert003 end   *************");
    })

    /**
     * @tc.name Concurrent query and insert test
     * @tc.number QueryWithInsert004
     * @tc.desc 2 pieces of data larger than 2M, delete 2 pieces,
     * insert 1 piece of data smaller than 1M, rowCount is equal to 1.
     */
    it('QueryWithInsert004', 0, async function (done) {
      console.log(TAG + "************* QueryWithInsert004 start *************");
      let bigU8 = new Uint8Array(Array(1024 * 1024 * 2).fill(1));
      let u8 = new Uint8Array(Array(2).fill(1));
      for (let i = 0; i < 2; i++) {
        const valueBucket = {
          "name": "zhangsan" + String(i),
          "age": i,
          "salary": 100.5,
          "blobType": bigU8,
        };
        await rdbStore.insert("test", valueBucket);
      }
      let predicates = new relationalStore.RdbPredicates("test");
      let resultSet = await rdbStore.query(predicates);
      predicates.between('age', 0, 1);
      let deleteRows = await rdbStore.delete(predicates);
      expect(deleteRows).assertEqual(2);
      const value = {
        "name": "zhangsan",
        "age": 30,
        "salary": 100.5,
        "blobType": u8,
      };
      let rowId = await rdbStore.insert('test', value);
      expect(rowId).assertEqual(3);
      try {
        while (resultSet.goToNextRow()) {
          const age = resultSet.getString(resultSet.getColumnIndex("age"));
          console.log(TAG + "age:" + age);
        }
      } catch (err) {
        console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message);
        done();
        expect().assertFail();
      }
      expect(resultSet.rowCount).assertEqual(1);
      done();
      console.log(TAG + "************* QueryWithInsert004 end   *************");
    })
    /**
     * @tc.name Concurrent query and insert test
     * @tc.number QueryWithInsert005
     * @tc.desc 10 pieces of data with a total of less than 2M, delete 6 pieces,
     * insert 3 pieces of data with a single value greater than 2M, expect an error.
     */
    it('QueryWithInsert005', 0, async function (done) {
      console.log(TAG + "************* QueryWithInsert005 start *************");
      let u8 = new Uint8Array(Array(2).fill(1));
      let bigU8 = new Uint8Array(Array(1024 * 1024 * 2).fill(1));
      for (let i = 0; i < 10; i++) {
        const valueBucket = {
          "name": "zhangsan" + String(i),
          "age": i,
          "salary": 100.5,
          "blobType": u8,
        };
        await rdbStore.insert("test", valueBucket);
      }
      let predicates = new relationalStore.RdbPredicates("test");
      let resultSet = await rdbStore.query(predicates);
      predicates.between('age', 0, 5);
      let deleteRows = await rdbStore.delete(predicates);
       expect(deleteRows).assertEqual(6);
      const value = {
        "name": "zhangsan",
        "age": 30,
        "salary": 100.5,
        "blobType": bigU8,
      };
      let rowId = await rdbStore.insert('test', value);
      expect(rowId).assertEqual(11);
      try {
        while (resultSet.goToNextRow()) {
          const age = resultSet.getString(resultSet.getColumnIndex("age"));
          console.log(TAG + "age:" + age);
        }
      } catch (err) {
        console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message);
        expect(err.code).assertEqual('14800000');
        done();
      }
      console.log(TAG + "rowCount:" + resultSet.rowCount);
      done();
      console.log(TAG + "************* QueryWithInsert005 end   *************");
    })

    /**
     * @tc.name Concurrent query and update test
     * @tc.number QueryWithUpdate001
     * @tc.desc 10 records with a total of less than 2M data, updated 3 records, rowCount is 10.
     */
    it('QueryWithUpdate001', 0, async function (done) {
      console.log(TAG + "************* QueryWithUpdate001 start *************");
      let u8 = new Uint8Array(Array(1).fill(1));
      for (let i = 0; i < 10; i++) {
        const valueBucket = {
          "name": "zhangsan" + String(i),
          "age": i,
          "salary": 100.5,
          "blobType": u8,
        };
        await rdbStore.insert("test", valueBucket);
      }
      let predicates = new relationalStore.RdbPredicates("test");
      let resultSet = await rdbStore.query(predicates);
      const value = {
        "name": "lisi",
        "age": 18,
        "salary": 200.5,
        "blobType": u8,
      };
      predicates.between("age", 5, 7)

      let updateRows = await rdbStore.update(value, predicates);
      expect(updateRows).assertEqual(3);
      try {
        while (resultSet.goToNextRow()) {
          const age = resultSet.getString(resultSet.getColumnIndex("age"));
          console.log(TAG + "age:" + age);
        }
      } catch (err) {
        console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message);
        done();
        expect().assertFail();
      }
      expect(resultSet.rowCount).assertEqual(10);
      done();
      console.log(TAG + "************* QueryWithUpdate001 end   *************");
    })

    /**
     * @tc.name Concurrent query and update test
     * @tc.number QueryWithUpdate002
     * @tc.desc 10 pieces of single data less than 1M, update 3 pieces, rowCount is 10.
     */
    it('QueryWithUpdate002', 0, async function (done) {
      console.log(TAG + "************* QueryWithUpdate002 start *************");
      let u8 = new Uint8Array(Array(1024 * 1024).fill(1));
      for (let i = 0; i < 10; i++) {
        const valueBucket = {
          "name": "zhangsan" + String(i),
          "age": i,
          "salary": 100.5,
          "blobType": u8,
        };
        await rdbStore.insert("test", valueBucket);
      }
      let predicates = new relationalStore.RdbPredicates("test");
      let resultSet = await rdbStore.query(predicates);
      const value = {
        "name": "lisi",
        "age": 18,
        "salary": 200.5,
        "blobType": new Uint8Array(Array(1).fill(2)),
      };
      predicates.between("age", 5, 7)
      let updateRows = await rdbStore.update(value, predicates);
      expect(updateRows).assertEqual(3);
      try {
        while (resultSet.goToNextRow()) {
          const age = resultSet.getString(resultSet.getColumnIndex("age"));
          console.log(TAG + "age:" + age);
        }
      } catch (err) {
        console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message);
        done();
        expect().assertFail();
      }
      expect(resultSet.rowCount).assertEqual(10);
      done();
      console.log(TAG + "************* QueryWithUpdate002 end   *************");
    })

    /**
     * @tc.name Concurrent query and update test
     * @tc.number QueryWithUpdate003
     * @tc.desc 2 pieces of data larger than 2M, update 2 pieces of data smaller than 1M,
     * rowCount is 2
     */
    it('QueryWithUpdate003', 0, async function (done) {
      console.log(TAG + "************* QueryWithUpdate003 start *************");
      let bigU8 = new Uint8Array(Array(1024 * 1024 * 2).fill(1));
      let u8 = new Uint8Array(Array(3).fill(1));
      for (let i = 0; i < 2; i++) {
        const valueBucket = {
          "name": "zhangsan" + String(i),
          "age": i,
          "salary": 100.5,
          "blobType": bigU8,
        };
        await rdbStore.insert("test", valueBucket);
      }
      let predicates = new relationalStore.RdbPredicates("test");
      let resultSet = await rdbStore.query(predicates);
      const value = {
        "name": "lisi",
        "age": 18,
        "salary": 200.5,
        "blobType": u8,
      };
      predicates.between("age", 0, 1);
      let updateRows = await rdbStore.update(value, predicates);
      expect(updateRows).assertEqual(2);
      try {
        while (resultSet.goToNextRow()) {
          const age = resultSet.getString(resultSet.getColumnIndex("age"));
          console.log(TAG + "age:" + age);
        }
      } catch (err) {
        console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message);
        done();
        expect().assertFail();
      }
      expect(resultSet.rowCount).assertEqual(2);
      done();
      console.log(TAG + "************* QueryWithUpdate003 end   *************");
    })

    /**
     * @tc.name Concurrent query and update test
     * @tc.number QueryWithUpdate004
     * @tc.desc 4 pieces of single data less than 1M, update 2 pieces of single data greater than 2M,
     * expect an error
     */
    it('QueryWithUpdate004', 0, async function (done) {
      console.log(TAG + "************* QueryWithUpdate004 start *************");
      let bigU8 = new Uint8Array(Array(1024 * 1024 * 2).fill(1));
      let u8 = new Uint8Array(Array(3).fill(1));
      for (let i = 0; i < 2; i++) {
        const valueBucket = {
          "name": "zhangsan" + String(i),
          "age": i,
          "salary": 100.5,
          "blobType": bigU8,
        };
        await rdbStore.insert("test", valueBucket);
      }
      let predicates = new relationalStore.RdbPredicates("test");
      let resultSet = await rdbStore.query(predicates);
      const value = {
        "name": "lisi",
        "age": 18,
        "salary": 200.5,
        "blobType": u8,
      };
      predicates.between("age", 0, 1);
      let updateRows = await rdbStore.update(value, predicates);
      expect(updateRows).assertEqual(2);
      try {
        while (resultSet.goToNextRow()) {
          const age = resultSet.getString(resultSet.getColumnIndex("age"));
          console.log(TAG + "age:" + age);
        }
      } catch (err) {
        console.log(TAG + "catch err: failed, err: code=" + err.code + " message=" + err.message);
        done();
        expect().assertFail();
      }
      console.log(TAG + "rowCount:" + resultSet.rowCount);
      done();
      console.log(TAG + "************* QueryWithUpdate004 end   *************");
    })
    console.log(TAG + "*************Unit Test End*************");
})