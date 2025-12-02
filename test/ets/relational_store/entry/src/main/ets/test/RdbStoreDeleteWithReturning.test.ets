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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect, Level, Size, TestType } from "@ohos/hypium";
import relationalStore from '@ohos.data.relationalStore';
import AbilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';
import fs from '@ohos.file.fs';
const TAG = "[RDB_STORE_DELETE_WITH_RETURNING_TEST]";
let rdbStore: relationalStore.RdbStore | undefined = undefined;

const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "data ASSET, " + "data1 ASSETS," + "blobType BLOB," +
  "test_id INTEGER," + "FOREIGN KEY (test_id) REFERENCES test1(test_id)" + ");"

const CREATE_TABLE_TEST1 =
  "CREATE TABLE IF NOT EXISTS test1 (" + " test_id INTEGER PRIMARY KEY AUTOINCREMENT," + "test_name TEXT NOT NULL" +
    ");";

const FOREIGN_KEYS_ON = "PRAGMA foreign_keys = ON;";
const FOREIGN_KEYS_OFF = "PRAGMA foreign_keys = OFF;";

const dbName = "DeleteRdbStore.db";
const STORE_CONFIG: relationalStore.StoreConfig = {
  name: dbName,
  securityLevel: relationalStore.SecurityLevel.S1,
}

const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();

const dbPath = context.databaseDir + "/rdb/" + dbName;
const dbPathWal = dbPath + "-wal";
const dbPathShm = dbPath + "-shm";

async function createCorruptDb() {
  try {
    let fileExist = fs.accessSync(dbPath);
    console.info(TAG + "dbPath:" + dbPath);
    expect(fileExist).assertTrue();
    fs.truncateSync(dbPathWal, 4);
    fs.truncateSync(dbPathShm, 4);
    let file = fs.openSync(dbPath, fs.OpenMode.READ_WRITE);
    fs.truncateSync(file.fd, 4);
    fs.fsyncSync(file.fd);
    fs.closeSync(file);
  } catch (err) {
    console.info(TAG, `CreateCorruptDb err.code ${err.code}, err.message ${err.message}`)
  }
  console.info(TAG, `quit create corrupt store`);
}

export default function RdbStoreDeleteWithReturning() {
  describe('rdbStoreDeleteWithReturning', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
    })
    beforeEach(async () => {
      console.info(TAG + 'beforeEach');
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore != undefined).assertTrue();
      await rdbStore?.executeSql(CREATE_TABLE_TEST1);
      await rdbStore?.executeSql(CREATE_TABLE_TEST);
      let valueBuckets = new Array<relationalStore.ValuesBucket>();
      let valueBuckets1 = new Array<relationalStore.ValuesBucket>();
      const num = 10;
      for (let i = 0; i < num; i++) {
        const valueBucket: relationalStore.ValuesBucket = {
          'test_name': 'lisi' + i,
        };
        valueBuckets1.push(valueBucket);
      }
      const config1: relationalStore.ReturningConfig = {
        columns: ['test_name'],
      }
      let results1 = await rdbStore?.batchInsertWithReturning("test1", valueBuckets1, config1);
      expect(results1.changed).assertEqual(num);
      for (let i = 0; i < num; i++) {
        const asset: relationalStore.Asset = {
          name: "example-image.jpg" + i,
          uri: "content://media/external/images/media/12345" + i,
          path: "/storage/emulated/0/Pictures/example-image.jpg" + i,
          createTime: "2024-01-15T10:30:00Z" + i,
          modifyTime: "2024-01-15T14:45:23Z" + i,
          size: "2048576" + i
        }
        const valueBucket: relationalStore.ValuesBucket = {
          'name': 'zhangsan' + i,
          'age': 18 + i,
          'salary': 25000.5 + i,
          'data': asset,
          'test_id': i
        };
        valueBuckets.push(valueBucket);
      }
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      let results = await rdbStore?.batchInsertWithReturning("test", valueBuckets, config);
      expect(results.changed).assertEqual(num);
    })
    afterEach(async () => {
      console.info(TAG + 'afterEach');
      await relationalStore.deleteRdbStore(context, STORE_CONFIG);
    })
    afterAll(async () => {
      console.info(TAG + 'afterAll');
    })
    console.log(TAG + "************* deleteWithReturning Begin *************");
    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning001
     * @tc.desc 1. Values is normal.
     */
    it('deleteWithReturning001', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturning001 start *************");
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan1');
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      try {
        let results = await rdbStore?.deleteWithReturning(predicates, config);
        expect(results?.changed).assertEqual(1);
        expect(results?.resultSet.rowCount).assertEqual(1);
        results?.resultSet.goToFirstRow();
        const name = results?.resultSet.getString(results?.resultSet.getColumnIndex('name'));
        const age = results?.resultSet.getLong(results?.resultSet.getColumnIndex('age'));
        expect(name).assertEqual("zhangsan1");
        expect(age).assertEqual(19);
      } catch (e) {
        console.error(TAG + `deleteWithReturning failed. code is ${e.code}, message is ${e.message}`);
        expect(true).assertFail();
      }
      console.log(TAG + "************* deleteWithReturning001 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturningSync test.
     * @tc.number deleteWithReturningSync001
     * @tc.desc 1. Values is normal.
     */
    it('deleteWithReturningSync001', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturningSync001 start *************");
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan4');
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      try {
        let results = rdbStore?.deleteWithReturningSync(predicates, config);
        expect(results?.changed).assertEqual(1);
        expect(results?.resultSet.rowCount).assertEqual(1);
        results?.resultSet.goToFirstRow();
        const name = results?.resultSet.getString(results?.resultSet.getColumnIndex('name'));
        const age = results?.resultSet.getLong(results?.resultSet.getColumnIndex('age'));
        expect(name).assertEqual("zhangsan4");
        expect(age).assertEqual(22);
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync001 failed. code is ${e.code}, message is ${e.message}`);
        expect(true).assertFail();
      }
      console.log(TAG + "************* deleteWithReturningSync001 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning003
     * @tc.desc 1. The tableName is wrong.
     */
    it('deleteWithReturning003', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturning003 start *************");
      let predicates = new relationalStore.RdbPredicates("wrongTableName");
      predicates.equalTo('name', 'zhangsan4');
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      try {
        await rdbStore?.deleteWithReturning(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning003 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual(14800021);
      }
      console.log(TAG + "************* deleteWithReturning003 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturningSync test.
     * @tc.number deleteWithReturningSync003
     * @tc.desc 1. The tableName is wrong.
     */
    it('deleteWithReturningSync003', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturningSync003 start *************");
      let predicates = new relationalStore.RdbPredicates("wrongTableName");
      predicates.equalTo('name', 'zhangsan4');
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      try {
        rdbStore?.deleteWithReturningSync(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync003 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual(14800021);
      }
      console.log(TAG + "************* deleteWithReturningSync003 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning004
     * @tc.desc 1. The tableName is empty.
     */
    it('deleteWithReturning004', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturning004 start *************");
      try {
        let predicates = new relationalStore.RdbPredicates("");
        predicates.equalTo('name', 'zhangsan4');
        const config: relationalStore.ReturningConfig = {
          columns: ['name', 'age'],
        }
        await rdbStore?.deleteWithReturning(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning004 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("401");
      }
      console.log(TAG + "************* deleteWithReturning004 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturningSync test.
     * @tc.number deleteWithReturningSync004
     * @tc.desc 1. The tableName is empty.
     */
    it('deleteWithReturningSync004', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturningSync004 start *************");
      try {
        let predicates = new relationalStore.RdbPredicates("");
        predicates.equalTo('name', 'zhangsan4');
        const config: relationalStore.ReturningConfig = {
          columns: ['name', 'age'],
        }
        rdbStore?.deleteWithReturningSync(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync004 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("401");
      }
      console.log(TAG + "************* deleteWithReturningSync004 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning005
     * @tc.desc 1. There are spaces in the table name.
     */
    it('deleteWithReturning005', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturning005 start *************");
      let predicates = new relationalStore.RdbPredicates("test test1");
      predicates.equalTo('name', 'zhangsan4');
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      try {
        await rdbStore?.deleteWithReturning(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning005 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      console.log(TAG + "************* deleteWithReturning005 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturningSync test.
     * @tc.number deleteWithReturningSync005
     * @tc.desc 1. There are spaces in the table name.
     */
    it('deleteWithReturningSync005', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturningSync005 start *************");
      let predicates = new relationalStore.RdbPredicates("test test1");
      predicates.equalTo('name', 'zhangsan4');
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      try {
        rdbStore?.deleteWithReturningSync(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync005 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      console.log(TAG + "************* deleteWithReturningSync005 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning006
     * @tc.desc 1. 0 < values.size <= 1024, The returned results can contain all the changed data.
     */
    it('deleteWithReturning006', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturning006 start *************");
      let valueBuckets = new Array<relationalStore.ValuesBucket>();
      for (let i = 10; i < 1024; i++) {
        const valueBucket: relationalStore.ValuesBucket = {
          'name': 'zhangsan' + i,
          'age': 18 + i,
          'salary': 25000.5 + i,
        };
        valueBuckets.push(valueBucket);
      }
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      let results = await rdbStore?.batchInsertWithReturning("test", valueBuckets, config);
      expect(results?.changed).assertEqual(1014);
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.contains('name', 'zhangsan');
      try {
        let result = await rdbStore?.deleteWithReturning(predicates, config);
        expect(result?.changed).assertEqual(1024);
        expect(result?.resultSet.rowCount).assertEqual(1024);
      } catch (e) {
        console.error(TAG + `deleteWithReturning006 failed. code is ${e.code}, message is ${e.message}`);
        expect(true).assertFail();
      }
      console.log(TAG + "************* deleteWithReturning006 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturningSync test.
     * @tc.number deleteWithReturningSync006
     * @tc.desc 1. 0 < values.size <= 1024, The returned results can contain all the changed data.
     */
    it('deleteWithReturningSync006', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturningSync006 start *************");
      let valueBuckets = new Array<relationalStore.ValuesBucket>();
      for (let i = 10; i < 1024; i++) {
        const valueBucket: relationalStore.ValuesBucket = {
          'name': 'zhangsan' + i,
          'age': 18 + i,
          'salary': 25000.5 + i,
        };
        valueBuckets.push(valueBucket);
      }
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      let results = await rdbStore?.batchInsertWithReturning("test", valueBuckets, config);
      expect(results?.changed).assertEqual(1014);
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.contains('name', 'zhangsan');
      try {
        let results = rdbStore?.deleteWithReturningSync(predicates, config);
        expect(results?.changed).assertEqual(1024);
        expect(results?.resultSet.rowCount).assertEqual(1024);
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync006 failed. code is ${e.code}, message is ${e.message}`);
        expect(true).assertFail();
      }
      console.log(TAG + "************* deleteWithReturningSync006 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning007
     * @tc.desc 1. values.size > 1024, The returned results contains only 1024 entries.
     * Any excess entries are discarded, and the number of changed entries represents the actual number of modified rows.
     */
    it('deleteWithReturning007', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturning007 start *************");
      let valueBuckets = new Array<relationalStore.ValuesBucket>();
      for (let i = 10; i < 1100; i++) {
        const valueBucket: relationalStore.ValuesBucket = {
          'name': 'zhangsan' + i,
          'age': 18 + i,
          'salary': 25000.5 + i,
        };
        valueBuckets.push(valueBucket);
      }
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      let results = await rdbStore?.batchInsertWithReturning("test", valueBuckets, config);
      expect(results?.changed).assertEqual(1090);
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.contains('name', 'zhangsan');
      try {
        let results = await rdbStore?.deleteWithReturning(predicates, config);
        expect(results?.changed).assertEqual(1100);
        expect(results?.resultSet.rowCount).assertEqual(1024);
      } catch (e) {
        console.error(TAG + `deleteWithReturning007 failed. code is ${e.code}, message is ${e.message}`);
        expect(true).assertFail();
      }
      console.log(TAG + "************* deleteWithReturning007 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturningSync test.
     * @tc.number deleteWithReturningSync007
     * @tc.desc 1. values.size > 1024, The returned results contains only 1024 entries.
     * Any excess entries are discarded, and the number of changed entries represents the actual number of modified rows.
     */
    it('deleteWithReturningSync007', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturningSync007 start *************");
      let valueBuckets = new Array<relationalStore.ValuesBucket>();
      for (let i = 10; i < 1100; i++) {
        const valueBucket: relationalStore.ValuesBucket = {
          'name': 'zhangsan' + i,
          'age': 18 + i,
          'salary': 25000.5 + i,
        };
        valueBuckets.push(valueBucket);
      }
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      let results = await rdbStore?.batchInsertWithReturning("test", valueBuckets, config);
      expect(results?.changed).assertEqual(1090);
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.contains('name', 'zhangsan');
      try {
        let results = rdbStore?.deleteWithReturningSync(predicates, config);
        expect(results?.changed).assertEqual(1100);
        expect(results?.resultSet.rowCount).assertEqual(1024);
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync007 failed. code is ${e.code}, message is ${e.message}`);
        expect(true).assertFail();
      }
      console.log(TAG + "************* deleteWithReturningSync007 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning008
     * @tc.desc 1. 1 < columns.size <= 4, Return the results of the specified field.
     */
    it('deleteWithReturning008', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturning008 start *************");
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan4');
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age', 'salary']
      }
      try {
        let results = await rdbStore?.deleteWithReturning(predicates, config);
        results?.resultSet.columnNames.forEach(colName => {
          expect(config.columns).assertContain(colName);
        })
        expect(results?.resultSet.columnCount).assertEqual(config.columns.length);
        results?.resultSet.goToFirstRow();
        const name = results?.resultSet.getString(results?.resultSet.getColumnIndex('name'));
        const age = results?.resultSet.getLong(results?.resultSet.getColumnIndex('age'));
        expect(name).assertEqual("zhangsan4");
        expect(age).assertEqual(22);
      } catch (e) {
        console.error(TAG + `deleteWithReturning008 failed. code is ${e.code}, message is ${e.message}`);
        expect(true).assertFail();
      }
      console.log(TAG + "************* deleteWithReturning008 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturningSync test.
     * @tc.number deleteWithReturningSync008
     * @tc.desc 1. 1 < columns.size <= 4, Return the results of the specified field.
     */
    it('deleteWithReturningSync008', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturningSync008 start *************");
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan5');
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      try {
        let results = rdbStore?.deleteWithReturningSync(predicates, config);
        results?.resultSet.columnNames.forEach(colName => {
          expect(config.columns).assertContain(colName);
        })
        expect(results?.resultSet.columnCount).assertEqual(config.columns.length);
        results?.resultSet.goToFirstRow();
        const name = results?.resultSet.getString(results?.resultSet.getColumnIndex('name'));
        const age = results?.resultSet.getLong(results?.resultSet.getColumnIndex('age'));
        expect(name).assertEqual("zhangsan5");
        expect(age).assertEqual(23);
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync008 failed. code is ${e.code}, message is ${e.message}`);
        expect(true).assertFail();
      }
      console.log(TAG + "************* deleteWithReturningSync008 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning009
     * @tc.desc 1. columns.size == 0, errCode 14800001.
     */
    it('deleteWithReturning009', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturning009 start *************");
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan5');
      const config: relationalStore.ReturningConfig = {
        columns: [],
      }
      try {
        await rdbStore?.deleteWithReturning(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning009 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      console.log(TAG + "************* deleteWithReturning009 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturningSync test.
     * @tc.number deleteWithReturningSync009
     * @tc.desc 1. columns.size == 0, errCode 14800001.
     */
    it('deleteWithReturningSync009', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturningSync009 start *************");
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan5');
      const config: relationalStore.ReturningConfig = {
        columns: [],
      }
      try {
        rdbStore?.deleteWithReturningSync(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync009 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      console.log(TAG + "************* deleteWithReturningSync009 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning010
     * @tc.desc 1. columns.size > 4, Throwing an error.
     */
    it('deleteWithReturning010', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturning010 start *************");
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan5');
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age', 'salary', 'data', 'blobType'],
      }
      try {
        await rdbStore?.deleteWithReturning(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning010 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      console.log(TAG + "************* deleteWithReturning010 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturningSync test.
     * @tc.number deleteWithReturningSync010
     * @tc.desc 1. columns.size > 4, Throwing an error.
     */
    it('deleteWithReturningSync010', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturningSync010 start *************");
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan5');
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age', 'salary', 'data', 'blobType'],
      }
      try {
        rdbStore?.deleteWithReturningSync(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync010 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      console.log(TAG + "************* deleteWithReturningSync010 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning011
     * @tc.desc 1. columns contain special characters: "*"," ",",".
     */
    it('deleteWithReturning011', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturning011 start *************");
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan5');
      const config: relationalStore.ReturningConfig = {
        columns: ['ab*'],
      }
      try {
        await rdbStore?.deleteWithReturning(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning011 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      config.columns = ['a b'];
      try {
        await rdbStore?.deleteWithReturning(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning011 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      config.columns = ['a,b'];
      try {
        await rdbStore?.deleteWithReturning(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning011 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      console.log(TAG + "************* deleteWithReturning011 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturningSync test.
     * @tc.number deleteWithReturningSync011
     * @tc.desc 1. columns contain special characters: "*"," ",",".
     */
    it('deleteWithReturningSync011', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturningSync011 start *************");
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan5');
      const config: relationalStore.ReturningConfig = {
        columns: ['ab*'],
      }
      try {
        rdbStore?.deleteWithReturningSync(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync011 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      config.columns = ['a b'];
      try {
        rdbStore?.deleteWithReturningSync(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync011 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      config.columns = ['a,b'];
      try {
        rdbStore?.deleteWithReturningSync(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync011 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      console.log(TAG + "************* deleteWithReturningSync011 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning012
     * @tc.desc 1. Violation of constraint foreign key.
     */
    it('deleteWithReturning012', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturning012 start *************");
      await rdbStore?.executeSql(FOREIGN_KEYS_ON);
      let predicates = new relationalStore.RdbPredicates("test1");
      predicates.equalTo('test_id', 1);
      const config: relationalStore.ReturningConfig = {
        columns: ['test_name'],
      }
      try {
        await rdbStore?.deleteWithReturning(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        await rdbStore?.executeSql(FOREIGN_KEYS_OFF);
        console.error(TAG + `deleteWithReturning012 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual(14800032);
      }
      await rdbStore?.executeSql(FOREIGN_KEYS_OFF);
      console.log(TAG + "************* deleteWithReturning012 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturningSync test.
     * @tc.number deleteWithReturningSync012
     * @tc.desc 1. Violation of constraint foreign key.
     */
    it('deleteWithReturningSync012', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturningSync012 start *************");
      await rdbStore?.executeSql(FOREIGN_KEYS_ON);
      let predicates = new relationalStore.RdbPredicates("test1");
      predicates.equalTo('test_id', 2);
      const config: relationalStore.ReturningConfig = {
        columns: ['test_name'],
      }
      try {
        rdbStore?.deleteWithReturningSync(predicates, config);
        await rdbStore?.executeSql(FOREIGN_KEYS_OFF);
        expect(true).assertFail();
      } catch (e) {
        await rdbStore?.executeSql(FOREIGN_KEYS_OFF);
        console.error(TAG + `deleteWithReturningSync012 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual(14800032);
      }
      await rdbStore?.executeSql(FOREIGN_KEYS_OFF);
      console.log(TAG + "************* deleteWithReturningSync012 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning013
     * @tc.desc 1. Normal parameters, rdb already close.
     */
    it('deleteWithReturning013', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturning013 start *************");
      await rdbStore?.close();
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan5');
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      try {
        await rdbStore?.deleteWithReturning(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning013 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800014");
      }
      console.log(TAG + "************* deleteWithReturning013 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturningSync test.
     * @tc.number deleteWithReturningSync013
     * @tc.desc 1. Normal parameters, rdb already close.
     */
    it('deleteWithReturningSync013', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturningSync013 start *************");
      await rdbStore?.close();
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan5');
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      try {
        rdbStore?.deleteWithReturningSync(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync013 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800014");
      }
      console.log(TAG + "************* deleteWithReturningSync013 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning014
     * @tc.desc 1. Abnormal parameters, rdb already close.
     */
    it('deleteWithReturning014', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturning014 start *************");
      await rdbStore?.close();
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan5');
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age', '*'],
      }
      try {
        await rdbStore?.deleteWithReturning(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning014 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800014");
      }
      console.log(TAG + "************* deleteWithReturning014 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturningSync test.
     * @tc.number deleteWithReturningSync014
     * @tc.desc 1. Abnormal parameters, rdb already close.
     */
    it('deleteWithReturningSync014', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturningSync014 start *************");
      await rdbStore?.close();
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan5');
      const config: relationalStore.ReturningConfig = {
        columns: ['*'],
      }
      try {
        rdbStore?.deleteWithReturningSync(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync014 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800014");
      }
      console.log(TAG + "************* deleteWithReturningSync014 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning015
     * @tc.desc 1. Database corruption.
     */
    it('deleteWithReturning015', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturning015 start *************");
      await createCorruptDb();
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan5');
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      try {
        await rdbStore?.deleteWithReturning(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning015 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual(14800011);
      }
      console.log(TAG + "************* deleteWithReturning015 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturningSync test.
     * @tc.number deleteWithReturningSync015
     * @tc.desc 1. Database corruption.
     */
    it('deleteWithReturningSync015', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturningSync015 start *************");
      await createCorruptDb();
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan5');
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      try {
        rdbStore?.deleteWithReturningSync(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync015 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual(14800011);
      }
      console.log(TAG + "************* deleteWithReturningSync015 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning016
     * @tc.desc 1. The database file is locked.
     */
    it('deleteWithReturning016', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturning016 start *************");
      let deferredTrans = await rdbStore?.createTransaction({
        transactionType: relationalStore.TransactionType.DEFERRED
      });
      const valueBucket: relationalStore.ValuesBucket = {
        "name": "lisi",
        "age": 18,
        "salary": 100.5,
      };
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan5');
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      try {
        await deferredTrans?.insert("test", valueBucket);
        await rdbStore?.deleteWithReturning(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning016 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual(14800024);
      }
      await deferredTrans?.commit();
      console.log(TAG + "************* deleteWithReturning016 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturningSync test.
     * @tc.number deleteWithReturningSync016
     * @tc.desc 1. The database file is locked.
     */
    it('deleteWithReturningSync016', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturningSync016 start *************");
      let deferredTrans = await rdbStore?.createTransaction({
        transactionType: relationalStore.TransactionType.DEFERRED
      });
      const valueBucket: relationalStore.ValuesBucket = {
        "name": "lisi",
        "age": 18,
        "salary": 100.5,
      };
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.equalTo('name', 'zhangsan5');
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      try {
        await deferredTrans?.insert("test", valueBucket);
        rdbStore?.deleteWithReturningSync(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync016 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual(14800024);
      }
      await deferredTrans?.commit();
      console.log(TAG + "************* deleteWithReturningSync016 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning017
     * @tc.desc 1. illegal table name
     */
    it('deleteWithReturning028', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturning017 start *************");
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
      }
      try {
        let predicates1 = new relationalStore.RdbPredicates("123test");
        await rdbStore?.deleteWithReturning(predicates1, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning017 1 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      try {
        let predicates2 = new relationalStore.RdbPredicates("345test");
        rdbStore?.deleteWithReturningSync(predicates2, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning017 2 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      let predicates3 = new relationalStore.RdbPredicates("te.s.t");
      try {
        await rdbStore?.deleteWithReturning(predicates3, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning017 3 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      try {
        rdbStore?.deleteWithReturningSync(predicates3, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning017 4 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      let predicates5 = new relationalStore.RdbPredicates(".test");
      try {
        await rdbStore?.deleteWithReturning(predicates5, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning017 5 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      try {
        rdbStore?.deleteWithReturningSync(predicates5, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning017 6 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      let predicates7 = new relationalStore.RdbPredicates("test..");
      try {
        await rdbStore?.deleteWithReturning(predicates7, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning017 7 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      try {
        rdbStore?.deleteWithReturningSync(predicates7, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning017 8 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      console.log(TAG + "************* deleteWithReturning017 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning018
     * @tc.desc 1. maxReturningCount <= 0 || maxReturningCount > 0x7ffe.
     */
    it('deleteWithReturning018', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturning018 start *************");
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
        maxReturningCount: -2
      }
      let predicates = new relationalStore.RdbPredicates("test");
      try {
        await rdbStore?.deleteWithReturning(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning018 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      config.maxReturningCount = 0;
      try {
        await rdbStore?.deleteWithReturning(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning018 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      config.maxReturningCount = 0x7fff;
      try {
        await rdbStore?.deleteWithReturning(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning018 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      console.log(TAG + "************* deleteWithReturning018 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturningSync test.
     * @tc.number deleteWithReturningSync018
     * @tc.desc 1. maxReturningCount <= 0 || maxReturningCount > 0x7ffe.
     */
    it('deleteWithReturningSync018', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturningSync018 start *************");
      const config: relationalStore.ReturningConfig = {
        columns: ['name', 'age'],
        maxReturningCount: -2
      }
      let predicates = new relationalStore.RdbPredicates("test");
      try {
        rdbStore?.deleteWithReturningSync(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync018 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      config.maxReturningCount = 0;
      try {
        rdbStore?.deleteWithReturningSync(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync018 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      config.maxReturningCount = 0x7FFF;
      try {
        rdbStore?.deleteWithReturningSync(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync018 failed. code is ${e.code}, message is ${e.message}`);
        expect(e.code).assertEqual("14800001");
      }
      console.log(TAG + "************* deleteWithReturningSync018 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning019
     * @tc.desc 1. valueBuckets.size < maxReturningCount < 0x7FFF.
     */
    it('deleteWithReturning019', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturning019 start *************");
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.between('id', 1, 2);
      const config: relationalStore.ReturningConfig = {
        columns: ['name'],
        maxReturningCount: 5
      }
      try {
        let results = await rdbStore?.deleteWithReturning(predicates, config);
        expect(results?.changed).assertEqual(2);
        expect(results?.resultSet.rowCount).assertEqual(2);
      } catch (e) {
        console.error(TAG + `deleteWithReturning019 failed. code is ${e.code}, message is ${e.message}`);
        expect(true).assertFail();
      }
      console.log(TAG + "************* deleteWithReturning019 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturningSync test.
     * @tc.number deleteWithReturningSync019
     * @tc.desc 1. valueBuckets.size < maxReturningCount < 0x7FFF.
     */
    it('deleteWithReturningSync019', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturningSync019 start *************");
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.between('id', 1, 2);
      const config: relationalStore.ReturningConfig = {
        columns: ['name'],
        maxReturningCount: 5
      }
      try {
        let results = rdbStore?.deleteWithReturningSync(predicates, config);
        expect(results?.changed).assertEqual(2);
        expect(results?.resultSet.rowCount).assertEqual(2);
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync019 failed. code is ${e.code}, message is ${e.message}`);
        expect(true).assertFail();
      }
      console.log(TAG + "************* deleteWithReturningSync019 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning020
     * @tc.desc 1. maxReturningCount < valueBuckets.size < 0x7FFF.
     */
    it('deleteWithReturning020', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturning020 start *************");
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.between('id', 1, 10);
      const config: relationalStore.ReturningConfig = {
        columns: ['name'],
        maxReturningCount: 5
      }
      try {
        let results = await rdbStore?.deleteWithReturning(predicates, config);
        expect(results?.changed).assertEqual(10);
        expect(results?.resultSet.rowCount).assertEqual(5);
      } catch (e) {
        console.error(TAG + `deleteWithReturning020 failed. code is ${e.code}, message is ${e.message}`);
        expect(true).assertFail();
      }
      console.log(TAG + "************* deleteWithReturning020 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturningSync test.
     * @tc.number deleteWithReturningSync020
     * @tc.desc 1.maxReturningCount < valueBuckets.size < 0x7FFF.
     */
    it('deleteWithReturningSync020', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturningSync020 start *************");
      let predicates = new relationalStore.RdbPredicates("test");
      predicates.between('id', 1, 10);
      const config: relationalStore.ReturningConfig = {
        columns: ['name'],
        maxReturningCount: 5
      }
      try {
        let results = rdbStore?.deleteWithReturningSync(predicates, config);
        expect(results?.changed).assertEqual(10);
        expect(results?.resultSet.rowCount).assertEqual(5);
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync020 failed. code is ${e.code}, message is ${e.message}`);
        expect(true).assertFail();
      }
      console.log(TAG + "************* deleteWithReturningSync020 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturning test.
     * @tc.number deleteWithReturning021
     * @tc.desc 1. Pass special characters to field names.
     */
    it('deleteWithReturning021', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturning021 start *************");
      let predicates = new relationalStore.RdbPredicates("test");
      const config: relationalStore.ReturningConfig = {
        columns: ['name?'],
        maxReturningCount: 5
      }
      try {
        await rdbStore?.deleteWithReturning(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturning021 failed. code is ${e.code}, message is ${e.message}`);
        expect(14800021).assertEqual(e.code);
      }
      console.log(TAG + "************* deleteWithReturning021 end *************");
      done();
    })

    /**
     * @tc.name deleteWithReturningSync test.
     * @tc.number deleteWithReturningSync021
     * @tc.desc 1. Pass special characters to field names.
     */
    it('deleteWithReturningSync021', 0, async (done: Function) => {
      console.log(TAG + "************* deleteWithReturningSync021 start *************");
      let predicates = new relationalStore.RdbPredicates("test");
      const config: relationalStore.ReturningConfig = {
        columns: ['name?'],
        maxReturningCount: 5
      }
      try {
        rdbStore?.deleteWithReturningSync(predicates, config);
        expect(true).assertFail();
      } catch (e) {
        console.error(TAG + `deleteWithReturningSync021 failed. code is ${e.code}, message is ${e.message}`);
        expect(14800021).assertEqual(e.code);
      }
      console.log(TAG + "************* deleteWithReturningSync021 end *************");
      done();
    })
    console.log(TAG + "************* deleteWithReturning end *************");
  })
}