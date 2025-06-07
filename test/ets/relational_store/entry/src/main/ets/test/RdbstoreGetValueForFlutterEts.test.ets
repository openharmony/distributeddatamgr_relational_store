
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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect, Level, Size, TestType,
  Assert } from "@ohos/hypium";
import relationalStore from '@ohos.data.relationalStore';
import AbilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';
import { ValuesBucket } from "@ohos.data.ValuesBucket";


const TAG = "[STAGE_RELATIONAL_STORE_JSKITS_TEST]";
let rdbStore:relationalStore.RdbStore | undefined = undefined;

const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" +
  "id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, age INTEGER, salary REAL, blobType BLOB, data1 asset)";

const STORE_CONFIG: relationalStore.StoreConfig = {
  name: "rdbStore.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}

const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();


export default function getValueForFlutterEtsTest() {
  describe('getValueForFlutterEtsTest', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
    })
    beforeEach(async () => {
      console.info(TAG + 'beforeEach');
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore != undefined).assertTrue();
      await rdbStore?.executeSql(CREATE_TABLE_TEST);
    })
    afterEach(async () => {
      console.info(TAG + 'afterEach');
      await relationalStore.deleteRdbStore(context, "rdbStore.db");
    })
    afterAll(async () => {
      console.info(TAG + 'afterAll');
    })


    /**
     * @tc.name testRdbStoreGetValueForFlutter
     * @tc.number testRdbStoreGetValueForFlutter_0001
     * @tc.desc integer greater than Number.MAX_SAFE_INTEGER test
     */
    it('testRdbStoreGetValueForFlutter_0001',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStoreGetValueForFlutter_0001 start *************");
      let valueNum = Number.MAX_SAFE_INTEGER.toString() + 0;
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore != undefined).assertTrue();
      await rdbStore.executeSql(CREATE_TABLE_TEST);
      const valueBucket1: ValuesBucket = {
        'age': valueNum,
      }
      try {
        let rowId = await rdbStore.insert("test", valueBucket1);
        expect(1).assertEqual(rowId);
      } catch (err) {
        console.error(`### insert failed, code:${err.code}, message:${err.message}`);
      }
      try {
        let resultSet = await rdbStore.querySql('SELECT * FROM test');
        expect(true).assertEqual(resultSet.goToFirstRow());
        expect(valueNum).assertEqual(resultSet.getValueForFlutter(resultSet.getColumnIndex('age')));
        resultSet.close();
      } catch (err) {
        console.error(`### query failed, code:${err.code}, message:${err.message}`);
      }
      done();
      console.log(TAG + "************* testRdbStoreGetValueForFlutter_0001 end *************");
    })

    /**
     * @tc.name testRdbStoreGetValueForFlutter
     * @tc.number testRdbStoreGetValueForFlutter_0002
     * @tc.desc integer is Number.MAX_SAFE_INTEGER test
     */
    it('testRdbStoreGetValueForFlutter_0002',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStoreGetValueForFlutter_0002 start *************");
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore != undefined).assertTrue();
      await rdbStore.executeSql(CREATE_TABLE_TEST);
      const valueBucket1: ValuesBucket = {
        'age': Number.MAX_SAFE_INTEGER,
      }
      try {
        let rowId = await rdbStore.insert("test", valueBucket1);
        expect(1).assertEqual(rowId);
      } catch (err) {
        console.error(`### insert failed, code:${err.code}, message:${err.message}`);
      }
      try {
        let resultSet = await rdbStore.querySql('SELECT * FROM test');
        expect(true).assertEqual(resultSet.goToFirstRow());
        expect(Number.MAX_SAFE_INTEGER).assertEqual(resultSet.getValueForFlutter(resultSet.getColumnIndex('age')));
        resultSet.close();
      } catch (err) {
        console.error(`### query failed, code:${err.code}, message:${err.message}`);
      }
      done();
      console.log(TAG + "************* testRdbStoreGetValueForFlutter_0002 end *************");
    })

    /**
     * @tc.name testRdbStoreGetValueForFlutter
     * @tc.number testRdbStoreGetValueForFlutter_0003
     * @tc.desc integer less than Number.MAX_SAFE_INTEGER test
     */
    it('testRdbStoreGetValueForFlutter_0003',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStoreGetValueForFlutter_0003 start *************");
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore != undefined).assertTrue();
      await rdbStore.executeSql(CREATE_TABLE_TEST);
      const valueBucket1: ValuesBucket = {
        'age': 100,
      }
      try {
        let rowId = await rdbStore.insert("test", valueBucket1);
        expect(1).assertEqual(rowId);
      } catch (err) {
        console.error(`### insert failed, code:${err.code}, message:${err.message}`);
      }
      try {
        let resultSet = await rdbStore.querySql('SELECT * FROM test');
        expect(true).assertEqual(resultSet.goToFirstRow());
        expect(100).assertEqual(resultSet.getValueForFlutter(resultSet.getColumnIndex('age')));
        resultSet.close();
      } catch (err) {
        console.error(`### query failed, code:${err.code}, message:${err.message}`);
      }
      done();
      console.log(TAG + "************* testRdbStoreGetValueForFlutter_0003 end *************");
    })

    /**
     * @tc.name testRdbStoreGetValueForFlutter
     * @tc.number testRdbStoreGetValueForFlutter_0004
     * @tc.desc integer greater than Number.MIN_SAFE_INTEGER test
     */
    it('testRdbStoreGetValueForFlutter_0004',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStoreGetValueForFlutter_0004 start *************");
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore != undefined).assertTrue();
      await rdbStore.executeSql(CREATE_TABLE_TEST);
      const valueBucket1: ValuesBucket = {
        'age': -100,
      }
      try {
        let rowId = await rdbStore.insert("test", valueBucket1);
        expect(1).assertEqual(rowId);
      } catch (err) {
        console.error(`### insert failed, code:${err.code}, message:${err.message}`);
      }
      try {
        let resultSet = await rdbStore.querySql('SELECT * FROM test');
        expect(true).assertEqual(resultSet.goToFirstRow());
        expect(-100).assertEqual(resultSet.getValueForFlutter(resultSet.getColumnIndex('age')));
        resultSet.close();
      } catch (err) {
        console.error(`### query failed, code:${err.code}, message:${err.message}`);
      }
      done();
      console.log(TAG + "************* testRdbStoreGetValueForFlutter_0004 end *************");
    })

    /**
     * @tc.name testRdbStoreGetValueForFlutter
     * @tc.number testRdbStoreGetValueForFlutter_0005
     * @tc.desc integer is Number.MIN_SAFE_INTEGER test
     */
    it('testRdbStoreGetValueForFlutter_0005',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStoreGetValueForFlutter_0005 start *************");
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore != undefined).assertTrue();
      await rdbStore.executeSql(CREATE_TABLE_TEST);
      const valueBucket1: ValuesBucket = {
        'age': Number.MIN_SAFE_INTEGER,
      }
      try {
        let rowId = await rdbStore.insert("test", valueBucket1);
        expect(1).assertEqual(rowId);
      } catch (err) {
        console.error(`### insert failed, code:${err.code}, message:${err.message}`);
      }
      try {
        let resultSet = await rdbStore.querySql('SELECT * FROM test');
        expect(true).assertEqual(resultSet.goToFirstRow());
        expect(Number.MIN_SAFE_INTEGER).assertEqual(resultSet.getValueForFlutter(resultSet.getColumnIndex('age')));
        resultSet.close();
      } catch (err) {
        console.error(`### query failed, code:${err.code}, message:${err.message}`);
      }
      done();
      console.log(TAG + "************* testRdbStoreGetValueForFlutter_0005 end *************");
    })

    /**
     * @tc.name testRdbStoreGetValueForFlutter
     * @tc.number testRdbStoreGetValueForFlutter_0006
     * @tc.desc integer less than Number.MIN_SAFE_INTEGER test
     */
    it('testRdbStoreGetValueForFlutter_0006',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStoreGetValueForFlutter_0006 start *************");
      let valueNum = Number.MIN_SAFE_INTEGER.toString() + 0;
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore != undefined).assertTrue();
      await rdbStore.executeSql(CREATE_TABLE_TEST);
      const valueBucket1: ValuesBucket = {
        'age': valueNum,
      }
      try {
        let rowId = await rdbStore.insert("test", valueBucket1);
        expect(1).assertEqual(rowId);
      } catch (err) {
        console.error(`### insert failed, code:${err.code}, message:${err.message}`);
      }
      try {
        let resultSet = await rdbStore.querySql('SELECT * FROM test');
        expect(true).assertEqual(resultSet.goToFirstRow());
        expect(valueNum).assertEqual(resultSet.getValueForFlutter(resultSet.getColumnIndex('age')));
        resultSet.close();
      } catch (err) {
        console.error(`### query failed, code:${err.code}, message:${err.message}`);
      }
      done();
      console.log(TAG + "************* testRdbStoreGetValueForFlutter_0006 end *************");
    })

    /**
     * @tc.name testRdbStoreGetValueForFlutter
     * @tc.number testRdbStoreGetValueForFlutter_0007
     * @tc.desc other types test
     */
    it('testRdbStoreGetValueForFlutter_0007',  0, async  (done:Function) => {
      console.log(TAG + "************* testRdbStoreGetValueForFlutter_0007 start *************");
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore != undefined).assertTrue();
      await rdbStore.executeSql(CREATE_TABLE_TEST);
      const asset1: relationalStore.Asset = {
        name: "name1",
        uri: "uri1",
        createTime: "createTime1",
        modifyTime: "modifyTime1",
        size: "size1",
        path: "path1",
      }
      const valueBucket1: relationalStore.ValuesBucket = {
        'name': 'test',
        'age': 18,
        'salary': 100,
        'blobType': true,
        'data1': asset1,
      }
      try {
        let rowId = await rdbStore.insert("test", valueBucket1);
        expect(1).assertEqual(rowId);
      } catch (err) {
        console.error(`### insert failed, code:${err.code}, message:${err.message}`);
      }
      try {
        let resultSet = await rdbStore.querySql('SELECT * FROM test');
        expect(true).assertEqual(resultSet.goToFirstRow());
        expect('test').assertEqual(resultSet.getValueForFlutter(resultSet.getColumnIndex('name')));
        expect(18).assertEqual(resultSet.getValueForFlutter(resultSet.getColumnIndex('age')));
        expect(1).assertEqual(resultSet.getValueForFlutter(resultSet.getColumnIndex('blobType')));
        const assets2 = resultSet.getValueForFlutter(resultSet.getColumnIndex('data1')) as relationalStore.Asset;
        expect(asset1.name).assertEqual(assets2.name);
        expect(asset1.uri).assertEqual(assets2.uri);
        expect(asset1.createTime).assertEqual(assets2.createTime);
        expect(asset1.modifyTime).assertEqual(assets2.modifyTime);
        expect(asset1.size).assertEqual(assets2.size);
        expect(asset1.path).assertEqual(assets2.path);
        resultSet.close();
      } catch (err) {
        console.error(`### query failed, code:${err.code}, message:${err.message}`);
      }
      done();
      console.log(TAG + "************* testRdbStoreGetValueForFlutter_0007 end *************");
    })
  })
}