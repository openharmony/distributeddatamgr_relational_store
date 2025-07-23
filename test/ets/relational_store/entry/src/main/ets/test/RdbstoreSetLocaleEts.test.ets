
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


const TAG = "[STAGE_RELATIONAL_STORE_JSKITS_TEST]";
let rdbStore:relationalStore.RdbStore | undefined = undefined;

const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
  "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL)";

const STORE_CONFIG: relationalStore.StoreConfig = {
  name: "rdbStore.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}

const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();


export default function SetLocaleEtsTest() {
  describe('SetLocaleEtsTest', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
    })
    beforeEach(async () => {
      console.info(TAG + 'beforeEach');
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
      expect(rdbStore != undefined).assertTrue();
      await rdbStore?.executeSql(CREATE_TABLE_TEST);
      const valueBucket: relationalStore.ValuesBucket = {
        'name': '张三',
        'age': 18,
        'salary': 25000,
      };
      const valueBucket1: relationalStore.ValuesBucket = {
        'name': '李四',
        'age': 18,
        'salary': 25000,
      };
      const valueBucket2: relationalStore.ValuesBucket = {
        'name': '王五',
        'age': 18,
        'salary': 25000,
      };
      await rdbStore?.insert('test', valueBucket);
      await rdbStore?.insert('test', valueBucket1);
      await rdbStore?.insert('test', valueBucket2);

    })
    afterEach(async () => {
      console.info(TAG + 'afterEach');
      await relationalStore.deleteRdbStore(context, "rdbStore.db");
    })
    afterAll(async () => {
      console.info(TAG + 'afterAll');
    })


    /**
     * @tc.name Normal case
     * @tc.number testRdbStoreSetLocale_0001
     */
    it('testRdbStoreSetLocale_0001',  0, async  () => {
      console.log(TAG + "************* testRdbStoreSetLocale_0001 start *************");
      try {
        await rdbStore?.setLocale("zh");
        let resultSet = await rdbStore?.querySql("select * from test order by name collate LOCALES")
        resultSet?.goToNextRow()

        expect('李四').assertEqual(resultSet?.getString(resultSet.getColumnIndex("name")));
        resultSet?.goToNextRow()
        expect('王五').assertEqual(resultSet?.getString(resultSet.getColumnIndex("name")));
        resultSet?.goToNextRow()
        expect('张三').assertEqual(resultSet?.getString(resultSet.getColumnIndex("name")));
      }catch (e){
        console.error(`message is ${e.message}  code  ${e.code}`);
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStoreSetLocale_0001 end *************");
    })

    /**
     * @tc.name Abnormal case
     * @tc.number testRdbStoreSetLocale_0002
     */
    it('testRdbStoreSetLocale_0002',  0, async  () => {
      console.log(TAG + "************* testRdbStoreSetLocale_0002 start *************");
      try {
        await rdbStore?.close();
        await rdbStore?.setLocale("zh");
      }catch (e){
        console.error(`message is ${e.message}  code  ${e.code}`);
        expect(e.code).assertEqual("14800014");;
      }
      console.log(TAG + "************* testRdbStoreSetLocale_0002 end *************");
    })

    /**
     * @tc.name Abnormal case
     * @tc.number testRdbStoreSetLocale_0003
     */
    it('testRdbStoreSetLocale_0003',  0, async  () => {
      console.log(TAG + "************* testRdbStoreSetLocale_0003 start *************");
      try {
        await rdbStore?.setLocale("111");
      }catch (e){
        console.error(`message is ${e.message}  code  ${e.code}`);
        expect(e.code).assertEqual(14800001);;
      }
      console.log(TAG + "************* testRdbStoreSetLocale_0003 end *************");
    })

    /**
     * @tc.name Normal case
     * @tc.number testRdbStoreSetLocale_0004
     */
    it('testRdbStoreSetLocale_0004',  0, async  () => {
      console.log(TAG + "************* testRdbStoreSetLocale_0004 start *************");
      try {
        for (let i = 0; i < 10; i++) {
          await rdbStore?.querySql("select * from test")
        }
        await rdbStore?.setLocale("zh");
        let resultSet = await rdbStore?.querySql("select * from test order by name collate LOCALES")
        resultSet?.goToNextRow()

        expect('李四').assertEqual(resultSet?.getString(resultSet.getColumnIndex("name")));
        resultSet?.goToNextRow()
        expect('王五').assertEqual(resultSet?.getString(resultSet.getColumnIndex("name")));
        resultSet?.goToNextRow()
        expect('张三').assertEqual(resultSet?.getString(resultSet.getColumnIndex("name")));
      }catch (e){
        console.error(`message is ${e.message}  code  ${e.code}`);
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStoreSetLocale_0004 end *************");
    })

    /**
     * @tc.name Normal case
     * @tc.number testRdbStoreSetLocale_0005
     */
    it('testRdbStoreSetLocale_0005',  0, async  () => {
      console.log(TAG + "************* testRdbStoreSetLocale_0005 start *************");
      try {
        await rdbStore?.setLocale("zh");
        const rdbTrans = await rdbStore?.createTransaction();
        let resultSet = await rdbTrans?.querySql("select * from test order by name collate LOCALES")
        console.log(`mmy rowCount ${resultSet?.rowCount}`)
        resultSet?.goToNextRow()
        expect('李四').assertEqual(resultSet?.getString(resultSet.getColumnIndex("name")));
        resultSet?.goToNextRow()
        expect('王五').assertEqual(resultSet?.getString(resultSet.getColumnIndex("name")));
        resultSet?.goToNextRow()
        expect('张三').assertEqual(resultSet?.getString(resultSet.getColumnIndex("name")));
        await rdbTrans?.commit();
      }catch (e){
        console.error(`message is ${e.message}  code  ${e.code}`);
        expect().assertFail();
      }
      console.log(TAG + "************* testRdbStoreSetLocale_0005 end *************");
    })
  })
}