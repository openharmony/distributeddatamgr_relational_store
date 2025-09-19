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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from '@ohos/hypium'
import AbilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';
import relationalStore from '@ohos.data.relationalStore'

const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();
const TAG = "[RelationalStoreCloseTest]";
const dbName = "RdbCloseTest.db";
const ERR_CODE = 14800014;
const STORE_CONFIG: relationalStore.StoreConfig = {
  name: dbName,
  securityLevel: relationalStore.SecurityLevel.S3
};

const CREATE_TABLE_TEST =
  "CREATE TABLE IF NOT EXISTS EMPLOYEE (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL, age INTEGER, salary REAL, blobType BLOB, float32 floatvector(128))";

export default function RelationalStoreCloseTest() {

  describe('relationalStoreCloseTest', () => {

    beforeAll(async () => {
      console.info(TAG + 'beforeAll');
    });

    beforeEach(async () => {
      console.info(TAG + 'beforeEach');
    });

    afterEach(async () => {
      console.info(TAG + 'afterEach');
    });

    afterAll(async () => {
      console.info(TAG + 'afterAll');
    });

    console.info(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.name testRdbStoreRegisterAndClose0100
     * @tc.number testRdbStoreRegisterAndClose0100
     * @tc.desc RelationalStore register then close and unregister
     * @tc.size APITest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreRegisterAndClose0100', 0, async (done: Function) => {
      console.info(TAG + "************* testRdbStoreRegisterAndClose0100 start *************");

      // 开始订阅消息
      let storeObserver = (ChangeInfos: Array<relationalStore.ChangeInfo>) => {
        for (let i = 0; i < ChangeInfos.length; i++) {
          console.info(TAG + "testRdbStoreDataChange0100 ChangeInfos.length=" + ChangeInfos.length);
          console.info(TAG + "testRdbStoreDataChange0100 ChangeInfos[i].inserted[0]=" + ChangeInfos[i].inserted[0]);
        }
      }

      for (let i = 0; i < 100; i++) {
        let rdbStore: relationalStore.RdbStore | undefined = undefined;
        try {
          rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG)
          expect(true).assertEqual(rdbStore != null);
          console.info(TAG + 'Get RdbStore successfully.');
          (rdbStore as relationalStore.RdbStore).executeSql(CREATE_TABLE_TEST);
        } catch (err) {
          console.error(TAG + `Get RdbStore failed, code is ${err.code},message is ${err.message}`);
        }
        try {
          (rdbStore as relationalStore.RdbStore).on('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, storeObserver);
          (rdbStore as relationalStore.RdbStore).close();
          (rdbStore as relationalStore.RdbStore).off('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, storeObserver);
          expect().assertFail();
        } catch (err) {
          console.error(TAG + `on close off is failed, code is ${err.code},message is ${err.message}`);
          expect(true).assertEqual(err.code == ERR_CODE);
        }
        expect(true).assertEqual(rdbStore != null);
        rdbStore = undefined;
        await relationalStore.deleteRdbStore(context, dbName);
      }
      done()
      console.info(TAG + "************* testRdbStoreRegisterAndClose0100 end *************");
    });

    /**
     * @tc.name testRdbStoreRegisterAndClose0200
     * @tc.number testRdbStoreRegisterAndClose0200
     * @tc.desc RelationalStore register then close and unregister
     * @tc.size APITest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreRegisterAndClose0200', 0, async (done: Function) => {
      console.info(TAG + "************* testRdbStoreRegisterAndClose0200 start *************");

      // 开始订阅消息
      let storeObserver = (ChangeInfos: Array<relationalStore.ChangeInfo>) => {
        for (let i = 0; i < ChangeInfos.length; i++) {
          console.info(TAG + "testRdbStoreDataChange0100 ChangeInfos.length=" + ChangeInfos.length);
          console.info(TAG + "testRdbStoreDataChange0100 ChangeInfos[i].inserted[0]=" + ChangeInfos[i].inserted[0]);
        }
      }

      for (let i = 0; i < 100; i++) {
        let rdbStore: relationalStore.RdbStore | undefined = undefined;
        try {
          rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG)
          expect(true).assertEqual(rdbStore != null);
          console.info(TAG + 'Get RdbStore successfully.');
          (rdbStore as relationalStore.RdbStore).executeSql(CREATE_TABLE_TEST);
        } catch (err) {
          console.error(TAG + `Get RdbStore failed, code is ${err.code},message is ${err.message}`);
        }
        try {
          (rdbStore as relationalStore.RdbStore).on('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, storeObserver)
          (rdbStore as relationalStore.RdbStore).close();
          (rdbStore as relationalStore.RdbStore).emit('dataChange');
          expect().assertFail();
        } catch (err) {
          console.error(TAG + `on close off is failed, code is ${err.code},message is ${err.message}`);
          expect(true).assertEqual(err.code == ERR_CODE);
        }
        expect(true).assertEqual(rdbStore != null);
        rdbStore = undefined;
        await relationalStore.deleteRdbStore(context, dbName);
      }
      done()
      console.info(TAG + "************* testRdbStoreRegisterAndClose0200 end *************");
    });


    /**
     * @tc.name testRdbStoreRegisterAndClose0300
     * @tc.number testRdbStoreRegisterAndClose0300
     * @tc.desc RelationalStore register then close and unregister
     * @tc.size APITest
     * @tc.type Function
     * @tc.level Level 2
     */
    it('testRdbStoreRegisterAndClose0300', 0, async (done: Function) => {
      console.info(TAG + "************* testRdbStoreRegisterAndClose0300 start *************");

      // 开始订阅消息
      let storeObserver = (ChangeInfos: Array<relationalStore.ChangeInfo>) => {
        for (let i = 0; i < ChangeInfos.length; i++) {
          console.info(TAG + "testRdbStoreDataChange0100 ChangeInfos.length=" + ChangeInfos.length);
          console.info(TAG + "testRdbStoreDataChange0100 ChangeInfos[i].inserted[0]=" + ChangeInfos[i].inserted[0]);
        }
      }

      for (let i = 0; i < 100; i++) {
        let rdbStore: relationalStore.RdbStore | undefined = undefined;
        try {
          rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG)
          expect(true).assertEqual(rdbStore != null);
          console.info(TAG + 'Get RdbStore successfully.');
          (rdbStore as relationalStore.RdbStore).executeSql(CREATE_TABLE_TEST);
        } catch (err) {
          console.error(TAG + `Get RdbStore failed, code is ${err.code},message is ${err.message}`);
        }
        try {
          (rdbStore as relationalStore.RdbStore).on('dataChange', relationalStore.SubscribeType.SUBSCRIBE_TYPE_LOCAL_DETAILS, storeObserver)
          (rdbStore as relationalStore.RdbStore).close();
          (rdbStore as relationalStore.RdbStore).emit('dataChange');
          expect().assertFail();
        } catch (err) {
          console.error(TAG + `on close off is failed, code is ${err.code},message is ${err.message}`);
          expect(true).assertEqual(err.code == ERR_CODE);
        }
        expect(true).assertEqual(rdbStore != null);
        rdbStore = undefined;
        await relationalStore.deleteRdbStore(context, dbName);
      }
      done()
      console.info(TAG + "************* testRdbStoreRegisterAndClose0300 end *************");
    });

    console.info(TAG + " *************Unit Test End*************");
  })
}
