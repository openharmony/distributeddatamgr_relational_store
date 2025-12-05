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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from '@ohos/hypium';
import relationalStore from '@ohos.data.relationalStore'
import AbilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';
const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();
let DISTRIBUTED_CONFIG : relationalStore.DistributedConfig;
const TAG = "[RELATIONAL_STORE_SETDISTRIBUTEDTABLE_JSKITS_TEST]"

const STORE_CONFIG:relationalStore.StoreConfig = {
  name: "RdbTest.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}

const STORE_CONFIG1:relationalStore.StoreConfig = {
  name: "RdbTest1.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}

let rdbStore: relationalStore.RdbStore | undefined;
let rdbStore1: relationalStore.RdbStore | undefined;

export default function RdbSetDistributedTable() {
  describe('executeSqlTest', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
    })
    beforeEach(async () => {
      console.info(TAG + 'beforeEach')
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
      rdbStore1 = await relationalStore.getRdbStore(context, STORE_CONFIG1);
    })

    afterEach(async () => {
      console.info(TAG + 'afterEach')
      rdbStore = undefined;
      await relationalStore.deleteRdbStore(context, "RdbTest.db");
      rdbStore1 = undefined;
      await relationalStore.deleteRdbStore(context, "RdbTest1.db");
    })

    afterAll(async () => {
      console.info(TAG + 'afterAll')
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.number setDistributedTableTest0001
     * @tc.name set COLLABORATION table
     * @tc.desc set device distributedtable COLLABORATION success
     */
    it('SetDistributedTableTest0001', 0, async () => {
      console.log(TAG + "************* SetDistributedTableTest0001 start *************");
      try {
        DISTRIBUTED_CONFIG = {
          autoSync: false,
          asyncDownloadAsset: false,
          enableCloud: false,
          tableType: relationalStore.DistributedTableType.DEVICE_COLLABORATION
        }
      } catch (e) {
        console.error(`SetDistributedTables error, code is ${e.code},massegeis ${e.message}`);
        expect(null).assertFail();
      }
      if (rdbStore != undefined) {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG);
          console.info('SetDistributedTables EMPLOYEE DEVICE_COLLABORATION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE DEVICE_COLLABORATION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* setDistributedTableTest0001 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0002
     * @tc.name set SINGLE_VERSION table
     * @tc.desc set device distributedtable SINGLE_VERSION success
     */
    it('setDistributedTableTest0002', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0002 start *************");
      try {
        DISTRIBUTED_CONFIG = {
          autoSync: false,
          asyncDownloadAsset: false,
          enableCloud: false,
          tableType: relationalStore.DistributedTableType.SINGLE_VERSION
        }
      } catch (e) {
        console.error(`SetDistributedTables error, code is ${e.code},massegeis ${e.message}`);
        expect(null).assertFail();
      }
      if (rdbStore != undefined) {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG);
          console.info('SetDistributedTables EMPLOYEE DEVICE_COLLABORATION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE DEVICE_COLLABORATION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* setDistributedTableTest0002 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0003
     * @tc.name set default table
     * @tc.desc set device distributedtable tabletype is default(COLLABORATION) success
     */
    it('setDistributedTableTest0003', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0003 start *************");
      if (rdbStore != undefined) {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"]);
          console.info('SetDistributedTables EMPLOYEE DEVICE_COLLABORATION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE DEVICE_COLLABORATION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* concurrentExecuteDDLSQLTest0001 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0004
     * @tc.name set SINGLE_VERSION table no schema
     * @tc.desc set device distributedtable SINGLE_VERSION fail because no schema
     */
    it('setDistributedTableTest0004', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0004 start *************");
      try {
        DISTRIBUTED_CONFIG = {
          autoSync: false,
          asyncDownloadAsset: false,
          enableCloud: false,
          tableType: relationalStore.DistributedTableType.SINGLE_VERSION
        }
      } catch (e) {
        console.error(`SetDistributedTables error, code is ${e.code},massegeis ${e.message}`);
        expect(null).assertFail();
      }
      if (rdbStore1 != undefined) {
        try {
          await rdbStore1.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},massegeis ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore1.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG);
          console.info('SetDistributedTables EMPLOYEE DEVICE_COLLABORATION successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE DEVICE_COLLABORATION failed, code is ${err.code},message is ${err.message}`);
          expect(true).assertTrue();
        }
      }
      console.log(TAG + "************* setDistributedTableTest0004 end *************");
    })
    console.log(TAG + "*************Unit Test End*************");
  })
}
