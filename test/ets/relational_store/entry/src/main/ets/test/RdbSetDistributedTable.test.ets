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
const TAG = "[RELATIONAL_STORE_SETDISTRIBUTEDTABLE_JSKITS_TEST]"

const DISTRIBUTED_CONFIG_COLLABORATION:relationalStore.DistributedConfig= {
  autoSync: false,
  asyncDownloadAsset: false,
  enableCloud: false,
  tableType: relationalStore.DistributedTableType.DEVICE_COLLABORATION
}
const DISTRIBUTED_CONFIG_SINGLE:relationalStore.DistributedConfig = {
  autoSync: false,
  asyncDownloadAsset: false,
  enableCloud: false,
  tableType: relationalStore.DistributedTableType.SINGLE_VERSION
}
const DISTRIBUTED_CONFIG_INVALID:relationalStore.DistributedConfig = {
  autoSync: false,
  asyncDownloadAsset: false,
  enableCloud: false,
  tableType: 3
}
const DISTRIBUTED_CONFIG_UNDEFINED:relationalStore.DistributedConfig = {
  autoSync: false,
  asyncDownloadAsset: false,
  enableCloud: false,
  tableType: undefined
}
const DISTRIBUTED_CONFIG_NOTABLETYPE:relationalStore.DistributedConfig = {
  autoSync: false,
}
const STORE_CONFIG:relationalStore.StoreConfig = {
  name: "RdbTest.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}
const STORE_CONFIGNoschema:relationalStore.StoreConfig = {
  name: "RdbTestNoschema.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}

const STORE_CONFIG1:relationalStore.StoreConfig = {
  name: "RdbTest1.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}
const STORE_CONFIG2:relationalStore.StoreConfig = {
  name: "RdbTest2.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}
const STORE_CONFIG3:relationalStore.StoreConfig = {
  name: "RdbTest3.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}
const STORE_CONFIG4:relationalStore.StoreConfig = {
  name: "RdbTest4.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}
const STORE_CONFIG5:relationalStore.StoreConfig = {
  name: "RdbTest5.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}
const STORE_CONFIG6:relationalStore.StoreConfig = {
  name: "RdbTest6.db",
  securityLevel: relationalStore.SecurityLevel.S1,
}

let rdbStore: relationalStore.RdbStore | undefined;
let rdbStoreNoschema: relationalStore.RdbStore | undefined;
let rdbStore1: relationalStore.RdbStore | undefined;
let rdbStore2: relationalStore.RdbStore | undefined;
let rdbStore3: relationalStore.RdbStore | undefined;
let rdbStore4: relationalStore.RdbStore | undefined;
let rdbStore5: relationalStore.RdbStore | undefined;
let rdbStore6: relationalStore.RdbStore | undefined;

export default function RdbSetDistributedTable() {
  describe('setDistributedTableTest', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
    })
    beforeEach(async () => {
      console.info(TAG + 'beforeEach')
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
      rdbStore1 = await relationalStore.getRdbStore(context, STORE_CONFIG1);
      rdbStoreNoschema = await relationalStore.getRdbStore(context, STORE_CONFIGNoschema);
      rdbStore2 = await relationalStore.getRdbStore(context, STORE_CONFIG2);
      rdbStore3 = await relationalStore.getRdbStore(context, STORE_CONFIG3);
      rdbStore4 = await relationalStore.getRdbStore(context, STORE_CONFIG4);
      rdbStore5 = await relationalStore.getRdbStore(context, STORE_CONFIG5);
      rdbStore6 = await relationalStore.getRdbStore(context, STORE_CONFIG6);
    })

    afterEach(async () => {
      console.info(TAG + 'afterEach')
      rdbStore = undefined;
      await relationalStore.deleteRdbStore(context, "RdbTest.db");
      rdbStore1 = undefined;
      await relationalStore.deleteRdbStore(context, "RdbTest1.db");
      rdbStore2 = undefined;
      await relationalStore.deleteRdbStore(context, "RdbTest2.db");
      rdbStore3 = undefined;
      await relationalStore.deleteRdbStore(context, "RdbTest3.db");
      rdbStore4 = undefined;
      await relationalStore.deleteRdbStore(context, "RdbTest4.db");
      rdbStore5 = undefined;
      await relationalStore.deleteRdbStore(context, "RdbTest5.db");
      rdbStore6 = undefined;
      await relationalStore.deleteRdbStore(context, "RdbTest6.db");
      rdbStoreNoschema = undefined;
      await relationalStore.deleteRdbStore(context, "RdbTestNoschema.db");
    })

    afterAll(async () => {
      console.info(TAG + 'afterAll')
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.number setDistributedTableTest0001
     * @tc.name set COLLABORATION table
     * @tc.desc has schema set DEVICE_COLLABORATION success, after set SINGLE_VERSION fail
     */
    it('SetDistributedTableTest0001', 0, async () => {
      console.log(TAG + "************* SetDistributedTableTest0001 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_COLLABORATION);
          console.info('SetDistributedTableTest0001 EMPLOYEE DEVICE_COLLABORATION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedTableTest0001 EMPLOYEE DEVICE_COLLABORATION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedTableTest0001 EMPLOYEE SINGLE_VERSION successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetDistributedTableTest0001 EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual(14800000);
        }
      }
      console.log(TAG + "************* setDistributedTableTest0001 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0002
     * @tc.name set SINGLE_VERSION table
     * @tc.desc has schema set SINGLE_VERSION success, after set DEVICE_COLLABORATION fail
     */
    it('setDistributedTableTest0002', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0002 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedTables EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_COLLABORATION);
          console.info('SetDistributedTables EMPLOYEE DEVICE_COLLABORATION successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE DEVICE_COLLABORATION failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual(14800000);
        }
      }
      console.log(TAG + "************* setDistributedTableTest0002 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0003
     * @tc.name set SINGLE_VERSION table no schema
     * @tc.desc no schema set SINGLE_VERSION fail, after set DEVICE_COLLABORATION success
     */
    it('setDistributedTableTest0003', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0003 start *************");
      if (rdbStoreNoschema == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStoreNoschema.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStoreNoschema.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedTables EMPLOYEE SINGLE_VERSION successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual(14800000);
        }
        try {
          await rdbStoreNoschema.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_COLLABORATION);
          console.info('SetDistributedTables EMPLOYEE DEVICE_COLLABORATION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE DEVICE_COLLABORATION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* setDistributedTableTest0003 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0004
     * @tc.name set SINGLE_VERSION table no schema
     * @tc.desc rdbStore has schema set SINGLE_VERSION sucsess, rdbStoreNoschema noschema set SINGLE_VERSION fail
     */
    it('setDistributedTableTest0004', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0004 start *************");
      if (rdbStoreNoschema == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStoreNoschema.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStoreNoschema.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedTables EMPLOYEE SINGLE_VERSION successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual(14800000);
        }
      }
      if (rdbStore != undefined) {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedTables EMPLOYEE SINGLE_VERSION successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* setDistributedTableTest0004 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0005
     * @tc.name set SINGLE_VERSION table
     * @tc.desc rdbStore1 has schema set SINGLE_VERSION fail due to bundlename is fail
     */
    it('setDistributedTableTest0005', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0005 start *************");
      if (rdbStore1 == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore1.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore1.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedTables EMPLOYEE SINGLE_VERSION successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual(14800000);
        }
      }
      console.log(TAG + "************* setDistributedTableTest0005 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0006
     * @tc.name set SINGLE_VERSION table
     * @tc.desc has schema set table type is invalid
     */
    it('setDistributedTableTest0006', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0006 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_INVALID);
          console.info('SetDistributedTables EMPLOYEE SINGLE_VERSION successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE SINGLE_VERSION failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual("401");
        }
      }
      console.log(TAG + "************* setDistributedTableTest0006 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0007
     * @tc.name set default table
     * @tc.desc has schema set table type is default
     */

    it('setDistributedTableTest0007', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0007 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"]);
          console.info('SetDistributedTables EMPLOYEE successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* setDistributedTableTest0007 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0008
     * @tc.name set single table
     * @tc.desc has schema set table single type fail due to sync field is not intable
     */

    it('setDistributedTableTest0008', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0008 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedTables EMPLOYEE successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual(14800000);
        }
      }
      console.log(TAG + "************* setDistributedTableTest0008 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0009
     * @tc.name set single table
     * @tc.desc has schema set table single type fail due to sync specialfield is not unique
     */
    it('setDistributedTableTest0009', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0009 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, AGE INTEGER UNIQUE ON CONFLICT REPLACE, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedTables EMPLOYEE successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual(14800000);
        }
      }
      console.log(TAG + "************* setDistributedTableTest0009 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0010
     * @tc.name set single table
     * @tc.desc has schema set table single type success
     */
    it('setDistributedTableTest0010', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0010 start *************");
      if (rdbStore2 == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore2.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (NAME TEXT NOT NULL PRIMARY KEY, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore2.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedTables EMPLOYEE successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* setDistributedTableTest0010 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0011
     * @tc.name set single table
     * @tc.desc has schema set table single type fail sync primarykey but table has other unique field not null not sync
     */
    it('setDistributedTableTest0011', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0011 start *************");
      if (rdbStore2 == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore2.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (NAME TEXT NOT NULL PRIMARY KEY, AGE INTEGER UNIQUE NOT NULL, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore2.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedTables EMPLOYEE successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual(14800000);
        }
      }
      console.log(TAG + "************* setDistributedTableTest0011 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0012
     * @tc.name set single table
     * @tc.desc has schema set table single type fail sync primarykey but table has other unique field not sync
     */
    it('setDistributedTableTest0012', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0012 start *************");
      if (rdbStore2 == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore2.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (NAME TEXT NOT NULL PRIMARY KEY, AGE INTEGER UNIQUE, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore2.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedTables EMPLOYEE successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual(14800000);
        }
      }
      console.log(TAG + "************* setDistributedTableTest0012 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0013
     * @tc.name set single table
     * @tc.desc has schema set table single type fail primarykey table but primarykey is not sync
     */
    it('setDistributedTableTest0013', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0013 start *************");
      if (rdbStore3 == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore3.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (NAME TEXT NOT NULL PRIMARY KEY, AGE INTEGER UNIQUE, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore3.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedTables EMPLOYEE successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual(14800000);
        }
      }
      console.log(TAG + "************* setDistributedTableTest0013 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0014
     * @tc.name set single table
     * @tc.desc has schema set table single type fail table is no primarykey table
     */
    it('setDistributedTableTest0014', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0014 start *************");
      if (rdbStore3 == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore3.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (NAME TEXT NOT NULL, AGE INTEGER UNIQUE, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore3.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedTables EMPLOYEE successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual(14800000);
        }
      }
      console.log(TAG + "************* setDistributedTableTest0014 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0015
     * @tc.name set single table
     * @tc.desc has schema set table single type fail table is has primarykey table and Spcialfield is primarykey, but table has not null field no default value is not sync
     */
    it('setDistributedTableTest0015', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0015 start *************");
      if (rdbStore3 == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore3.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (NAME TEXT NOT NULL, AGE INTEGER PRIMARY KEY, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore3.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedTables EMPLOYEE successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual(14800000);
        }
      }
      console.log(TAG + "************* setDistributedTableTest0015 end *************");
    })


    /**
     * @tc.number setDistributedTableTest0016
     * @tc.name set single table
     * @tc.desc has schema set table single type fail table is has primarykey table and primarykey is autoIncrement&sync, but Spcialfield is not unique
     */
    it('setDistributedTableTest0016', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0016 start *************");
      if (rdbStore4 == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore4.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore4.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedTables EMPLOYEE successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual(14800000);
        }
      }
      console.log(TAG + "************* setDistributedTableTest0016 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0017
     * @tc.name set single table
     * @tc.desc has schema set table single type fail table is has primarykey table and primarykey is autoIncrement&nosync, but has two Spcialfields
     */
    it('setDistributedTableTest0017', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0017 start *************");
      if (rdbStore5 == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore5.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE , AGE INTEGER UNIQUE, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore5.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedTables EMPLOYEE successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual(14800000);
        }
      }
      console.log(TAG + "************* setDistributedTableTest0017 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0018
     * @tc.name set single table
     * @tc.desc has schema set table single type fail due to deviceSyncFields is empty
     */
    it('setDistributedTableTest0018', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0018 start *************");
      if (rdbStore6 == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore6.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE , AGE INTEGER UNIQUE, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore6.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedTables EMPLOYEE successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual(14800000);
        }
      }
      console.log(TAG + "************* setDistributedTableTest0018 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0019
     * @tc.name set single table
     * @tc.desc has schema set table single type success table is has primarykey table and Spcialfield is primarykey, table has not null field default value is not sync
     */
    it('setDistributedTableTest0019', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0019 start *************");
      if (rdbStore3 == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore3.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (NAME TEXT NOT NULL DEFAULT "zhangsan", AGE INTEGER PRIMARY KEY, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore3.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedTables EMPLOYEE successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual(14800000);
        }
      }
      console.log(TAG + "************* setDistributedTableTest0019 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0020
     * @tc.name set single table
     * @tc.desc has schema set table single type success has two unique feild and sync all
     */
    it('setDistributedTableTest0020', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0020 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER UNIQUE ON CONFLICT REPLACE, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedTables EMPLOYEE successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual(14800000);
        }
      }
      console.log(TAG + "************* setDistributedTableTest0020 end *************");
    })

    /**
     * @tc.number setDistributedTableTest0021
     * @tc.name set single table
     * @tc.desc has schema set table single type fail table is has primarykey table and primarykey is autoIncrement&sync, but has unique feild is not sync
     */
    it('setDistributedTableTest0021', 0, async () => {
      console.log(TAG + "************* setDistributedTableTest0021 start *************");
      if (rdbStore4 == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore4.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER UNIQUE, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore4.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetDistributedTables EMPLOYEE successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual(14800000);
        }
      }
      console.log(TAG + "************* setDistributedTableTest0021 end *************");
    })

    /**
     * @tc.number setCloudDistributedTableTest0001
     * @tc.name set cloud table
     * @tc.desc setCloudDistributedTable table config no tabletype
     */
    it('setCloudDistributedTableTest0001', 0, async () => {
      console.log(TAG + "************* setCloudDistributedTableTest0001 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetCloudDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_CLOUD, DISTRIBUTED_CONFIG_NOTABLETYPE);
          console.info('SetCloudDistributedTables EMPLOYEE successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetCloudDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* setCloudDistributedTableTest0001 end *************");
    })

    /**
     * @tc.number setCloudDistributedTableTest0002
     * @tc.name set cloud table
     * @tc.desc setCloudDistributedTable fail due to type is COLLABORATION
     */
    it('setCloudDistributedTableTest0002', 0, async () => {
      console.log(TAG + "************* setCloudDistributedTableTest0002 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetCloudDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_CLOUD, DISTRIBUTED_CONFIG_COLLABORATION);
          console.info('SetCloudDistributedTables EMPLOYEE successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetCloudDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual("801");
        }
      }
      console.log(TAG + "************* setCloudDistributedTableTest0002 end *************");
    })

    /**
     * @tc.number setCloudDistributedTableTest0003
     * @tc.name set cloud table
     * @tc.desc setCloudDistributedTable success type is SINGLE
     */
    it('setCloudDistributedTableTest0003', 0, async () => {
      console.log(TAG + "************* setCloudDistributedTableTest0003 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetCloudDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_CLOUD, DISTRIBUTED_CONFIG_SINGLE);
          console.info('SetCloudDistributedTables EMPLOYEE successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetCloudDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* setCloudDistributedTableTest0003 end *************");
    })

    /**
     * @tc.number setCloudDistributedTableTest0004
     * @tc.name set cloud table
     * @tc.desc setCloudDistributedTable fail due to  type is invalid
     */
    it('setCloudDistributedTableTest0004', 0, async () => {
      console.log(TAG + "************* setCloudDistributedTableTest0004 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetCloudDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_CLOUD, DISTRIBUTED_CONFIG_INVALID);
          console.info('SetCloudDistributedTables EMPLOYEE successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetCloudDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual("401");
        }
      }
      console.log(TAG + "************* setCloudDistributedTableTest0004 end *************");
    })

    /**
     * @tc.number setCloudDistributedTableTest0005
     * @tc.name set cloud table
     * @tc.desc setCloudDistributedTable success type is undefined
     */
    it('setCloudDistributedTableTest0005', 0, async () => {
      console.log(TAG + "************* setCloudDistributedTableTest0005 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetCloudDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_CLOUD, DISTRIBUTED_CONFIG_UNDEFINED);
          console.info('SetCloudDistributedTables EMPLOYEE successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetCloudDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
      }
      console.log(TAG + "************* setCloudDistributedTableTest0005 end *************");
    })

    /**
     * @tc.number setMutleDistributedTableTest0001
     * @tc.name set cloud table and set device table
     * @tc.desc setCloudDistributedTable first and setDeviceDistributedTable fail due to table type device and cloud is exclusive
     */
    it('setMutleDistributedTableTest0001', 0, async () => {
      console.log(TAG + "************* setMutleDistributedTableTest0001 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetCloudDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_CLOUD, DISTRIBUTED_CONFIG_UNDEFINED);
          console.info('SetCloudDistributedTables EMPLOYEE successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetCloudDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDeviceDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_COLLABORATION);
          console.info('SetDeviceDistributedTables EMPLOYEE successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetDeviceDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual(14800000);
        }
      }
      console.log(TAG + "************* setMutleDistributedTableTest0001 end *************");
    })

    /**
     * @tc.number setMutleDistributedTableTest0002
     * @tc.name set device table and set cloud table
     * @tc.desc setDeviceDistributedTable first and setCloudDistributedTable fail due to table type device and cloud is exclusive
     */
    it('setMutleDistributedTableTest0002', 0, async () => {
      console.log(TAG + "************* setMutleDistributedTableTest0002 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
      } else {
        try {
          await rdbStore.executeSql('CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code},message is ${e.message}`);
          expect(null).assertFail();
        }
        console.info(`SetDeviceDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_DEVICE, DISTRIBUTED_CONFIG_COLLABORATION);
          console.info('SetDeviceDistributedTables EMPLOYEE successfully.');
          expect(true).assertTrue();
        } catch (err) {
          console.error(`SetDeviceDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(null).assertFail();
        }
        console.info(`SetCloudDistributedTables EMPLOYEE begin`);
        try {
          await rdbStore.setDistributedTables(["EMPLOYEE"], relationalStore.DistributedType.DISTRIBUTED_CLOUD, DISTRIBUTED_CONFIG_UNDEFINED);
          console.info('SetCloudDistributedTables EMPLOYEE successfully.');
          expect(null).assertFail();
        } catch (err) {
          console.error(`SetCloudDistributedTables EMPLOYEE failed, code is ${err.code},message is ${err.message}`);
          expect(err.code).assertEqual(14800000);
        }
      }
      console.log(TAG + "************* setMutleDistributedTableTest0002 end *************");
    })
    console.log(TAG + "*************Unit Test End*************");
  })
}
