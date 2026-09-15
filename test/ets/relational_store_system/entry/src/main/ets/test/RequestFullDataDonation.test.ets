/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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
import common from '@ohos.app.ability.common';
import fs from '@ohos.file.fs';
const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();
const TAG = "[RELATIONAL_STORE_RequestFullDataDonation_JSKITS_TEST]"

async function corruptFile(fileName: string)
{
  let stat = await fs.stat(fileName);
  let file = await fs.open(fileName, fs.OpenMode.READ_WRITE);
  fs.lseek(file.fd, 0, fs.WhenceType.SEEK_SET);
  let bufferSize = stat.size;
  let buffer = new ArrayBuffer(bufferSize);
  let uint8Array = new Uint8Array(buffer);
  let fChar = 'F'.charCodeAt(0);
  uint8Array.fill(fChar);
  await fs.write(file.fd, buffer, { offset: 0, length: bufferSize });
}

async function corruptDb(ctx: common.ApplicationContext, config: relationalStore.StoreConfig)
{
  let dbPath = ctx.databaseDir + "/rdb/" + config.name;
  let dbPathWal = dbPath + "-wal";
  let dbPathShm = dbPath + "-shm";
  await corruptFile(dbPath);
  await corruptFile(dbPathWal);
  await corruptFile(dbPathShm);
}

const STORE_CONFIG: relationalStore.StoreConfig = {
  name: "RdbTestDonation.db",
  securityLevel: relationalStore.SecurityLevel.S1,
  isSearchable: true
}

const STORE_CONFIG_READONLY: relationalStore.StoreConfig = {
  name: "RdbTestDonationRO.db",
  securityLevel: relationalStore.SecurityLevel.S1,
  isSearchable: true,
  isReadOnly: true
}

let rdbStore: relationalStore.RdbStore | undefined;
let rdbStoreRO: relationalStore.RdbStore | undefined;

export default function RequestFullDataDonation() {
  describe('RequestFullDataDonation', () => {
    beforeAll(async () => {
      console.info(TAG + 'beforeAll')
    })

    beforeEach(async () => {
      console.info(TAG + 'beforeEach')
      rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
      if (rdbStore != undefined) {
        try {
          await rdbStore.executeSql(
            'CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
        } catch (e) {
          console.error(`executeSql error, code is ${e.code}, message is ${e.message}`);
          expect(null).assertFail();
        }
      }
    })

    afterEach(async () => {
      console.info(TAG + 'afterEach')
      rdbStore = undefined;
      await relationalStore.deleteRdbStore(context, "RdbTestDonation.db");
      if (rdbStoreRO != undefined) {
        rdbStoreRO = undefined;
        await relationalStore.deleteRdbStore(context, "RdbTestDonationRO.db");
      }
    })

    afterAll(async () => {
      console.info(TAG + 'afterAll')
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.number RequestFullDataDonationTest0001
     * @tc.name request full data donation success
     * @tc.desc call requestFullDataDonation with valid table name, expect success
     */
    it('RequestFullDataDonationTest0001', 0, async () => {
      console.log(TAG + "************* RequestFullDataDonationTest0001 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
        return;
      }
      try {
        await rdbStore.requestFullDataDonation(["EMPLOYEE"]);
        console.info('RequestFullDataDonationTest0001 success');
        expect(true).assertTrue();
      } catch (err) {
        console.info(`RequestFullDataDonationTest0001 failed, code is ${err.code}, message is ${err.message}`);
        expect(null).assertFail();
      }
      console.log(TAG + "************* RequestFullDataDonationTest0001 end *************");
    })

    /**
     * @tc.number RequestFullDataDonationTest0002
     * @tc.name request full data donation with multiple tables
     * @tc.desc call requestFullDataDonation with multiple valid table names, expect success
     */
    it('RequestFullDataDonationTest0002', 0, async () => {
      console.log(TAG + "************* RequestFullDataDonationTest0002 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
        return;
      }
      try {
        await rdbStore.executeSql(
          'CREATE TABLE IF NOT EXISTS DEPARTMENT (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, LOCATION TEXT)');
      } catch (e) {
        console.error(`executeSql error, code is ${e.code}, message is ${e.message}`);
        expect(null).assertFail();
      }
      try {
        await rdbStore.requestFullDataDonation(["EMPLOYEE", "DEPARTMENT"]);
        console.info('RequestFullDataDonationTest0002 success');
        expect(true).assertTrue();
      } catch (err) {
        console.info(`RequestFullDataDonationTest0002 failed, code is ${err.code}, message is ${err.message}`);
        expect(null).assertFail();
      }
      console.log(TAG + "************* RequestFullDataDonationTest0002 end *************");
    })

    /**
     * @tc.number RequestFullDataDonationTest0003
     * @tc.name request full data donation with empty table list
     * @tc.desc call requestFullDataDonation with empty array, expect 14800001 (E_INVALID_ARGS)
     */
    it('RequestFullDataDonationTest0003', 0, async () => {
      console.log(TAG + "************* RequestFullDataDonationTest0003 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
        return;
      }
      try {
        await rdbStore.requestFullDataDonation([]);
        console.info('RequestFullDataDonationTest0003 should throw but did not');
        expect(null).assertFail();
      } catch (err) {
        console.info(`RequestFullDataDonationTest0003 err, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual(14800001);
      }
      console.log(TAG + "************* RequestFullDataDonationTest0003 end *************");
    })

    /**
     * @tc.number RequestFullDataDonationTest0004
     * @tc.name request full data donation with non-existent table
     * @tc.desc SetDistributedTables does not validate table existence, expect success
     */
    it('RequestFullDataDonationTest0004', 0, async () => {
      console.log(TAG + "************* RequestFullDataDonationTest0004 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
        return;
      }
      try {
        await rdbStore.requestFullDataDonation(["NON_EXISTENT_TABLE"]);
        console.info('RequestFullDataDonationTest0004 success');
        expect(true).assertTrue();
      } catch (err) {
        console.info(`RequestFullDataDonationTest0004 failed, code is ${err.code}, message is ${err.message}`);
        expect(null).assertFail();
      }
      console.log(TAG + "************* RequestFullDataDonationTest0004 end *************");
    })

    /**
     * @tc.number RequestFullDataDonationTest0005
     * @tc.name request full data donation with no arguments
     * @tc.desc call requestFullDataDonation with no arguments, expect 14800001 (E_INVALID_ARGS)
     */
    it('RequestFullDataDonationTest0005', 0, async () => {
      console.log(TAG + "************* RequestFullDataDonationTest0005 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
        return;
      }
      try {
        await (rdbStore as any).requestFullDataDonation();
        console.info('RequestFullDataDonationTest0005 should throw but did not');
        expect(null).assertFail();
      } catch (err) {
        console.info(`RequestFullDataDonationTest0005 err, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual(14800001);
      }
      console.log(TAG + "************* RequestFullDataDonationTest0005 end *************");
    })

    /**
     * @tc.number RequestFullDataDonationTest0006
     * @tc.name request full data donation with invalid argument type
     * @tc.desc call requestFullDataDonation with a string instead of array, expect parameter error
     */
    it('RequestFullDataDonationTest0006', 0, async () => {
      console.log(TAG + "************* RequestFullDataDonationTest0006 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
        return;
      }
      try {
        await (rdbStore as any).requestFullDataDonation("EMPLOYEE");
        console.info('RequestFullDataDonationTest0006 should throw but did not');
        expect(null).assertFail();
      } catch (err) {
        console.info(`RequestFullDataDonationTest0006 err, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual(401);
      }
      console.log(TAG + "************* RequestFullDataDonationTest0006 end *************");
    })

    /**
     * @tc.number RequestFullDataDonationTest0007
     * @tc.name request full data donation with too many arguments
     * @tc.desc call requestFullDataDonation with extra arguments, expect parameter error
     */
    it('RequestFullDataDonationTest0007', 0, async () => {
      console.log(TAG + "************* RequestFullDataDonationTest0007 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
        return;
      }
      try {
        await (rdbStore as any).requestFullDataDonation(["EMPLOYEE"], "extra");
        console.info('RequestFullDataDonationTest0007 should throw but did not');
        expect(null).assertFail();
      } catch (err) {
        console.info(`RequestFullDataDonationTest0007 err, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual(14800001);
      }
      console.log(TAG + "************* RequestFullDataDonationTest0007 end *************");
    })

    /**
     * @tc.number RequestFullDataDonationTest0008
     * @tc.name request full data donation after store closed
     * @tc.desc call requestFullDataDonation after rdbStore.close(), expect 14800014
     */
    it('RequestFullDataDonationTest0008', 0, async () => {
      console.log(TAG + "************* RequestFullDataDonationTest0008 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
        return;
      }
      try {
        await rdbStore.close();
        await rdbStore.requestFullDataDonation(["EMPLOYEE"]);
        console.info('RequestFullDataDonationTest0008 should throw but did not');
        expect(null).assertFail();
      } catch (err) {
        console.info(`RequestFullDataDonationTest0008 err, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual(14800014);
      }
      console.log(TAG + "************* RequestFullDataDonationTest0008 end *************");
    })

    /**
     * @tc.number RequestFullDataDonationTest0009
     * @tc.name request full data donation on read-only database
     * @tc.desc call requestFullDataDonation on a read-only db, expect 14800043 (E_NOT_SUPPORT)
     */
    it('RequestFullDataDonationTest0009', 0, async () => {
      console.log(TAG + "************* RequestFullDataDonationTest0009 start *************");
      // Create the database first with a normal config, then reopen as read-only
      let roConfig: relationalStore.StoreConfig = {
        name: "RdbTestDonationRO.db",
        securityLevel: relationalStore.SecurityLevel.S1,
        isSearchable: true
      };
      let tmpStore = await relationalStore.getRdbStore(context, roConfig);
      if (tmpStore == undefined) {
        expect().assertFail();
        return;
      }
      await tmpStore.executeSql(
        'CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL UNIQUE, AGE INTEGER, SALARY REAL, CODES BLOB)');
      await tmpStore.close();
      tmpStore = undefined;

      // Now open as read-only
      rdbStoreRO = await relationalStore.getRdbStore(context, STORE_CONFIG_READONLY);
      if (rdbStoreRO == undefined) {
        expect().assertFail();
        return;
      }
      try {
        await rdbStoreRO.requestFullDataDonation(["EMPLOYEE"]);
        console.info('RequestFullDataDonationTest0009 should throw but did not');
        expect(null).assertFail();
      } catch (err) {
        console.info(`RequestFullDataDonationTest0009 err, code is ${err.code}, message is ${err.message}`);
        expect(err.code).assertEqual(14800043);
      }
      await rdbStoreRO?.close();
      rdbStoreRO = undefined;
      console.log(TAG + "************* RequestFullDataDonationTest0009 end *************");
    })

    /**
     * @tc.number RequestFullDataDonationTest0010
     * @tc.name request full data donation returns Promise
     * @tc.desc verify requestFullDataDonation returns a Promise that resolves
     */
    it('RequestFullDataDonationTest0010', 0, async () => {
      console.log(TAG + "************* RequestFullDataDonationTest0010 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
        return;
      }
      try {
        let result = rdbStore.requestFullDataDonation(["EMPLOYEE"]);
        expect(result instanceof Promise).assertTrue();
        await result;
        console.info('RequestFullDataDonationTest0010 success');
        expect(true).assertTrue();
      } catch (err) {
        console.info(`RequestFullDataDonationTest0010 failed, code is ${err.code}, message is ${err.message}`);
        expect(null).assertFail();
      }
      console.log(TAG + "************* RequestFullDataDonationTest0010 end *************");
    })

    /**
     * @tc.number RequestFullDataDonationTest0011
     * @tc.name request full data donation called twice
     * @tc.desc call requestFullDataDonation twice in succession, both should succeed
     */
    it('RequestFullDataDonationTest0011', 0, async () => {
      console.log(TAG + "************* RequestFullDataDonationTest0011 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
        return;
      }
      try {
        await rdbStore.requestFullDataDonation(["EMPLOYEE"]);
        console.info('RequestFullDataDonationTest0011 first call success');
        await rdbStore.requestFullDataDonation(["EMPLOYEE"]);
        console.info('RequestFullDataDonationTest0011 second call success');
        expect(true).assertTrue();
      } catch (err) {
        console.info(`RequestFullDataDonationTest0011 failed, code is ${err.code}, message is ${err.message}`);
        expect(null).assertFail();
      }
      console.log(TAG + "************* RequestFullDataDonationTest0011 end *************");
    })

    /**
     * @tc.number RequestFullDataDonationTest0012
     * @tc.name request full data donation with duplicate table names
     * @tc.desc call requestFullDataDonation with duplicate table names in the list, expect success
     */
    it('RequestFullDataDonationTest0012', 0, async () => {
      console.log(TAG + "************* RequestFullDataDonationTest0012 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
        return;
      }
      try {
        await rdbStore.requestFullDataDonation(["EMPLOYEE", "EMPLOYEE"]);
        console.info('RequestFullDataDonationTest0012 success');
        expect(true).assertTrue();
      } catch (err) {
        console.info(`RequestFullDataDonationTest0012 failed, code is ${err.code}, message is ${err.message}`);
        expect(null).assertFail();
      }
      console.log(TAG + "************* RequestFullDataDonationTest0012 end *************");
    })

    /**
     * @tc.number RequestFullDataDonationTest0013
     * @tc.name request full data donation with corrupted database
     * @tc.desc corrupt the database file then call requestFullDataDonation,
     *          SetDistributedTables is IPC metadata op, does not access db file, expect success
     */
    it('RequestFullDataDonationTest0013', 0, async () => {
      console.log(TAG + "************* RequestFullDataDonationTest0013 start *************");
      if (rdbStore == undefined) {
        expect().assertFail();
        return;
      }
      try {
        await rdbStore.close();
        await corruptDb(context, STORE_CONFIG);
        rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
        await rdbStore.requestFullDataDonation(["EMPLOYEE"]);
        console.info('RequestFullDataDonationTest0013 success (IPC metadata op does not access db file)');
        expect(true).assertTrue();
      } catch (err) {
        console.info(`RequestFullDataDonationTest0013 failed, code is ${err.code}, message is ${err.message}`);
        expect(null).assertFail();
      }
      console.log(TAG + "************* RequestFullDataDonationTest0013 end *************");
    })
  })
}