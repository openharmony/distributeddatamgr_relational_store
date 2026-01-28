/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
import { BusinessError } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { relationalStore } from '@kit.ArkData';
import AbilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';
// import fs from '@ohos.file.fs';
import { fileIo as fs } from '@kit.CoreFileKit';

const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();

const DOMAIN = 0x0985;
const TAG = "[RDB_STORE_GET_RDB_STORE_SYNC_ETS_TEST]"

const STORE_CONFIG: relationalStore.StoreConfig = {
  name: 'RdbTest.db',
  securityLevel: relationalStore.SecurityLevel.S3,
  encrypt: false,
  customDir: 'customDir/subCustomDir',
  isReadOnly: false,
};
const SQL_CREATE_TABLE =
  'CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, AGE INTEGER, SALARY REAL, CODES BLOB, IDENTITY UNLIMITED INT)';

let value1 = 'Lisa';
let value2 = 18;
let value3 = 100.5;
let value4 = new Uint8Array([1, 2, 3, 4, 5]);
let value5 = BigInt('15822401018187971961171');
const valueBucket: relationalStore.ValuesBucket = {
  'NAME': value1,
  'AGE': value2,
  'SALARY': value3,
  'CODES': value4,
  'IDENTITY': value5,
};

async function corruptDatabaseFile(fileName: string)
{
  let fileExist = fs.accessSync(fileName);
  expect(fileExist).assertTrue();
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

async function moveDatabaseFile(filePath: string)
{
  let fileExist = fs.accessSync(filePath);
  expect(fileExist).assertTrue();
  fs.unlinkSync(filePath);
}

async function changeFileModeOnlyRead(filePath: string)
{
  let fileExist = fs.accessSync(filePath);
  expect(fileExist).assertTrue();
  await fs.open(filePath, fs.OpenMode.READ_ONLY);
}

export default function RdbStoreGetRdbStoreSyncEtsTest() {
  describe('rdbStoreGetRdbStoreSyncEtsTest', () => {
    // Defines a test suite. Two parameters are supported: test suite name and test suite function.
    beforeAll(async () => {
      console.info(TAG + 'beforeAll');
    })
    beforeEach(async () => {
      console.info(TAG + 'beforeEach');
      await relationalStore.deleteRdbStore(context, STORE_CONFIG);
    })
    afterEach(async () => {
      console.info(TAG + 'afterEach');
      await relationalStore.deleteRdbStore(context, STORE_CONFIG);
    })
    afterAll(async () => {
      console.info(TAG + 'afterAll');
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.name rdb store getRdbStoreSync test
     * @tc.number getRdbStoreSyncTest001
     * @tc.desc rdb store getRdbStoreSync normal test
     */
    it('getRdbStoreSyncTest001', 0, async (done: Function) => {

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest001 start *************");

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, STORE_CONFIG);
        store.executeSync(SQL_CREATE_TABLE);
        store.insertSync('EMPLOYEE', valueBucket);
        let predicates = new relationalStore.RdbPredicates('EMPLOYEE');
        predicates.equalTo('NAME', 'Lisa');
        const resultSet = store.querySync(predicates, ['ID', 'NAME', 'AGE', 'SALARY', 'CODES', 'IDENTITY']);
        while (resultSet.goToNextRow()) {
          const id = resultSet.getLong(resultSet.getColumnIndex('ID'));
          const name = resultSet.getString(resultSet.getColumnIndex('NAME'));
          const age = resultSet.getLong(resultSet.getColumnIndex('AGE'));
          const salary = resultSet.getDouble(resultSet.getColumnIndex('SALARY'));
          const identity = resultSet.getValue(resultSet.getColumnIndex('IDENTITY'));
          hilog.info(DOMAIN, TAG, `id=${id}, name=${name}, age=${age}, salary=${salary}, identity=${identity}`);
        }
        resultSet.close();
        store.deleteSync(predicates);
        store.close();
        await relationalStore.deleteRdbStore(context, STORE_CONFIG);
        done();
      } catch (e) {
        const err = e as BusinessError;
        hilog.error(DOMAIN, 'getRdbStoreSyncTest001', `Failed to get RdbStore. Code:${err.code}, message:${err.message}`);
        expect().assertFail();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest001 end   *************");
    })


    /**
     * @tc.name rdb store getRdbStoreSync test
     * @tc.number getRdbStoreSyncTest002
     * @tc.desc Throw error Code:14800001, message:Invalid args.Parameter error. The StoreConfig.name must be a file name without path.
     */
    it('getRdbStoreSyncTest002', 0, async (done: Function) => {

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest002 start *************");
      const storeConfig: relationalStore.StoreConfig = {
        name: 'abc/RdbTest.db',
        securityLevel: relationalStore.SecurityLevel.S3,
        encrypt: false,
        customDir: 'customDir/subCustomDir',
        isReadOnly: false
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.error(DOMAIN, 'getRdbStoreSyncTest002', `Failed to get RdbStore. Code:${err.code}, message:${err.message}`);
        expect(14800001).assertEqual(Number(err.code));
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest002 end   *************");
    })



    /**
     * @tc.name rdb store getRdbStoreSync test
     * @tc.number getRdbStoreSyncTest003
     * @tc.desc Throw error Code:14800001, message:Invalid args.Illegal CryptoParam.
     */
    it('getRdbStoreSyncTest003', 0, async (done: Function) => {

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest003 start *************");
      let cryptoParam: relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array(),
        iterationCount: -1,
      };

      const storeConfig: relationalStore.StoreConfig = {
        name: 'RdbTest.db',
        securityLevel: relationalStore.SecurityLevel.S3,
        encrypt: true,
        customDir: 'customDir/subCustomDir',
        isReadOnly: false,
        cryptoParam: cryptoParam
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.error(DOMAIN, 'getRdbStoreSyncTest003', `Failed to get RdbStore. Code:${err.code}, message:${err.message}`);
        expect(14800001).assertEqual(Number(err.code));
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest003 end   *************");
    })


    /**
     * @tc.name rdb store getRdbStoreSync test
     * @tc.number getRdbStoreSyncTest004
     * @tc.desc Throw error Code:14800001, message:Invalid args.Illegal tokenizer.
     */
    it('getRdbStoreSyncTest004', 0, async (done: Function) => {

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest004 start *************");
      const storeConfig: relationalStore.StoreConfig = {
        name: 'RdbTest.db',
        securityLevel: relationalStore.SecurityLevel.S3,
        encrypt: false,
        customDir: 'customDir/subCustomDir',
        isReadOnly: false,
        tokenizer: -1
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.error(DOMAIN, 'getRdbStoreSyncTest004', `Failed to get RdbStore. Code:${err.code}, message:${err.message}`);
        expect(14800001).assertEqual(Number(err.code));
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest004 end   *************");
    })

    /**
     * @tc.name rdb store getRdbStoreSync test
     * @tc.number getRdbStoreSyncTest005
     * @tc.desc Throw error Code:14800001, message:Invalid args.Parameter error. The customDir length must be less than or equal to 128 bytes.
     */
    it('getRdbStoreSyncTest005', 0, async (done: Function) => {

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest005 start *************");
      const storeConfig: relationalStore.StoreConfig = {
        name: 'RdbTest.db',
        securityLevel: relationalStore.SecurityLevel.S3,
        encrypt: false,
        customDir: 'customDir/subCustomDir/subCustomDir/subCustomDir/subCustomDir/subCustomDir/subCustomDir/subCustomDir/subCustomDir/subCustomDir/subCustomDir',
        isReadOnly: false
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.error(DOMAIN, 'getRdbStoreSyncTest005', `Failed to get RdbStore. Code:${err.code}, message:${err.message}`);
        expect(14800001).assertEqual(Number(err.code));
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest005 end   *************");
    })


    /**
     * @tc.name rdb store getRdbStoreSync test
     * @tc.number getRdbStoreSyncTest006
     * @tc.desc Throw error Code:14800001, message:Invalid args.Parameter error. The customDir must be a relative directory.
     */
    it('getRdbStoreSyncTest006', 0, async (done: Function) => {

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest006 start *************");
      const storeConfig: relationalStore.StoreConfig = {
        name: 'RdbTest.db',
        securityLevel: relationalStore.SecurityLevel.S3,
        encrypt: false,
        customDir: '/customDir/subCustomDir',
        isReadOnly: false
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.error(DOMAIN, 'getRdbStoreSyncTest006', `Failed to get RdbStore. Code:${err.code}, message:${err.message}`);
        expect(14800001).assertEqual(Number(err.code));
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest006 end   *************");
    })


    /**
     * @tc.name rdb store getRdbStoreSync test
     * @tc.number getRdbStoreSyncTest007
     * @tc.desc Throw error Code:14800010, message:Failed to open or delete the database by an invalid database path.
     */
    it('getRdbStoreSyncTest007', 0, async (done: Function) => {

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest007 start *************");
      const storeConfig: relationalStore.StoreConfig = {
        name: 'RdbTest.db',
        securityLevel: relationalStore.SecurityLevel.S1,
        encrypt: false,
        customDir: 'entry/rdb',
        isReadOnly: false,
        rootDir: "invalidPath/invalidPath"
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.error(DOMAIN, 'getRdbStoreSyncTest007', `Failed to get RdbStore. Code:${err.code}, message:${err.message}`);
        expect(14800010).assertEqual(Number(err.code));
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest007 end   *************");
    })


    /**
     * @tc.name rdb store getRdbStoreSync test
     * @tc.number getRdbStoreSyncTest008
     * @tc.desc Throw error Code:14800011, message:Failed to open the database because it is corrupted.
     */
    it('getRdbStoreSyncTest008', 0, async (done: Function) => {

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest008 start *************");

      const dbName = "RdbTest.db";
      const dbPath = context.databaseDir + "/rdb/" + dbName;
      const dbPathWal = dbPath + "-wal";
      const dbPathShm = dbPath + "-shm";

      const storeConfig: relationalStore.StoreConfig = {
        name: dbName,
        securityLevel: relationalStore.SecurityLevel.S1,
        allowRebuild: false,
      };
      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        store.executeSync(SQL_CREATE_TABLE);
        for (let i = 0; i < 100; i++) {
           store.insertSync('EMPLOYEE', valueBucket);
        }
        store.close();

        await corruptDatabaseFile(dbPath);
        await corruptDatabaseFile(dbPathWal);
        await corruptDatabaseFile(dbPathShm);

        store = relationalStore.getRdbStoreSync(context, storeConfig);
        store.insertSync('EMPLOYEE', valueBucket);
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.error(DOMAIN, 'getRdbStoreSyncTest008', `Failed to get RdbStore. Code:${err.code}, message:${err.message}`);
        expect(14800011).assertEqual(Number(err.code));
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest008 end   *************");
    })


    /**
     * @tc.name rdb store getRdbStoreSync test
     * @tc.number getRdbStoreSyncTest009
     * @tc.desc Throw error Code:14801001, message:The operation is supported in the stage model only.
     */
    // TODO
    it('getRdbStoreSyncTest009', 0, async (done: Function) => {

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest009 start *************");
      const storeConfig: relationalStore.StoreConfig = {
        name: 'RdbTest.db',
        securityLevel: relationalStore.SecurityLevel.S1,
        encrypt: false,
        dataGroupId: '12345678',
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.error(DOMAIN, 'getRdbStoreSyncTest009', `Failed to get RdbStore. Code:${err.code}, message:${err.message}`);
        expect(14801001).assertEqual(Number(err.code));
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest009 end   *************");
    })


    /**
     * @tc.name rdb store getRdbStoreSync test
     * @tc.number getRdbStoreSyncTest010
     * @tc.desc Throw error Code:14801002, message:Invalid data ground ID.
     */

    it('getRdbStoreSyncTest010', 0, async (done: Function) => {

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest010 start *************");
      const storeConfig: relationalStore.StoreConfig = {
        name: 'RdbTest.db',
        securityLevel: relationalStore.SecurityLevel.S1,
        encrypt: false,
        dataGroupId: '12345678',
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.error(DOMAIN, 'getRdbStoreSyncTest010', `Failed to get RdbStore. Code:${err.code}, message:${err.message}`);
        expect(14801002).assertEqual(Number(err.code));
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest010 end   *************");
    })


    /**
     * @tc.name rdb store getRdbStoreSync test
     * @tc.number getRdbStoreSyncTest011
     * @tc.desc Throw error Code:14800017 - Config changed.
     */

    it('getRdbStoreSyncTest011', 0, async (done: Function) => {

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest011 start *************");
      const storeConfig: relationalStore.StoreConfig = {
        name: 'RdbTest.db',
        securityLevel: relationalStore.SecurityLevel.S1,
      };

      const changedStoreConfig: relationalStore.StoreConfig = {
        name: 'RdbTest.db',
        securityLevel: relationalStore.SecurityLevel.S2,
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        store = relationalStore.getRdbStoreSync(context, changedStoreConfig);
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.error(DOMAIN, 'getRdbStoreSyncTest011', `Failed to get RdbStore. Code:${err.code}, message:${err.message}`);
        expect(14800017).assertEqual(Number(err.code));
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest011 end   *************");
    })


    /**
     * @tc.name rdb store getRdbStoreSync test
     * @tc.number getRdbStoreSyncTest012
     * @tc.desc Throw error Code:14800020 - The secret key is corrupted or lost.
     */
    // TODO
    it('getRdbStoreSyncTest012', 0, async (done: Function) => {

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest012 start *************");

      const dbName = "RdbTest.db";
      const storeConfig: relationalStore.StoreConfig = {
        name: dbName,
        securityLevel: relationalStore.SecurityLevel.S1,
        encrypt: true
      };
      const dbPath = context.databaseDir + "/rdb/" + dbName;
      const dbPathWal = dbPath + "-wal";
      const dbPathShm = dbPath + "-shm";
      const dbPathKey = context.databaseDir + "/rdb/key/RdbTest.pub_key_v2";


      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        store.executeSync(SQL_CREATE_TABLE);
        store.insertSync('EMPLOYEE', valueBucket);
        store.close();
        store = undefined;

        const newDbName = "NewRdbTest.db";
        const newDbPath = context.databaseDir + "/rdb/" + newDbName;
        const newDbPathWal = newDbPath + "-wal";
        const newDbPathShm = newDbPath + "-shm";

        await fs.renameSync(dbPath, newDbPath);
        await fs.renameSync(dbPathWal, newDbPathWal);
        await fs.renameSync(dbPathShm, newDbPathShm);
        corruptDatabaseFile(dbPathKey);
        storeConfig.name = newDbName;
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        store.executeSync(SQL_CREATE_TABLE);
        store.insertSync('EMPLOYEE', valueBucket);
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.error(DOMAIN, 'getRdbStoreSyncTest012', `Failed to get RdbStore. Code:${err.code}, message:${err.message}`);
        expect(14800020).assertEqual(Number(err.code));
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest012 end   *************");
    })



    /**
     * @tc.name rdb store getRdbStoreSync test
     * @tc.number getRdbStoreSyncTest013
     * @tc.desc Throw error Code:14800021 - SQLite: Generic error.
     */
    it('getRdbStoreSyncTest013', 0, async (done: Function) => {

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest013 start *************");

      const storeConfig: relationalStore.StoreConfig = {
        name: 'RdbTest.db',
        securityLevel: relationalStore.SecurityLevel.S1,
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        store.executeSync(SQL_CREATE_TABLE);
        store.insertSync('error_table_name', valueBucket);
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.error(DOMAIN, 'getRdbStoreSyncTest013', `Failed to get RdbStore. Code:${err.code}, message:${err.message}`);
        expect(14800021).assertEqual(Number(err.code));
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest013 end   *************");
    })


    /**
     * @tc.name rdb store getRdbStoreSync test
     * @tc.number getRdbStoreSyncTest014
     * @tc.desc Throw error Code:14800027 - SQLite: Attempt to write a readonly database.
     */
    it('getRdbStoreSyncTest014', 0, async (done: Function) => {

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest014 start *************");

      const dbName = "RdbTest.db";
      const dbPath = context.databaseDir + "/rdb/" + dbName;
      const dbPathWal = dbPath + "-wal";
      const dbPathShm = dbPath + "-shm";

      const storeConfig: relationalStore.StoreConfig = {
        name: dbName,
        securityLevel: relationalStore.SecurityLevel.S1,
        isReadOnly: false,
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        store.executeSync(SQL_CREATE_TABLE);
        store.insertSync('EMPLOYEE', valueBucket);
        store.close();
        store = undefined;
        changeFileModeOnlyRead(dbPath);
        changeFileModeOnlyRead(dbPathWal);
        changeFileModeOnlyRead(dbPathShm);
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        store.executeSync("PRAGMA journal_mode")
        store.insertSync('EMPLOYEE', valueBucket);
        store.executeSync("pragma integrity_check");
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.error(DOMAIN, 'getRdbStoreSyncTest014', `Failed to get RdbStore. Code:${err.code}, message:${err.message}`);
        expect(14800027).assertEqual(Number(err.code));
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest014 end   *************");
    })


    /**
     * @tc.name rdb store getRdbStoreSync test
     * @tc.number getRdbStoreSyncTest015
     * @tc.desc Throw error Code:14800028 - SQLite: Some kind of disk I/O error occurred.
     */
    it('getRdbStoreSyncTest015', 0, async (done: Function) => {

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest015 start *************");

      const dbName = "RdbTest.db";
      const dbPath = context.databaseDir + "/rdb/" + dbName;
      const storeConfig: relationalStore.StoreConfig = {
        name: dbName,
        securityLevel: relationalStore.SecurityLevel.S1,
        encrypt: true,
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        moveDatabaseFile(dbPath);
        store.close();
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        store.executeSync(SQL_CREATE_TABLE);
        store.insertSync('EMPLOYEE', valueBucket);
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.error(DOMAIN, 'getRdbStoreSyncTest015', `Failed to get RdbStore. Code:${err.code}, message:${err.message}`);
        expect(14800028).assertEqual(Number(err.code));
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest015 end   *************");
    })


    /**
     * @tc.name rdb store getRdbStoreSync test
     * @tc.number getRdbStoreSyncTest016
     * @tc.desc Throw error Code:14800029 - SQLite: The database is full.
     */
    it('getRdbStoreSyncTest016', 0, async (done: Function) => {

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest016 start *************");

      const storeConfig: relationalStore.StoreConfig = {
        name: 'RdbTest.db',
        securityLevel: relationalStore.SecurityLevel.S1,
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        store.executeSync(`PRAGMA max_page_count = 1`);
        store.executeSync(SQL_CREATE_TABLE);
        store.insertSync('EMPLOYEE', valueBucket);
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.error(DOMAIN, 'getRdbStoreSyncTest016', `Failed to get RdbStore. Code:${err.code}, message:${err.message}`);
        expect(14800029).assertEqual(Number(err.code));
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest016 end   *************");
    })



    /**
     * @tc.name rdb store getRdbStoreSync test
     * @tc.number getRdbStoreSyncTest017
     * @tc.desc Throw error Code:14800030 - SQLite: Unable to open the database file.
     */
    it('getRdbStoreSyncTest017', 0, async (done: Function) => {

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest017 start *************");

      const storeConfig: relationalStore.StoreConfig = {
        name: 'RdbTest.db',
        securityLevel: relationalStore.SecurityLevel.S1,
        isReadOnly: true,
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.error(DOMAIN, 'getRdbStoreSyncTest017', `Failed to get RdbStore. Code:${err.code}, message:${err.message}`);
        expect(14800030).assertEqual(Number(err.code));
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest017 end   *************");
    })

    hilog.info(DOMAIN, TAG, "*************Unit Test End*************");
  })
}







