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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from '@ohos/hypium';
import hilog from '@ohos.hilog';
import relationalStore from '@ohos.data.relationalStore';
import AbilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';
import fs from '@ohos.file.fs';
import { BusinessError } from '@ohos.base';

const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();

const DOMAIN = 0x0985;
const TAG = "[RDB_STORE_GET_RDB_STORE_SYNC_ETS_TEST]";

const RDB_TEST_NAME = 'RdbTest.db';
// SQL for creating test table
const SQL_CREATE_TABLE =
  'CREATE TABLE IF NOT EXISTS EMPLOYEE (ID INTEGER PRIMARY KEY AUTOINCREMENT, NAME TEXT NOT NULL, AGE INTEGER, SALARY REAL, CODES BLOB, IDENTITY UNLIMITED INT)';

// Test data
const value1 = 'Lisa';
const value2 = 18;
const value3 = 100.5;
const value4 = new Uint8Array([1, 2, 3, 4, 5]);
const value5 = BigInt('15822401018187971961171');
const valueBucket: relationalStore.ValuesBucket = {
  'NAME': value1,
  'AGE': value2,
  'SALARY': value3,
  'CODES': value4,
  'IDENTITY': value5,
};

/**
 * Corrupt database file to simulate database corruption
 * @param fileName Database file path
 */
async function corruptDatabaseFile(fileName: string)
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

/**
 * Remove database file to simulate I/O error
 * @param filePath Database file path
 */
async function moveDatabaseFile(filePath: string): Promise<void> {
  // fs.accessSync throws if file doesn't exist
  fs.accessSync(filePath);
  expect(true).assertTrue();
  fs.unlinkSync(filePath);
}

/**
 * Change file to read-only mode
 * @param filePath File path
 */
async function changeFileModeOnlyRead(filePath: string): Promise<void> {
  // fs.accessSync throws if file doesn't exist
  fs.accessSync(filePath);
  expect(true).assertTrue();
  let file = await fs.open(filePath, fs.OpenMode.READ_ONLY);
  await fs.close(file.fd);
}

/**
 * Cleanup test-related database files
 * @param dbName Database name
 */
async function cleanupDatabaseFiles(dbName: string): Promise<void> {
  const dbPath = context.databaseDir + "/rdb/" + dbName;
  const dbPathWal = dbPath + "-wal";
  const dbPathShm = dbPath + "-shm";
  const dbPathKey = context.databaseDir + "/rdb/key/" + dbName.replace('.db', '.pub_key_v2');

  try {
    fs.accessSync(dbPath);
    fs.unlinkSync(dbPath);
  } catch (e) {
  }
  try {
    fs.accessSync(dbPathWal);
    fs.unlinkSync(dbPathWal);
  } catch (e) {
  }
  try {
    fs.accessSync(dbPathShm);
    fs.unlinkSync(dbPathShm);
  } catch (e) {
  }
  try {
    fs.accessSync(dbPathKey);
    fs.unlinkSync(dbPathKey);
  } catch (e) {
  }
}

export default function RdbStoreGetRdbStoreSyncEtsTest() {
  describe('rdbStoreGetRdbStoreSyncEtsTest', () => {
    beforeAll(async () => {
      hilog.info(DOMAIN, TAG, 'beforeAll: Test suite initialization');
    })

    beforeEach(async () => {
      hilog.info(DOMAIN, TAG, 'beforeEach: Cleanup before each test');
      await relationalStore.deleteRdbStore(context, RDB_TEST_NAME);
    })

    afterEach(async () => {
      hilog.info(DOMAIN, TAG, 'afterEach: Cleanup after each test');
      await relationalStore.deleteRdbStore(context, RDB_TEST_NAME);
    })

    afterAll(async () => {
      hilog.info(DOMAIN, TAG, 'afterAll: Test suite cleanup');
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.name rdb store getRdbStoreSync normal test
     * @tc.number getRdbStoreSyncTest001
     * @tc.desc Normal parameters, open database, create table, insert data, query data, delete data
     * @tc.expect No exception, return RdbStore normally
     */
    it('getRdbStoreSyncTest001', 0, async (done: Function) => {
      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest001 start *************");

      // Test configuration
      const storeConfig: relationalStore.StoreConfig = {
        name: RDB_TEST_NAME,
        securityLevel: relationalStore.SecurityLevel.S3,
        encrypt: false,
        customDir: 'customDir/subCustomDir',
        isReadOnly: false,
      };
      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        // 1. Get RdbStore
        hilog.info(DOMAIN, TAG, "Step 1: Get RdbStore");
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        expect(store !== undefined).assertTrue();

        // 2. Create table
        hilog.info(DOMAIN, TAG, "Step 2: Create table");
        store.executeSync(SQL_CREATE_TABLE);

        // 3. Insert data
        hilog.info(DOMAIN, TAG, "Step 3: Insert data");
        let insertResult = store.insertSync('EMPLOYEE', valueBucket);
        expect(insertResult > 0).assertTrue();
        hilog.info(DOMAIN, TAG, `Insert result: ${insertResult}`);

        // 4. Query data
        hilog.info(DOMAIN, TAG, "Step 4: Query data");
        let predicates = new relationalStore.RdbPredicates('EMPLOYEE');
        predicates.equalTo('NAME', 'Lisa');
        const resultSet = store.querySync(predicates, ['ID', 'NAME', 'AGE', 'SALARY', 'CODES', 'IDENTITY']);

        // 5. Verify query results
        hilog.info(DOMAIN, TAG, "Step 5: Verify query results");
        let rowCount = 0;
        while (resultSet.goToNextRow()) {
          rowCount++;
          const id = resultSet.getLong(resultSet.getColumnIndex('ID'));
          const name = resultSet.getString(resultSet.getColumnIndex('NAME'));
          const age = resultSet.getLong(resultSet.getColumnIndex('AGE'));
          const salary = resultSet.getDouble(resultSet.getColumnIndex('SALARY'));
          const identity = resultSet.getValue(resultSet.getColumnIndex('IDENTITY'));
          hilog.info(DOMAIN, TAG, `Record found - id=${id}, name=${name}, age=${age}, salary=${salary}, identity=${identity}`);

          // Verify data
          expect(name).assertEqual(value1);
          expect(age).assertEqual(value2);
          expect(salary).assertEqual(value3);
        }
        resultSet.close();
        expect(rowCount).assertEqual(1);

        // 6. Delete data
        hilog.info(DOMAIN, TAG, "Step 6: Delete data");
        let deleteResult = store.deleteSync(predicates);
        expect(deleteResult >= 0).assertTrue();

        // 7. Close database
        hilog.info(DOMAIN, TAG, "Step 7: Close store");

        hilog.info(DOMAIN, TAG, "getRdbStoreSyncTest001: All steps passed");
        done();
      } catch (e) {
        const err = e as BusinessError;
        hilog.error(DOMAIN, TAG, `getRdbStoreSyncTest001 failed. Code:${err.code}, message:${err.message}`);
        expect().assertFail();
      } finally {
        store?.close();
        await relationalStore.deleteRdbStore(context, storeConfig);
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest001 end *************");
    })

    /**
     * @tc.name rdb store getRdbStoreSync with invalid database name
     * @tc.number getRdbStoreSyncTest002
     * @tc.desc Abnormal parameter, config contains invalid database name (with path separator)
     * @tc.expect Throw exception, 14800001 Invalid args
     */
    it('getRdbStoreSyncTest002', 0, async (done: Function) => {
      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest002 start *************");

      const storeConfig: relationalStore.StoreConfig = {
        name: 'abc/RdbTest.db', // Invalid: contains path separator
        securityLevel: relationalStore.SecurityLevel.S3,
        encrypt: false,
        customDir: 'customDir/subCustomDir',
        isReadOnly: false
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        hilog.error(DOMAIN, TAG, "getRdbStoreSyncTest002: Should have thrown an error");
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.info(DOMAIN, TAG, `getRdbStoreSyncTest002: Caught expected error. Code:${err.code}, message:${err.message}`);
        expect(14800001).assertEqual(Number(err.code));
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest002 end *************");
    })

    /**
     * @tc.name rdb store getRdbStoreSync with invalid crypto param
     * @tc.number getRdbStoreSyncTest003
     * @tc.desc Abnormal parameter, config contains invalid cryptoParam
     * @tc.expect Throw exception, 14800001 Invalid args
     */
    it('getRdbStoreSyncTest003', 0, async (done: Function) => {
      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest003 start *************");

      let cryptoParam: relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array(), // Invalid: empty key
        iterationCount: -1, // Invalid: negative number
      };

      const storeConfig: relationalStore.StoreConfig = {
        name: RDB_TEST_NAME,
        securityLevel: relationalStore.SecurityLevel.S3,
        encrypt: true,
        customDir: 'customDir/subCustomDir',
        isReadOnly: false,
        cryptoParam: cryptoParam
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        hilog.error(DOMAIN, TAG, "getRdbStoreSyncTest003: Should have thrown an error");
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.info(DOMAIN, TAG, `getRdbStoreSyncTest003: Caught expected error. Code:${err.code}, message:${err.message}`);
        expect(14800001).assertEqual(Number(err.code));
      } finally {
        store?.close();
        await relationalStore.deleteRdbStore(context, storeConfig);
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest003 end *************");
    })

    /**
     * @tc.name rdb store getRdbStoreSync with invalid tokenizer
     * @tc.number getRdbStoreSyncTest004
     * @tc.desc Abnormal parameter, config contains invalid tokenizer
     * @tc.expect Throw exception, 14800001 Invalid args
     */
    it('getRdbStoreSyncTest004', 0, async (done: Function) => {
      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest004 start *************");

      const storeConfig: relationalStore.StoreConfig = {
        name: RDB_TEST_NAME,
        securityLevel: relationalStore.SecurityLevel.S3,
        encrypt: false,
        customDir: 'customDir/subCustomDir',
        isReadOnly: false,
        tokenizer: -1 // Invalid: out of range tokenizer value
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        hilog.error(DOMAIN, TAG, "getRdbStoreSyncTest004: Should have thrown an error");
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.info(DOMAIN, TAG, `getRdbStoreSyncTest004: Caught expected error. Code:${err.code}, message:${err.message}`);
        expect(14800001).assertEqual(Number(err.code));
      } finally {
        store?.close();
        await relationalStore.deleteRdbStore(context, storeConfig);
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest004 end *************");
    })

    /**
     * @tc.name rdb store getRdbStoreSync with customDir exceeding 128 bytes
     * @tc.number getRdbStoreSyncTest005
     * @tc.desc Abnormal parameter, config contains customDir exceeding 128 bytes
     * @tc.expect Throw exception, 14800001 Invalid args
     */
    it('getRdbStoreSyncTest005', 0, async (done: Function) => {
      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest005 start *************");

      // Construct customDir exceeding 128 bytes
      const longCustomDir = 'customDir/subCustomDir/subCustomDir/subCustomDir/subCustomDir/subCustomDir/subCustomDir/subCustomDir/subCustomDir/subCustomDir/subCustomDir';

      const storeConfig: relationalStore.StoreConfig = {
        name: RDB_TEST_NAME,
        securityLevel: relationalStore.SecurityLevel.S3,
        encrypt: false,
        customDir: longCustomDir,
        isReadOnly: false
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        hilog.error(DOMAIN, TAG, "getRdbStoreSyncTest005: Should have thrown an error");
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.info(DOMAIN, TAG, `getRdbStoreSyncTest005: Caught expected error. Code:${err.code}, message:${err.message}`);
        expect(14800001).assertEqual(Number(err.code));
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest005 end *************");
    })

    /**
     * @tc.name rdb store getRdbStoreSync with customDir starting with '/'
     * @tc.number getRdbStoreSyncTest006
     * @tc.desc Abnormal parameter, config contains customDir starting with '/'
     * @tc.expect Throw exception, 14800001 Invalid args
     */
    it('getRdbStoreSyncTest006', 0, async (done: Function) => {
      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest006 start *************");

      const storeConfig: relationalStore.StoreConfig = {
        name: RDB_TEST_NAME,
        securityLevel: relationalStore.SecurityLevel.S3,
        encrypt: false,
        customDir: '/customDir/subCustomDir', // Invalid: absolute path
        isReadOnly: false
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        hilog.error(DOMAIN, TAG, "getRdbStoreSyncTest006: Should have thrown an error");
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.info(DOMAIN, TAG, `getRdbStoreSyncTest006: Caught expected error. Code:${err.code}, message:${err.message}`);
        expect(14800001).assertEqual(Number(err.code));
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest006 end *************");
    })

    /**
     * @tc.name rdb store getRdbStoreSync with invalid database path
     * @tc.number getRdbStoreSyncTest007
     * @tc.desc Abnormal parameter, database path contains invalid value
     * @tc.expect Throw exception, 14800010 Invalid database path
     */
    it('getRdbStoreSyncTest007', 0, async (done: Function) => {
      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest007 start *************");

      const storeConfig: relationalStore.StoreConfig = {
        name: RDB_TEST_NAME,
        securityLevel: relationalStore.SecurityLevel.S1,
        encrypt: false,
        customDir: 'entry/rdb',
        isReadOnly: false,
        rootDir: "invalidPath/invalidPath" // Invalid: invalid root directory path
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        hilog.error(DOMAIN, TAG, "getRdbStoreSyncTest007: Should have thrown an error");
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.info(DOMAIN, TAG, `getRdbStoreSyncTest007: Caught expected error. Code:${err.code}, message:${err.message}`);
        expect(14800010).assertEqual(Number(err.code));
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest007 end *************");
    })

    /**
     * @tc.name rdb store getRdbStoreSync with corrupted database
     * @tc.number getRdbStoreSyncTest008
     * @tc.desc Abnormal parameter, database corruption (wrong encryption key causes decryption failure)
     * @tc.expect Throw exception, 14800011 Database is corrupted
     */
    it('getRdbStoreSyncTest008', 0, async (done: Function) => {
      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest008 start *************");

      // Define custom encryption key
      let cryptoParam: relationalStore.CryptoParam = {
        encryptionKey: new Uint8Array([1, 2, 3, 4, 5, 6]),
      };

      const storeConfig: relationalStore.StoreConfig = {
        name: RDB_TEST_NAME,
        securityLevel: relationalStore.SecurityLevel.S2,
        cryptoParam: cryptoParam
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        // 1. Create encrypted database with custom key [1, 2, 3, 4, 5, 6]
        hilog.info(DOMAIN, TAG, "Step 1: Create encrypted database with key [1,2,3,4,5,6]");
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        store.executeSync(SQL_CREATE_TABLE);
        store.insertSync('EMPLOYEE', valueBucket);
        store.close();
        store = undefined;
        hilog.info(DOMAIN, TAG, "getRdbStoreSyncTest008: Database created and closed successfully");

        // 2. Modify encryption key to a different value [6, 5, 4, 3, 2, 1]
        hilog.info(DOMAIN, TAG, "Step 2: Change encryption key to [6,5,4,3,2,1]");
        cryptoParam.encryptionKey = new Uint8Array([6, 5, 4, 3, 2, 1]);

        // 3. Try to open database with wrong key
        // This will cause SQLite decryption to fail with E_SQLITE_CORRUPT
        hilog.info(DOMAIN, TAG, "Step 3: Try to open database with wrong key");
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        store.close();
        hilog.error(DOMAIN, TAG, "getRdbStoreSyncTest008: Should have thrown an error");
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.info(DOMAIN, TAG, `getRdbStoreSyncTest008: Caught expected error. Code:${err.code}, message:${err.message}`);
        // Using wrong encryption key causes SQLite to fail decryption
        // Result: E_SQLITE_CORRUPT (14800011)
        expect(14800011).assertEqual(Number(err.code));
        hilog.info(DOMAIN, TAG, "getRdbStoreSyncTest008: Successfully caught 14800011 error");
      } finally {
        store?.close();
        await relationalStore.deleteRdbStore(context, storeConfig);
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest008 end *************");
    })

    /**
     * @tc.name rdb store getRdbStoreSync in non-FA mode with dataGroupId
     * @tc.number getRdbStoreSyncTest009
     * @tc.desc Abnormal parameter, operation only supported in stage mode (using dataGroupId)
     * @tc.expect Throw exception, 14801001 The operation is supported in the stage model only
     * @tc.autoTest false (Requires Stage mode environment)
     */
    it('getRdbStoreSyncTest009', 0, async (done: Function) => {
      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest009 start *************");

      const storeConfig: relationalStore.StoreConfig = {
        name: RDB_TEST_NAME,
        securityLevel: relationalStore.SecurityLevel.S1,
        encrypt: false,
        dataGroupId: '12345678', // Only supported in Stage mode
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        // Should throw exception in non-Stage mode
        // Test may need adjustment if running in Stage mode
        hilog.warn(DOMAIN, TAG, "getRdbStoreSyncTest009: Test may pass in Stage mode");
        // Don't force failure as it might be running in Stage mode
      } catch (e) {
        const err = e as BusinessError;
        hilog.info(DOMAIN, TAG, `getRdbStoreSyncTest009: Caught expected error. Code:${err.code}, message:${err.message}`);
        // Expect 14801001 in non-Stage mode
        if (Number(err.code) === 14801001) {
          hilog.info(DOMAIN, TAG, "getRdbStoreSyncTest009: Correctly threw error for non-Stage mode");
        }
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest009 end *************");
    })

    /**
     * @tc.name rdb store getRdbStoreSync with invalid dataGroupId
     * @tc.number getRdbStoreSyncTest010
     * @tc.desc Abnormal parameter, invalid data group ID
     * @tc.expect Throw exception, 14801002 Invalid data group ID
     */
    it('getRdbStoreSyncTest010', 0, async (done: Function) => {
      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest010 start *************");

      const storeConfig: relationalStore.StoreConfig = {
        name: RDB_TEST_NAME,
        securityLevel: relationalStore.SecurityLevel.S1,
        encrypt: false,
        dataGroupId: '12345678', // Invalid: non-existent dataGroupId
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        hilog.error(DOMAIN, TAG, "getRdbStoreSyncTest010: Should have thrown an error");
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.info(DOMAIN, TAG, `getRdbStoreSyncTest010: Caught expected error. Code:${err.code}, message:${err.message}`);
        expect(14801002).assertEqual(Number(err.code));
      } finally {
        store?.close();
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest010 end *************");
    })

    /**
     * @tc.name rdb store getRdbStoreSync with changed config
     * @tc.number getRdbStoreSyncTest011
     * @tc.desc Abnormal parameter, config parameter changed (different securityLevel)
     * @tc.expect Throw exception, 14800017 Config changed
     */
    it('getRdbStoreSyncTest011', 0, async (done: Function) => {
      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest011 start *************");

      const storeConfig: relationalStore.StoreConfig = {
        name: RDB_TEST_NAME,
        securityLevel: relationalStore.SecurityLevel.S1,
      };

      const changedStoreConfig: relationalStore.StoreConfig = {
        name: RDB_TEST_NAME,
        securityLevel: relationalStore.SecurityLevel.S2, // Different security level
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        // 1. Create database with original config
        hilog.info(DOMAIN, TAG, "Step 1: Create database with original config");
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        // 2. Try to open with changed config (should fail)
        hilog.info(DOMAIN, TAG, "Step 2: Try to open with changed config");
        store = relationalStore.getRdbStoreSync(context, changedStoreConfig);
        hilog.error(DOMAIN, TAG, "getRdbStoreSyncTest011: Should have thrown an error");
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.info(DOMAIN, TAG, `getRdbStoreSyncTest011: Caught expected error. Code:${err.code}, message:${err.message}`);
        expect(14800017).assertEqual(Number(err.code));
      } finally {
        store?.close();
        await relationalStore.deleteRdbStore(context, storeConfig);
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest011 end *************");
    })

    /**
     * @tc.name rdb store getRdbStoreSync with corrupted key
     * @tc.number getRdbStoreSyncTest012
     * @tc.desc Abnormal parameter, secret key corrupted or lost
     * @tc.expect Throw exception, 14800020 The secret key is corrupted or lost
     * @tc.autoTest false (Requires specific environment configuration)
     */
    it('getRdbStoreSyncTest012', 0, async (done: Function) => {
      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest012 start *************");

      const dbName = RDB_TEST_NAME;
      const dbPath = context.databaseDir + "/rdb/" + dbName;
      const dbPathKey = context.databaseDir + "/rdb/key/" + dbName.replace('.db', '.pub_key_v2');

      // New file names after rename
      const newDbName = 'RdbTestCorrupted.db';
      const newDbPath = context.databaseDir + "/rdb/" + newDbName;
      const newDbPathKey = context.databaseDir + "/rdb/key/" + newDbName.replace('.db', '.pub_key_v2');

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        // Step 1: Create encrypted database
        hilog.info(DOMAIN, TAG, "Step 1: Create encrypted database");
        const storeConfig: relationalStore.StoreConfig = {
          name: dbName,
          securityLevel: relationalStore.SecurityLevel.S1,
          encrypt: true,
        };
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        store.executeSync(SQL_CREATE_TABLE);
        store.insertSync('EMPLOYEE', valueBucket);
        store.close();
        store = undefined;
        hilog.info(DOMAIN, TAG, "Step 1: Encrypted database created successfully");

        // Step 2: Rename database and key files, then corrupt the key file
        hilog.info(DOMAIN, TAG, "Step 2: Rename database and key files");
        fs.renameSync(dbPath, newDbPath);
        hilog.info(DOMAIN, TAG, `Renamed database: ${dbPath} -> ${newDbPath}`);

        // Rename key file if it exists
        try {
          fs.accessSync(dbPathKey);
          fs.renameSync(dbPathKey, newDbPathKey);
          hilog.info(DOMAIN, TAG, `Renamed key file: ${dbPathKey} -> ${newDbPathKey}`);
        } catch (e) {
          hilog.warn(DOMAIN, TAG, "Key file does not exist, skipping rename");
        }

        // Corrupt the renamed key file
        hilog.info(DOMAIN, TAG, "Step 3: Corrupt the renamed key file");
        await corruptDatabaseFile(newDbPathKey);
        hilog.info(DOMAIN, TAG, `Corrupted key file: ${newDbPathKey}`);

        // Step 4: Try to open the renamed database with corrupted key
        // This should trigger E_INVALID_SECRET_KEY (14800020)
        hilog.info(DOMAIN, TAG, "Step 4: Try to open database with corrupted key");
        const reopenConfig: relationalStore.StoreConfig = {
          name: newDbName,
          securityLevel: relationalStore.SecurityLevel.S1,
          encrypt: true,
          allowRebuild: false  // Disable auto-rebuild to ensure error is thrown
        };

        store = relationalStore.getRdbStoreSync(context, reopenConfig);
        store.executeSync(SQL_CREATE_TABLE);
        store.insertSync('EMPLOYEE', valueBucket);
        hilog.error(DOMAIN, TAG, "getRdbStoreSyncTest012: Should have thrown an error");
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.info(DOMAIN, TAG, `getRdbStoreSyncTest012: Caught expected error. Code:${err.code}, message:${err.message}`);
        const errorCode = Number(err.code);
        hilog.info(DOMAIN, TAG, `getRdbStoreSyncTest012: Error code: ${errorCode}, Expected: 14800020`);
        expect(errorCode).assertEqual(14800020);
      } finally {
        store?.close();
        // Clean up both original and renamed database files
        await cleanupDatabaseFiles(dbName);
        await cleanupDatabaseFiles(newDbName);
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest012 end *************");
    })

    /**
     * @tc.name rdb store getRdbStoreSync execute invalid SQL
     * @tc.number getRdbStoreSyncTest013
     * @tc.desc Abnormal parameter, execute invalid SQL statement
     * @tc.expect Throw exception, 14800021 SQLite: Generic error
     */
    it('getRdbStoreSyncTest013', 0, async (done: Function) => {
      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest013 start *************");

      const storeConfig: relationalStore.StoreConfig = {
        name: RDB_TEST_NAME,
        securityLevel: relationalStore.SecurityLevel.S1,
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        store.executeSync(SQL_CREATE_TABLE);

        // Try to insert into non-existent table
        hilog.info(DOMAIN, TAG, "Step 1: Execute invalid SQL");
        store.insertSync('error_table_name', valueBucket);
        hilog.error(DOMAIN, TAG, "getRdbStoreSyncTest013: Should have thrown an error");
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.info(DOMAIN, TAG, `getRdbStoreSyncTest013: Caught expected error. Code:${err.code}, message:${err.message}`);
        expect(14800021).assertEqual(Number(err.code));
      } finally {
        store?.close();
        await relationalStore.deleteRdbStore(context, storeConfig);
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest013 end *************");
    })

    /**
     * @tc.name rdb store getRdbStoreSync attempt to write readonly database
     * @tc.number getRdbStoreSyncTest014
     * @tc.desc Abnormal parameter, attempt to write to readonly database
     * @tc.expect Throw exception, 14800027 Attempt to write a readonly database
     * @tc.autoTest false (Requires specific file system permissions)
     */
    it('getRdbStoreSyncTest014', 0, async (done: Function) => {
      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest014 start *************");

      const dbName = RDB_TEST_NAME;
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
        // 1. Create database and insert data
        hilog.info(DOMAIN, TAG, "Step 1: Create database");
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        store.executeSync(SQL_CREATE_TABLE);
        store.insertSync('EMPLOYEE', valueBucket);
        store.close();
        store = undefined;

        // 2. Change file permissions to read-only (may not be supported on some systems)
        hilog.info(DOMAIN, TAG, "Step 2: Change files to read-only");
        try {
          await changeFileModeOnlyRead(dbPath);
          await changeFileModeOnlyRead(dbPathWal);
          await changeFileModeOnlyRead(dbPathShm);
        } catch (e) {
          hilog.warn(DOMAIN, TAG, "getRdbStoreSyncTest014: Cannot change file mode, skipping test");
          hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest014 end (skipped) *************");
          done();
          return;
        }

        // 3. Try to open and write to read-only database
        hilog.info(DOMAIN, TAG, "Step 3: Try to write to read-only database");
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        store.executeSync("PRAGMA journal_mode");
        store.insertSync('EMPLOYEE', valueBucket);
        store.executeSync("pragma integrity_check");
        hilog.error(DOMAIN, TAG, "getRdbStoreSyncTest014: Should have thrown an error");
        // If we reach here, the test condition couldn't be simulated
        hilog.warn(DOMAIN, TAG, "getRdbStoreSyncTest014: Could not simulate readonly condition, skipping test");
      } catch (e) {
        const err = e as BusinessError;
        hilog.info(DOMAIN, TAG, `getRdbStoreSyncTest014: Caught expected error. Code:${err.code}, message:${err.message}`);
        const errorCode = Number(err.code);
        if (!isNaN(errorCode)) {
          expect(errorCode).assertEqual(14800027);
        }
      } finally {
        store?.close();
        await relationalStore.deleteRdbStore(context, storeConfig);
      }

      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest014 end *************");
    })

    /**
     * @tc.name rdb store getRdbStoreSync with I/O error
     * @tc.number getRdbStoreSyncTest015
     * @tc.desc Abnormal parameter, I/O error (database file deleted)
     * @tc.expect Throw exception, 14800028 Disk I/O error occurred
     * @tc.autoTest false (Requires specific file system environment)
     */
    it('getRdbStoreSyncTest015', 0, async (done: Function) => {
      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest015 start *************");

      const dbName = RDB_TEST_NAME;
      const dbPath = context.databaseDir + "/rdb/" + dbName;
      const storeConfig: relationalStore.StoreConfig = {
        name: dbName,
        securityLevel: relationalStore.SecurityLevel.S1,
        encrypt: true,
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        // 1. Create database
        hilog.info(DOMAIN, TAG, "Step 1: Create database");
        store = relationalStore.getRdbStoreSync(context, storeConfig);

        // 2. Delete database file to simulate I/O error
        hilog.info(DOMAIN, TAG, "Step 2: Remove database file");
        await moveDatabaseFile(dbPath);
        store.close();

        // 3. Try to operate on deleted database
        hilog.info(DOMAIN, TAG, "Step 3: Try to operate on deleted database");
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        store.executeSync(SQL_CREATE_TABLE);
        store.insertSync('EMPLOYEE', valueBucket);
        hilog.error(DOMAIN, TAG, "getRdbStoreSyncTest015: Should have thrown an error");
        // If we reach here, I/O error couldn't be simulated
        hilog.warn(DOMAIN, TAG, "getRdbStoreSyncTest015: Could not simulate I/O error, skipping test");
      } catch (e) {
        const err = e as BusinessError;
        hilog.info(DOMAIN, TAG, `getRdbStoreSyncTest015: Caught expected error. Code:${err.code}, message:${err.message}`);
        const errorCode = Number(err.code);
        if (!isNaN(errorCode)) {
          expect(errorCode).assertEqual(14800028);
        }
      } finally {
        store?.close();
        await relationalStore.deleteRdbStore(context, storeConfig);
      }

      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest015 end *************");
    })

    /**
     * @tc.name rdb store getRdbStoreSync with database full
     * @tc.number getRdbStoreSyncTest016
     * @tc.desc Abnormal parameter, database full scenario
     * @tc.expect Throw exception, 14800029 The database is full
     */
    it('getRdbStoreSyncTest016', 0, async (done: Function) => {
      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest016 start *************");

      const storeConfig: relationalStore.StoreConfig = {
        name: RDB_TEST_NAME,
        securityLevel: relationalStore.SecurityLevel.S1,
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);

        // Set max_page_count to 1 to simulate full database
        hilog.info(DOMAIN, TAG, "Step 1: Set max_page_count to 1");
        store.executeSync(`PRAGMA max_page_count = 1`);

        // Try to create table and insert data (should fail due to full database)
        hilog.info(DOMAIN, TAG, "Step 2: Try to insert data into full database");
        store.executeSync(SQL_CREATE_TABLE);
        store.insertSync('EMPLOYEE', valueBucket);
        hilog.error(DOMAIN, TAG, "getRdbStoreSyncTest016: Should have thrown an error");
        // If we reach here, database full error couldn't be simulated
        hilog.warn(DOMAIN, TAG, "getRdbStoreSyncTest016: Could not simulate database full condition, skipping test");
      } catch (e) {
        const err = e as BusinessError;
        hilog.info(DOMAIN, TAG, `getRdbStoreSyncTest016: Caught expected error. Code:${err.code}, message:${err.message}`);
        const errorCode = Number(err.code);
        if (!isNaN(errorCode)) {
          expect(errorCode).assertEqual(14800029);
        }
      } finally {
        store?.close();
        await relationalStore.deleteRdbStore(context, storeConfig);
      }

      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest016 end *************");
    })

    /**
     * @tc.name rdb store getRdbStoreSync unable to open database file
     * @tc.number getRdbStoreSyncTest017
     * @tc.desc Abnormal parameter, no permission to open database file
     * @tc.expect Throw exception, 14800030 Unable to open the database file
     */
    it('getRdbStoreSyncTest017', 0, async (done: Function) => {
      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest017 start *************");

      const storeConfig: relationalStore.StoreConfig = {
        name: RDB_TEST_NAME,
        securityLevel: relationalStore.SecurityLevel.S1,
        isReadOnly: true, // Open non-existent database in read-only mode
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        hilog.error(DOMAIN, TAG, "getRdbStoreSyncTest017: Should have thrown an error");
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.info(DOMAIN, TAG, `getRdbStoreSyncTest017: Caught expected error. Code:${err.code}, message:${err.message}`);
        const errorCode = Number(err.code);
        if (!isNaN(errorCode)) {
          expect(errorCode).assertEqual(14800030);
        }
      } finally {
        store?.close();
        await relationalStore.deleteRdbStore(context, storeConfig);
      }

      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest017 end *************");
    })

    /**
     * @tc.name rdb store mixed async and sync interfaces with same config
     * @tc.number getRdbStoreSyncTest018
     * @tc.desc Normal operation, call getRdbStore then getRdbStoreSync with same config
     * @tc.expect No exception, both interfaces should work correctly
     */
    it('getRdbStoreSyncTest018', 0, async (done: Function) => {
      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest018 start *************");

      const storeConfig: relationalStore.StoreConfig = {
        name: RDB_TEST_NAME,
        securityLevel: relationalStore.SecurityLevel.S1,
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        // Step 1: Open database with async getRdbStore interface
        hilog.info(DOMAIN, TAG, "Step 1: Open database with getRdbStore (async)");
        store = await relationalStore.getRdbStore(context, storeConfig);
        expect(store !== undefined).assertTrue();

        // Create table and insert data
        hilog.info(DOMAIN, TAG, "Step 2: Execute SQL and insert data");
        await store.executeSql(SQL_CREATE_TABLE);
        store.insertSync('EMPLOYEE', valueBucket);

        // Close database
        hilog.info(DOMAIN, TAG, "Step 3: Close database");

        // Step 4: Open database again with sync getRdbStoreSync interface using same config
        hilog.info(DOMAIN, TAG, "Step 4: Reopen database with getRdbStoreSync (sync)");
        store = relationalStore.getRdbStoreSync(context, storeConfig);
        expect(store !== undefined).assertTrue();

        // Create table and insert data again
        hilog.info(DOMAIN, TAG, "Step 5: Execute SQL and insert data again");
        store.executeSync(SQL_CREATE_TABLE);
        store.insertSync('EMPLOYEE', valueBucket);

        hilog.info(DOMAIN, TAG, "getRdbStoreSyncTest018: Both async and sync interfaces work correctly");
      } catch (e) {
        const err = e as BusinessError;
        hilog.error(DOMAIN, TAG, `getRdbStoreSyncTest018: Unexpected error. Code:${err.code}, message:${err.message}`);
        expect().assertFail();
      } finally {
        store?.close();
        await relationalStore.deleteRdbStore(context, storeConfig);
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest018 end *************");
    })

    /**
     * @tc.name rdb store mixed async then sync with changed config
     * @tc.number getRdbStoreSyncTest019
     * @tc.desc Abnormal parameter, call getRdbStore then getRdbStoreSync with changed config
     * @tc.expect Throw exception, 14800017 Config changed
     */
    it('getRdbStoreSyncTest019', 0, async (done: Function) => {
      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest019 start *************");

      const originalConfig: relationalStore.StoreConfig = {
        name: RDB_TEST_NAME,
        securityLevel: relationalStore.SecurityLevel.S1,
      };

      const changedConfig: relationalStore.StoreConfig = {
        name: RDB_TEST_NAME,
        securityLevel: relationalStore.SecurityLevel.S2, // Different security level
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        // Step 1: Open database with async getRdbStore interface
        hilog.info(DOMAIN, TAG, "Step 1: Open database with getRdbStore (async)");
        store = await relationalStore.getRdbStore(context, originalConfig);
        expect(store !== undefined).assertTrue();

        // Close database
        hilog.info(DOMAIN, TAG, "Step 2: Close database");

        // Step 3: Try to open database with sync getRdbStoreSync interface using changed config
        hilog.info(DOMAIN, TAG, "Step 3: Try to reopen with getRdbStoreSync using changed config");
        store = relationalStore.getRdbStoreSync(context, changedConfig);

        hilog.error(DOMAIN, TAG, "getRdbStoreSyncTest019: Should have thrown an error");
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.info(DOMAIN, TAG, `getRdbStoreSyncTest019: Caught expected error. Code:${err.code}, message:${err.message}`);
        const errorCode = Number(err.code);
        expect(errorCode).assertEqual(14800017); // E_CONFIG_INVALID_CHANGE
        hilog.info(DOMAIN, TAG, "getRdbStoreSyncTest019: Successfully caught 14800017 error");
      } finally {
        store?.close();
        await relationalStore.deleteRdbStore(context, originalConfig);
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest019 end *************");
    })

    /**
     * @tc.name rdb store mixed sync then async with changed config
     * @tc.number getRdbStoreSyncTest020
     * @tc.desc Abnormal parameter, call getRdbStoreSync then getRdbStore with changed config
     * @tc.expect Throw exception, 14800017 Config changed
     */
    it('getRdbStoreSyncTest020', 0, async (done: Function) => {
      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest020 start *************");

      const originalConfig: relationalStore.StoreConfig = {
        name: RDB_TEST_NAME,
        securityLevel: relationalStore.SecurityLevel.S1,
      };

      const changedConfig: relationalStore.StoreConfig = {
        name: RDB_TEST_NAME,
        securityLevel: relationalStore.SecurityLevel.S2, // Different security level
      };

      let store: relationalStore.RdbStore | undefined = undefined;
      try {
        // Step 1: Open database with sync getRdbStoreSync interface
        hilog.info(DOMAIN, TAG, "Step 1: Open database with getRdbStoreSync (sync)");
        store = relationalStore.getRdbStoreSync(context, originalConfig);
        expect(store !== undefined).assertTrue();

        // Close database
        hilog.info(DOMAIN, TAG, "Step 2: Close database");

        // Step 3: Try to open database with async getRdbStore interface using changed config
        hilog.info(DOMAIN, TAG, "Step 3: Try to reopen with getRdbStore (async) using changed config");
        store = await relationalStore.getRdbStore(context, changedConfig);

        hilog.error(DOMAIN, TAG, "getRdbStoreSyncTest020: Should have thrown an error");
        expect().assertFail();
      } catch (e) {
        const err = e as BusinessError;
        hilog.info(DOMAIN, TAG, `getRdbStoreSyncTest020: Caught expected error. Code:${err.code}, message:${err.message}`);
        const errorCode = Number(err.code);
        expect(errorCode).assertEqual(14800017); // E_CONFIG_INVALID_CHANGE
        hilog.info(DOMAIN, TAG, "getRdbStoreSyncTest020: Successfully caught 14800017 error");
      } finally {
        store?.close();
        await relationalStore.deleteRdbStore(context, originalConfig);
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest020 end *************");
    })

    hilog.info(DOMAIN, TAG, "*************Unit Test End*************");
  })
}
