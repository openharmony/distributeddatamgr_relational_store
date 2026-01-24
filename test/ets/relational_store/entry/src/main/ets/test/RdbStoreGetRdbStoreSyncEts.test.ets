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
import { BusinessError } from '@kit.BasicServicesKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { relationalStore } from '@kit.ArkData';
import AbilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';
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
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest006 end   *************");
    })


    /**
     * @tc.name rdb store getRdbStoreSync test
     * @tc.number getRdbStoreSyncTest007
     * @tc.desc Throw error Code:14800001, message:Invalid args.Parameter error. The customDir must be a relative directory.
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
      }
      done();

      hilog.info(DOMAIN, TAG, "************* getRdbStoreSyncTest007 end   *************");
    })

    hilog.info(DOMAIN, TAG, "*************Unit Test End*************");
  })
}







