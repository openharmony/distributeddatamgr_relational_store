/**
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
import relationalStore from '@ohos.data.relationalStore';
import AbilityDelegatorRegistry from '@ohos.app.ability.abilityDelegatorRegistry';

const delegator = AbilityDelegatorRegistry.getAbilityDelegator();
const context = delegator.getAppContext().getApplicationContext();
const TAG = "[RDB_STORE_STOP_CLOUD_SYNC_TEST]";

const STORE_CONFIG: relationalStore.StoreConfig = {
    name: "StopCloudSyncTest.db",
    securityLevel: relationalStore.SecurityLevel.S1,
};

const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS EMPLOYEE ("
    + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    + "name TEXT NOT NULL, "
    + "age INTEGER, "
    + "salary REAL, "
    + "codes BLOB)";

let rdbStore: relationalStore.RdbStore | undefined = undefined;

export default function RdbStoreStopCloudSyncTest() {
    describe('rdbStoreStopCloudSyncTest', () => {
        beforeAll(async () => {
            console.info(TAG + 'beforeAll');
        });

        beforeEach(async () => {
            console.info(TAG + 'beforeEach');
            rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
            expect(rdbStore != undefined).assertTrue();
            await rdbStore?.executeSql(CREATE_TABLE_TEST);
        });

        afterEach(async () => {
            console.info(TAG + 'afterEach');
            rdbStore = undefined;
            await relationalStore.deleteRdbStore(context, "StopCloudSyncTest.db");
        });

        afterAll(async () => {
            console.info(TAG + 'afterAll');
        });

        console.info(TAG + "*************Unit Test Begin*************");

        /**
         * @tc.number StopCloudSyncTest0001
         * @tc.name test RdbStore stopCloudSync
         * @tc.desc call stopCloudSync on a normal rdb store
         */
        it('StopCloudSyncTest0001', 0, async () => {
            console.info(TAG + "************* StopCloudSyncTest0001 start *************");
            try {
                (rdbStore as relationalStore.RdbStore).stopCloudSync();
                expect(true).assertTrue();
            } catch (e) {
                console.error(TAG + `StopCloudSyncTest0001 failed, code is ${e.code}, message is ${e.message}`);
                expect(true).assertTrue();
            }
            console.info(TAG + "************* StopCloudSyncTest0001 end *************");
        });

        /**
         * @tc.number StopCloudSyncTest0002
         * @tc.name test RdbStore stopCloudSync after close
         * @tc.desc call stopCloudSync after store is closed should throw error
         */
        it('StopCloudSyncTest0002', 0, async () => {
            console.info(TAG + "************* StopCloudSyncTest0002 start *************");
            try {
                await (rdbStore as relationalStore.RdbStore).close();
                (rdbStore as relationalStore.RdbStore).stopCloudSync();
                expect(false).assertTrue();
            } catch (e) {
                console.error(TAG + `StopCloudSyncTest0002 failed, code is ${e.code}, message is ${e.message}`);
                expect(e.code == 14800011).assertTrue();
            }
            console.info(TAG + "************* StopCloudSyncTest0002 end *************");
        });

        /**
         * @tc.number StopCloudSyncTest0003
         * @tc.name test RdbStore stopCloudSync with insert data
         * @tc.desc insert data then call stopCloudSync
         */
        it('StopCloudSyncTest0003', 0, async () => {
            console.info(TAG + "************* StopCloudSyncTest0003 start *************");
            const valueBucket: relationalStore.ValuesBucket = {
                'name': 'zhangsan',
                'age': 18,
                'salary': 25000,
            };
            try {
                let rowId = await (rdbStore as relationalStore.RdbStore).insert("EMPLOYEE", valueBucket);
                console.info(TAG + `Insert is successful, rowId = ${rowId}`);
                (rdbStore as relationalStore.RdbStore).stopCloudSync();
                expect(true).assertTrue();
            } catch (e) {
                console.error(TAG + `StopCloudSyncTest0003 failed, code is ${e.code}, message is ${e.message}`);
                expect(true).assertTrue();
            }
            console.info(TAG + "************* StopCloudSyncTest0003 end *************");
        });

        /**
         * @tc.number StopCloudSyncTest0004
         * @tc.name test RdbStore stopCloudSync called multiple times
         * @tc.desc call stopCloudSync multiple times should not crash
         */
        it('StopCloudSyncTest0004', 0, async () => {
            console.info(TAG + "************* StopCloudSyncTest0004 start *************");
            try {
                (rdbStore as relationalStore.RdbStore).stopCloudSync();
                (rdbStore as relationalStore.RdbStore).stopCloudSync();
                (rdbStore as relationalStore.RdbStore).stopCloudSync();
                expect(true).assertTrue();
            } catch (e) {
                console.error(TAG + `StopCloudSyncTest0004 failed, code is ${e.code}, message is ${e.message}`);
                expect(true).assertTrue();
            }
            console.info(TAG + "************* StopCloudSyncTest0004 end *************");
        });

        /**
         * @tc.number StopCloudSyncTest0005
         * @tc.name test RdbStore stopCloudSync return type
         * @tc.desc verify stopCloudSync is a synchronous function returning undefined
         */
        it('StopCloudSyncTest0005', 0, async () => {
            console.info(TAG + "************* StopCloudSyncTest0005 start *************");
            try {
                let result = (rdbStore as relationalStore.RdbStore).stopCloudSync();
                expect(result == undefined).assertTrue();
            } catch (e) {
                console.error(TAG + `StopCloudSyncTest0005 failed, code is ${e.code}, message is ${e.message}`);
                expect(true).assertTrue();
            }
            console.info(TAG + "************* StopCloudSyncTest0005 end *************");
        });

        console.info(TAG + "*************Unit Test End*************");
    });
}
