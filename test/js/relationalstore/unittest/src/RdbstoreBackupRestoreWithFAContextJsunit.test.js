/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
import {describe, beforeAll, beforeEach, afterEach, afterAll, it, expect} from 'deccjsunit/index'
import data_relationalStore from '@ohos.data.relationalStore'
import ability_featureAbility from '@ohos.ability.featureAbility'
import fileio from '@ohos.fileio'

const TAG = "[RELATIONAL_STORE_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    + "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)"
const DATABASE_DIR = "/data/storage/el2/database/entry/rdb/"
var rdbStore
var context = ability_featureAbility.getContext()
const STORE_CONFIG = {
    name: "BackupResotreTest.db",
    securityLevel: data_relationalStore.SecurityLevel.S1,
}
const DATABASE_BACKUP_NAME = "Backup.db"

async function CreatRdbStore(STORE_CONFIG) {
    let rdbStore = await data_relationalStore.getRdbStore(context, STORE_CONFIG)
    await rdbStore.executeSql(CREATE_TABLE_TEST, null)
    let u8 = new Uint8Array([1, 2, 3])
    {
        const valueBucket = {
            "name": "zhangsan",
            "age": 18,
            "salary": 100.5,
            "blobType": u8,
        }
        await rdbStore.insert("test", valueBucket)
    }
    {
        const valueBucket = {
            "name": "lisi",
            "age": 28,
            "salary": 100.5,
            "blobType": u8,
        }
        await rdbStore.insert("test", valueBucket)
    }
    {
        const valueBucket = {
            "name": "wangwu",
            "age": 38,
            "salary": 90.0,
            "blobType": u8,
        }
        await rdbStore.insert("test", valueBucket)
    }
    return rdbStore
}

async function BackupTest(backupName) {
    try {
        let promiseRestore = rdbStore.backup(backupName)
        promiseRestore.then(() => {
            expect(false).assertTrue()
        }).catch((err) => {
            expect(true).assertTrue()
        })
        await promiseRestore
    } catch {
        expect(true).assertTrue()
    }

    rdbStore = null
}

async function RestoreTest(restoreName) {
    try {
        let promiseRestore = rdbStore.restore(restoreName)
        promiseRestore.then(() => {
            expect(false).assertTrue()
        }).catch((err) => {
            expect(true).assertTrue()
        })
        await promiseRestore
    } catch {
        expect(true).assertTrue()
    }

    rdbStore = null
}

describe('rdbStoreBackupRestoreWithFAContextTest', function () {
        beforeAll(async function () {
            console.info(TAG + 'beforeAll')
        })

        beforeEach(async function () {
            console.info(TAG + 'beforeEach')
            rdbStore = await CreatRdbStore(STORE_CONFIG)
        })

        afterEach(async function () {
            console.info(TAG + 'afterEach')
            await data_relationalStore.deleteRdbStore(context, STORE_CONFIG.name)
            await data_relationalStore.deleteRdbStore(context, DATABASE_BACKUP_NAME)
        })

        afterAll(async function () {
            console.info(TAG + 'afterAll')
        })

        console.log(TAG + "*************Unit Test Begin*************")

        /**
         * @tc.name RDB Backup Restore test
         * @tc.number SUB_DDM_RDB_JS_RdbBackupRestoreTest_0010
         * @tc.desc RDB backup and restore function test
         */
        it('RdbBackupRestoreTest_0010', 0, async function (done) {
            await console.log(TAG + "************* RdbBackupRestoreTest_0010 start *************")

            // RDB backup function test
            let promiseBackup = rdbStore.backup(DATABASE_BACKUP_NAME)
            promiseBackup.then(() => {
                try {
                    fileio.accessSync(DATABASE_DIR + DATABASE_BACKUP_NAME)
                    fileio.accessSync(DATABASE_DIR + STORE_CONFIG.name)
                } catch (err) {
                    expect(false).assertTrue()
                }
            }).catch((err) => {
                expect(false).assertTrue()
            })
            await promiseBackup

            // RDB restore function test
            let promiseRestore = rdbStore.restore(DATABASE_BACKUP_NAME)
            promiseRestore.then(() => {
                try {
                    fileio.accessSync(DATABASE_DIR + DATABASE_BACKUP_NAME)
                    expect(false).assertTrue()
                } catch (err) {
                    expect(true).assertTrue()
                }

                try {
                    fileio.accessSync(DATABASE_DIR + STORE_CONFIG.name)
                    expect(true).assertTrue()
                } catch (err) {
                    expect(false).assertTrue()
                }
            }).catch((err) => {
                expect(false).assertTrue()
            })
            await promiseRestore

            // RDB after restored, data query test
            let predicates = new data_relationalStore.RdbPredicates("test")
            predicates.equalTo("name", "zhangsan")
            let resultSet = await rdbStore.query(predicates)
            try {
                console.log(TAG + "After restore resultSet query done")
                expect(true).assertEqual(resultSet.goToFirstRow())
                const id = resultSet.getLong(resultSet.getColumnIndex("id"))
                const name = resultSet.getString(resultSet.getColumnIndex("name"))
                const blobType = resultSet.getBlob(resultSet.getColumnIndex("blobType"))
                expect(1).assertEqual(id)
                expect("zhangsan").assertEqual(name)
                expect(1).assertEqual(blobType[0])
            } catch (err) {
                expect(false).assertTrue()
            }
            resultSet = null
            rdbStore = null
            done()
            await console.log(TAG + "************* RdbBackupRestoreTest_0010 end *************")
        })

        /**
         * @tc.name RDB Backup test
         * @tc.number SUB_DDM_RDB_JS_RdbBackupRestoreTest_0020
         * @tc.desc RDB backup function test
         */
        it('RdbBackupRestoreTest_0020', 0, async function (done) {
            await console.log(TAG + "************* RdbBackupRestoreTest_0020 start *************")
            // RDB backup function test, backup file name empty
            BackupTest("")

            // RDB backup function test, backup file name already exists
            BackupTest(STORE_CONFIG.name)

            done()
            await console.log(TAG + "************* RdbBackupRestoreTest_0020 end *************")
        })

        /**
         * @tc.name RDB BackupRestore test
         * @tc.number SUB_DDM_RDB_JS_RdbBackupRestoreTest_0030
         * @tc.desc RDB restore function test
         */
        it('RdbBackupRestoreTest_0030', 0, async function (done) {
            await console.log(TAG + "************* RdbBackupRestoreTest_0030 start *************")
            await rdbStore.backup(DATABASE_BACKUP_NAME)

            // RDB restore function test, backup file name empty
            RestoreTest("")

            // RDB restore function test, backup file is specified to database name
            RestoreTest(STORE_CONFIG.name)

            done()
            await console.log(TAG + "************* RdbBackupRestoreTest_0030 end *************")
        })

        /**
         * @tc.name RDB BackupRestore test
         * @tc.number SUB_DDM_RDB_JS_RdbBackupRestoreTest_0040
         * @tc.desc RDB restore function test
         */
        it('RdbBackupRestoreTest_0040', 0, async function (done) {
            await console.log(TAG + "************* RdbBackupRestoreTest_0040 start *************")
            let dbName = "notExistName.db"

            // RDB restore function test, backup file does not exists
            try {
                fileio.accessSync(DATABASE_DIR + dbName)
                expect(false).assertTrue()
            } catch {
                RestoreTest(dbName)
            }

            done()
            await console.log(TAG + "************* RdbBackupRestoreTest_0040 end *************")
        })

        console.log(TAG + "*************Unit Test End*************")
    }
)
