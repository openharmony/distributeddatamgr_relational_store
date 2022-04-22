
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
import data_rdb from '@ohos.data.rdb'
import ability_featureAbility from '@ohos.ability.featureAbility';
import fileio from '@ohos.fileio'

const TAG = "[RDB_JSKITS_TEST]"
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test (" + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
    + "name TEXT NOT NULL, " + "age INTEGER, " + "salary REAL, " + "blobType BLOB)"
const DATABASE_BACKUP_NAME = "backup001.db"
const DATABASE_RESTORE_NAME = "restore001.db"
const DATABASE_DIR = "/data/storage/el2/database/entry/db/"
const STORE_CONFIG = {
    name: "BackupResotreTest.db",
}
var context = undefined
var rdbStore = undefined
describe('rdbStoreBackupRestoreWithFAContextTest', function () {
    beforeAll(async function () {
        console.info(TAG + 'beforeAll')
        context = ability_featureAbility.getContext()
        rdbStore = await data_rdb.getRdbStore(context, STORE_CONFIG, 1)
        await rdbStore.executeSql(CREATE_TABLE_TEST, null)
        var u8 = new Uint8Array([1, 2, 3])
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
    })

    beforeEach(async function () {
        console.info(TAG + 'beforeEach')
    })

    afterEach(async function () {
        console.info(TAG + 'afterEach')
    })

    afterAll(async function () {
        console.info(TAG + 'afterAll')
        rdbStore = null
        await data_rdb.deleteRdbStore(context, STORE_CONFIG.name)
        await data_rdb.deleteRdbStore(context, DATABASE_BACKUP_NAME)
        await data_rdb.deleteRdbStore(context, DATABASE_RESTORE_NAME)
    })

    console.log(TAG + "*************Unit Test Begin*************")
    /**
     * @tc.name RDB BackupRestore test
     * @tc.number SUB_DDM_RDB_JS_RdbBackupRestoreTest_0010
     * @tc.desc RDB BackupRestore test
     */
    it('RdbBackupRestoreTest_0010', 0, async function (done) {
        await console.log(TAG + "************* RdbBackupRestoreTest_0010 start *************")
        let promiseBackup = rdbStore.backup(DATABASE_DIR + DATABASE_BACKUP_NAME)
        promiseBackup.then(async () => {
            try {
                fileio.accessSync(DATABASE_DIR + DATABASE_BACKUP_NAME)
                fileio.accessSync(DATABASE_DIR + STORE_CONFIG.name)
            } catch (err) {
                expect(false).assertTrue()
            }

            try {
                fileio.accessSync(DATABASE_DIR + DATABASE_RESTORE_NAME)
                expect(false).assertTrue()
            } catch (err) {
                expect(true).assertTrue()
            }
        }).catch((err) => {
            expect(false).assertTrue()
        })
        await promiseBackup

        let promiseRestore = rdbStore.restore(DATABASE_DIR + DATABASE_RESTORE_NAME,DATABASE_DIR +  DATABASE_BACKUP_NAME)
        promiseRestore.then(async () => {
            try {
                fileio.accessSync(DATABASE_DIR + DATABASE_RESTORE_NAME)
            } catch (err) {
                expect(false).assertTrue()
            }

            try {
                fileio.accessSync(DATABASE_DIR + DATABASE_BACKUP_NAME)
                expect(false).assertTrue()
            } catch (err) {
                expect(true).assertTrue()
            }

            try {
                fileio.accessSync(DATABASE_DIR + STORE_CONFIG.name)
                expect(false).assertTrue()
            } catch (err) {
                expect(true).assertTrue()
            }
        }).catch((err) => {
            expect(false).assertTrue()
        })
        await promiseRestore

        let predicates = new data_rdb.RdbPredicates("test")
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

        done()
        await console.log(TAG + "************* RdbBackupRestoreTest_0010 end *************")
    })
    console.log(TAG + "*************Unit Test End*************")
})
