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

import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect, Level, Size, TestType } from "@ohos/hypium";
import relationalStore from '@ohos.data.relationalStore';
import common from "@ohos.app.ability.common"
import contextConstant from '@ohos.app.ability.contextConstant';
let context: common.UIAbilityContext

const TAG = "[RDB_GROUPID_TEST]";
const CREATE_TABLE_TEST = "CREATE TABLE IF NOT EXISTS test ("
  + "id INTEGER PRIMARY KEY AUTOINCREMENT, "
  + "name TEXT NOT NULL, "
  + "age INTEGER, "
  + "salary REAL, "
  + "blobType BLOB)";

async function crudTest(store:relationalStore.RdbStore):Promise<void>
{
  await store?.executeSql(CREATE_TABLE_TEST);
  let values:relationalStore.ValuesBucket = {
    name:"zhangsan",
    age:20,
    salary:1.5
  }
  let insertNum:number = await store?.insert("test", values) as number;
  expect(insertNum).assertEqual(1);
  let pre:relationalStore.RdbPredicates = new relationalStore.RdbPredicates("test");
  let resultSet:relationalStore.ResultSet = await store?.query(pre) as relationalStore.ResultSet;
  expect(resultSet.rowCount).assertEqual(1);
  expect(resultSet.goToFirstRow()).assertEqual(true);
  let row:relationalStore.ValuesBucket = resultSet.getRow();
  expect(row.name).assertEqual("zhangsan");
  resultSet.close();

  values.name = "lisi";
  pre.equalTo("name", "zhangsan");
  let updateNum:number = await store?.update(values, pre) as number;
  expect(updateNum).assertEqual(1);
  let pre1:relationalStore.RdbPredicates = new relationalStore.RdbPredicates("test");
  resultSet = await store?.query(pre1) as relationalStore.ResultSet;
  expect(resultSet.goToFirstRow()).assertEqual(true);
  row = resultSet.getRow();
  expect(row.name).assertEqual("lisi");
  resultSet.close();

  pre1.equalTo("name", "lisi");
  let deleteNum:number = await store?.delete(pre1) as number;
  expect(deleteNum).assertEqual(1);
  resultSet = await store?.query(pre) as relationalStore.ResultSet;
  expect(resultSet.rowCount).assertEqual(0);
  resultSet.close();
}

export default function RelationalStoreDataGroupId() {
  describe('relationalStoreDataGroupId', () => {
    beforeAll(() => {
      console.info(TAG + 'beforeAll')
      context = globalThis.abilityContext;
    })

    beforeEach(() => {
      console.info(TAG + 'beforeEach')
    })

    afterEach(() => {
      console.info(TAG + 'afterEach')
    })

    afterAll(async () => {
      console.info(TAG + 'afterAll')
    })

    console.log(TAG + "*************Unit Test Begin*************");

    /**
     * @tc.number SUB_DistributedData_RelationalStore_SDK_GetRdbStoreJsAPITest_0100
     * @tc.name relationalStore dataGroupId null test
     * @tc.desc relationalStore getRdbStore dataGroupId null test
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('SUB_DDM_RelationalStore_DataGroupId_0100', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL0, async () => {
      const STORE_CONFIG: relationalStore.StoreConfig = {
        name: "RdbTest.db",
        securityLevel: relationalStore.SecurityLevel.S1,
        dataGroupId: null,
      };
      try {
        let rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
        console.info(TAG, `Get RdbStore successfully.`);
        expect(rdbStore != undefined).assertTrue();
        await relationalStore.deleteRdbStore(context, STORE_CONFIG);
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code},message is ${errInfo.message}`);
        expect().assertFail();
      }
    })

    /**
     * @tc.number SUB_DistributedData_RelationalStore_SDK_GetRdbStoreJsAPITest_0200
     * @tc.name relationalStore dataGroupId undefined callback test
     * @tc.desc relationalStore getRdbStore dataGroupId undefined test
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('SUB_DDM_RelationalStore_DataGroupId_0200', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL0, async () => {
      const STORE_CONFIG: relationalStore.StoreConfig = {
        name: "RdbTest.db",
        securityLevel: relationalStore.SecurityLevel.S1,
        dataGroupId: undefined, 
      };
      try {
        let rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
        console.info(TAG, `Get RdbStore successfully.`);
        expect(rdbStore != undefined).assertTrue();
        await relationalStore.deleteRdbStore(context, STORE_CONFIG);
      } catch (errInfo) {
        expect().assertFail();
      }
    })


    /**
     * @tc.number SUB_DistributedData_RelationalStore_SDK_GetRdbStoreJsAPITest_0300
     * @tc.name relationalStore dataGroupId callback test
     * @tc.desc relationalStore getRdbStore dataGroupId test
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('SUB_DDM_RelationalStore_DataGroupId_0300', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL0, async () => {
      const STORE_CONFIG: relationalStore.StoreConfig = {
        name: "RdbTest.db",
        securityLevel: relationalStore.SecurityLevel.S1,
        dataGroupId: '112233',
      };
      try {
        await relationalStore.getRdbStore(context, STORE_CONFIG);
        console.info(TAG, `Get RdbStore successfully.`);
        expect().assertFail();
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code},message is ${errInfo.message}`);
        expect(errInfo.code == 14801002).assertTrue();
      }
    })

    /**
     * @tc.number SUB_DistributedData_RelationalStore_SDK_GetRdbStoreJsAPITest_0400
     * @tc.name relationalStore dataGroupId callback test
     * @tc.desc relationalStore deleteRdbStore dataGroupId test
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('SUB_DDM_RelationalStore_DataGroupId_0400', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL0, async () => {
      const STORE_CONFIG: relationalStore.StoreConfig = {
        name: "RdbTest.db",
        securityLevel: relationalStore.SecurityLevel.S1,
        dataGroupId: '123456',
      };
      try {
        let rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
        console.info(TAG, `Get RdbStore successfully.`);
        expect(rdbStore != undefined).assertTrue();
        await relationalStore.deleteRdbStore(context, STORE_CONFIG);
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code},message is ${errInfo.message}`);
        expect().assertFail();
      }
    })

    /**
     * @tc.number SUB_DistributedData_RelationalStore_SDK_GetRdbStoreJsAPITest_0400
     * @tc.name relationalStore dataGroupId callback test
     * @tc.desc relationalStore deleteRdbStore dataGroupId test
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('SUB_DDM_RelationalStore_DataGroupId_0400', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL0, async () => {
      const STORE_CONFIG: relationalStore.StoreConfig = {
        name: "RdbTest.db",
        securityLevel: relationalStore.SecurityLevel.S1,
        dataGroupId: '123456',
      };
      try {
        let rdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
        console.info(TAG, `Get RdbStore successfully.`);
        expect(rdbStore != undefined).assertTrue();
        await relationalStore.deleteRdbStore(context, STORE_CONFIG);
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code},message is ${errInfo.message}`);
        expect().assertFail();
      }
    })

    /**
     * @tc.number SUB_DistributedData_RelationalStore_SDK_GetRdbStoreJsAPITest_0500
     * @tc.name relationalStore dataGroupId el3 test
     * @tc.desc relationalStore deleteRdbStore dataGroupId test
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('SUB_DDM_RelationalStore_DataGroupId_0500', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL0, async () => {
      const STORE_CONFIG: relationalStore.StoreConfig = {
        name: "RdbTest.db",
        securityLevel: relationalStore.SecurityLevel.S1,
        dataGroupId: '123456',
      };
      let contextEl3:Context = context.createAreaModeContext(contextConstant.AreaMode.EL3);
      let groupDir:string = await contextEl3.getGroupDir("123456");
      console.info(TAG, "DataGroupId groupDir:" + groupDir);
      try {
        let store:relationalStore.RdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
        await crudTest(store);
        await relationalStore.deleteRdbStore(context, STORE_CONFIG);
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code},message is ${errInfo.message}`);
        expect().assertFail();
      }
    })

    /**
     * @tc.number SUB_DistributedData_RelationalStore_SDK_GetRdbStoreJsAPITest_0600
     * @tc.name relationalStore dataGroupId el4 test
     * @tc.desc relationalStore deleteRdbStore dataGroupId test
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('SUB_DDM_RelationalStore_DataGroupId_0600', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL0, async () => {
      const STORE_CONFIG: relationalStore.StoreConfig = {
        name: "RdbTest.db",
        securityLevel: relationalStore.SecurityLevel.S1,
        dataGroupId: '123456',
      };
      let contextEl4:Context = context.createAreaModeContext(contextConstant.AreaMode.EL4);
      let groupDir:string = await contextEl4.getGroupDir("123456");
      console.info(TAG, "DataGroupId groupDir:" + groupDir);
      try {
        let store:relationalStore.RdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
        await crudTest(store);
        await relationalStore.deleteRdbStore(context, STORE_CONFIG);
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code},message is ${errInfo.message}`);
        expect().assertFail();
      }
    })

    /**
     * @tc.number SUB_DistributedData_RelationalStore_SDK_GetRdbStoreJsAPITest_0700
     * @tc.name relationalStore dataGroupId el5 test
     * @tc.desc relationalStore deleteRdbStore dataGroupId test
     * @tc.size MediumTest
     * @tc.type Function
     * @tc.level Level 0
     */
    it('SUB_DDM_RelationalStore_DataGroupId_0700', TestType.FUNCTION | Size.MEDIUMTEST | Level.LEVEL0, async () => {
      const STORE_CONFIG: relationalStore.StoreConfig = {
        name: "RdbTest.db",
        securityLevel: relationalStore.SecurityLevel.S1,
        dataGroupId: '123456',
      };
      let contextEl5:Context = context.createAreaModeContext(contextConstant.AreaMode.EL5);
      let groupDir:string = await contextEl5.getGroupDir("123456");
      console.info(TAG, "DataGroupId groupDir:" + groupDir);
      try {
        let store:relationalStore.RdbStore = await relationalStore.getRdbStore(context, STORE_CONFIG);
        await crudTest(store);
        await relationalStore.deleteRdbStore(context, STORE_CONFIG);
      } catch (errInfo) {
        console.error(TAG, `failed, code is ${errInfo.code},message is ${errInfo.message}`);
        expect().assertFail();
      }
    })

    console.info(TAG + "*************Unit Test End*************");
  })
}