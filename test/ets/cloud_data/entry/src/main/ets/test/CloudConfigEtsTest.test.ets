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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or impligetProfileByAbilityEmptyAbilityCalled.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// @ts-nocheck
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from "@ohos/hypium"
import cloudData from '@ohos.data.cloudData';
import relationalStore from '@ohos.data.relationalStore';

export default function CloudConfigEtsTest() {
  describe('CloudConfigEtsTest', function () {
    beforeAll(function () {
      console.info('beforeAll called');
    })

    afterAll(function () {
      console.info('afterAll called');
    })

    beforeEach(function () {
      console.info('beforeEach called');
    })

    afterEach(async function () {
      console.info('afterEach called');
    })

    /**
     * @tc.name CloudSync001
     * @tc.desc Test Js Api cloudSync
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync001', 0, async function (done) {
        console.info('CloudSync001');
        function Progress(detail) {
            console.log('CloudSync001 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // cloud config permission denied
            await cloudData.Config.cloudSync("bundleName", "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress);
            expect(false).assertTrue();
            done();
        } catch (e) {
            console.error('CloudSync001 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 202).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync002
     * @tc.desc Test Js Api cloudSync with diff syncMode
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync002', 0, async function (done) {
        console.info('CloudSync002');
        function Progress(detail) {
            console.log('CloudSync002 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // cloud config permission denied
            await cloudData.Config.cloudSync("bundleName", "storeId", relationalStore.SyncMode.SYNC_MODE_NATIVE_FIRST, Progress);
            expect(false).assertTrue();
            done();
        } catch (e) {
            console.error('CloudSync002 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 202).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync003
     * @tc.desc Test Js Api cloudSync with diff syncMode
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync003', 0, async function (done) {
        console.info('CloudSync003');
        function Progress(detail) {
            console.log('CloudSync003 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // cloud config permission denied
            await cloudData.Config.cloudSync("bundleName", "storeId", relationalStore.SyncMode.SYNC_MODE_CLOUD_FIRST, Progress);
            expect(false).assertTrue();
            done();
        } catch (e) {
            console.error('CloudSync003 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 202).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync004
     * @tc.desc Test Js Api cloudSync, invalid param, no progress
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync004', 0, async function (done) {
        console.info('CloudSync004');
        try {
            // Parameter error. The number of parameters is incorrect.
            await cloudData.Config.cloudSync("bundleName", "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST);
            expect(false).assertTrue();
            done();
        } catch (e) {
            console.error('CloudSync004 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync005
     * @tc.desc Test Js Api cloudSync, invalid param, empty storeId
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync005', 0, async function (done) {
        console.info('CloudSync005');
        function Progress(detail) {
            console.log('CloudSync005 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. storeId can not empty.
            await cloudData.Config.cloudSync("bundleName", "", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress);
            expect(false).assertTrue();
            done();
        } catch (e) {
            console.error('CloudSync005 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 14800001).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync006
     * @tc.desc Test Js Api cloudSync, invalid param, storeId is null
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync006', 0, async function (done) {
        console.info('CloudSync006');
        function Progress(detail) {
            console.log('CloudSync006 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. The type of storeId must be string and not empty.
            await cloudData.Config.cloudSync("bundleName", null, relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress);
            expect(false).assertTrue();
            done();
        } catch (e) {
            console.error('CloudSync006 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync007
     * @tc.desc Test Js Api cloudSync, invalid param, storeId is undefined
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync007', 0, async function (done) {
        console.info('CloudSync007');
        function Progress(detail) {
            console.log('CloudSync007 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. The type of storeId must be string and not empty.
            await cloudData.Config.cloudSync("bundleName", undefined, relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress);
            expect(false).assertTrue();
            done();
        } catch (e) {
            console.error('CloudSync007 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync008
     * @tc.desc Test Js Api cloudSync, invalid param, storeId is invalid type
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync008', 0, async function (done) {
        console.info('CloudSync008');
        function Progress(detail) {
            console.log('CloudSync008 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. The type of storeId must be string.
            await cloudData.Config.cloudSync("bundleName", 10, relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress);
            expect(false).assertTrue();
            done();
        } catch (e) {
            console.error('CloudSync008 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync009
     * @tc.desc Test Js Api cloudSync, invalid param, wrong syncMode
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync009', 0, async function (done) {
        console.info('CloudSync009');
        function Progress(detail) {
            console.log('CloudSync009 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. The syncMode is invalid.
            await cloudData.Config.cloudSync("bundleName", "storeId", relationalStore.SyncMode.SYNC_MODE_PUSH, Progress);
            expect(false).assertTrue();
            done();
        } catch (e) {
            console.error('CloudSync009 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 14800001).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync010
     * @tc.desc Test Js Api cloudSync, invalid param, wrong syncMode
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync010', 0, async function (done) {
        console.info('CloudSync010');
        function Progress(detail) {
            console.log('CloudSync010 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. The syncMode is invalid.
            await cloudData.Config.cloudSync("bundleName", "storeId", relationalStore.SyncMode.SYNC_MODE_PULL, Progress);
            expect(false).assertTrue();
            done();
        } catch (e) {
            console.error('CloudSync010 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 14800001).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync011
     * @tc.desc Test Js Api cloudSync, invalid param, wrong syncMode
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync011', 0, async function (done) {
        console.info('CloudSync011');
        function Progress(detail) {
            console.log('CloudSync011 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. The syncMode is invalid.
            await cloudData.Config.cloudSync("bundleName", "storeId", 100, Progress);
            expect(false).assertTrue();
            done();
        } catch (e) {
            console.error('CloudSync011 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 14800001).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync012
     * @tc.desc Test Js Api cloudSync, invalid param, wrong syncMode
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync012', 0, async function (done) {
        console.info('CloudSync012');
        function Progress(detail) {
            console.log('CloudSync012 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. The type of syncMode must be number.
            await cloudData.Config.cloudSync("bundleName", "storeId", "syncMode", Progress);
            expect(false).assertTrue();
            done();
        } catch (e) {
            console.error('CloudSync012 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync013
     * @tc.desc Test Js Api cloudSync, invalid param, syncMode is null.
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync013', 0, async function (done) {
        console.info('CloudSync013');
        function Progress(detail) {
            console.log('CloudSync013 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. The type of syncMode must be number.
            await cloudData.Config.cloudSync("bundleName", "storeId", null, Progress);
            expect(false).assertTrue();
            done();
        } catch (e) {
            console.error('CloudSync013 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

        /**
     * @tc.name CloudSync014
     * @tc.desc Test Js Api cloudSync, invalid param, syncMode is undefined.
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync014', 0, async function (done) {
        console.info('CloudSync014');
        function Progress(detail) {
            console.log('CloudSync014 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. The type of syncMode must be number.
            await cloudData.Config.cloudSync("bundleName", "storeId", undefined, Progress);
            expect(false).assertTrue();
            done();
        } catch (e) {
            console.error('CloudSync014 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync015
     * @tc.desc Test Js Api cloudSync, invalid param, empty bundleName
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync015', 0, async function (done) {
        console.info('CloudSync015');
        function Progress(detail) {
            console.log('CloudSync015 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. bundleName can not be empty.
            await cloudData.Config.cloudSync("", "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress);
            expect(false).assertTrue();
            done();
        } catch (e) {
            console.error('CloudSync015 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 14800001).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync016
     * @tc.desc Test Js Api cloudSync, invalid param, bundleName is null
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync016', 0, async function (done) {
        console.info('CloudSync016');
        function Progress(detail) {
            console.log('CloudSync016 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. The type of bundleName must be string and not empty.
            await cloudData.Config.cloudSync(null, "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress);
            expect(false).assertTrue();
            done();
        } catch (e) {
            console.error('CloudSync016 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync017
     * @tc.desc Test Js Api cloudSync, invalid param, bundleName is undefined
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync017', 0, async function (done) {
        console.info('CloudSync017');
        function Progress(detail) {
            console.log('CloudSync017 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. The type of bundleName must be string and not empty.
            await cloudData.Config.cloudSync(undefined, "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress);
            expect(false).assertTrue();
            done();
        } catch (e) {
            console.error('CloudSync017 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync018
     * @tc.desc Test Js Api cloudSync, invalid param, bundleName is invalid type
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync018', 0, async function (done) {
        console.info('CloudSync018');
        function Progress(detail) {
            console.log('CloudSync018 Progress: ' + JSON.Stringify(detail));
        }
        try {
            // Parameter error. The type of bundleName must be string.
            await cloudData.Config.cloudSync(5, "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, Progress);
            expect(false).assertTrue();
            done();
        } catch (e) {
            console.error('CloudSync018 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync019
     * @tc.desc Test Js Api cloudSync, invalid param, progress is null
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync019', 0, async function (done) {
        console.info('CloudSync019');
        try {
            // Parameter error. The type progress should be function.
            await cloudData.Config.cloudSync("bundleName", "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, null);
            expect(false).assertTrue();
            done();
        } catch (e) {
            console.error('CloudSync019 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync020
     * @tc.desc Test Js Api cloudSync, invalid param, progress is undefined
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync020', 0, async function (done) {
        console.info('CloudSync020');
        try {
            // Parameter error. The type progress should be function.
            await cloudData.Config.cloudSync("bundleName", "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, undefined);
            expect(false).assertTrue();
            done();
        } catch (e) {
            console.error('CloudSync020 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name CloudSync021
     * @tc.desc Test Js Api cloudSync, invalid param, progress is undefined
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('CloudSync021', 0, async function (done) {
        console.info('CloudSync021');
        try {
            // Parameter error. The type progress should be function.
            await cloudData.Config.cloudSync("bundleName", "storeId", relationalStore.SyncMode.SYNC_MODE_TIME_FIRST, 123);
            expect(false).assertTrue();
            done();
        } catch (e) {
            console.error('CloudSync021 fail' + `, error code is ${e.code}, message is ${e.message}`);
            expect(e.code == 401).assertTrue();
            done();
        }
    })

    /**
     * @tc.name changeAppCloudSwitch001
     * @tc.desc Test changeAppCloudSwitch with no permission
     * @tc.type: FUNC
     * @tc.require:
     */
    it('changeAppCloudSwitch001', 0, async (done: () => void) => {
      let config: cloudData.SwitchConfig = {
        dbInfo: {
            'default_db': {
                enable: false
            }
        }
      };

      try {
        await cloudData.Config.changeAppCloudSwitch("test_account_001", "com.example.app1", false, config);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('changeAppCloudSwitch001 fail' + `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 202).assertTrue();
        done();
      }
    });

    /**
     * @tc.name clear001
     * @tc.desc Test clear with no permission
     * @tc.type: FUNC
     * @tc.require:
     */
    it('clear001', 0, async (done: () => void) => {
      let appActions: Record<string, cloudData.ClearAction> = {
        'com.example.simple': cloudData.ClearAction.CLEAR_CLOUD_INFO
      };

      let clearConfig: Record<string, cloudData.ClearConfig> = {
        'com.example.simple': {
          dbInfo: {
            'default_db': {
                action: cloudData.ClearAction.CLEAR_CLOUD_INFO
            }
          }
        }
      };

      try {
        await cloudData.Config.clear("test_account_002", appActions, clearConfig);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('clear001 fail' + `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 202).assertTrue();
        done();
      }
    });
  })
}