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

    /**
     * @tc.name QueryLastSyncInfoBatch_EmptyAccountId
     * @tc.desc Test queryLastSyncInfo with empty accountId string
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoBatch_EmptyAccountId', 0, async function (done) {
      console.info('QueryLastSyncInfoBatch_EmptyAccountId');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [
          { bundleName: "com.example.app1" }
        ];
        await cloudData.Config.queryLastSyncInfo("", bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('QueryLastSyncInfoBatch_EmptyAccountId fail' +
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    })

    /**
     * @tc.name QueryLastSyncInfoBatch_NullAccountId
     * @tc.desc Test queryLastSyncInfo with null accountId
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoBatch_NullAccountId', 0, async function (done) {
      console.info('QueryLastSyncInfoBatch_NullAccountId');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [
          { bundleName: "com.example.app1" }
        ];
        await cloudData.Config.queryLastSyncInfo(null, bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('QueryLastSyncInfoBatch_NullAccountId fail' +
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    })

    /**
     * @tc.name QueryLastSyncInfoBatch_UndefinedAccountId
     * @tc.desc Test queryLastSyncInfo with undefined accountId
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoBatch_UndefinedAccountId', 0, async function (done) {
      console.info('QueryLastSyncInfoBatch_UndefinedAccountId');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [
          { bundleName: "com.example.app1" }
        ];
        await cloudData.Config.queryLastSyncInfo(undefined, bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('QueryLastSyncInfoBatch_UndefinedAccountId fail' +
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    })

    /**
     * @tc.name QueryLastSyncInfoBatch_InvalidAccountIdType
     * @tc.desc Test queryLastSyncInfo with invalid accountId type (number)
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoBatch_InvalidAccountIdType', 0, async function (done) {
      console.info('QueryLastSyncInfoBatch_InvalidAccountIdType');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [
          { bundleName: "com.example.app1" }
        ];
        await cloudData.Config.queryLastSyncInfo(12345, bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('QueryLastSyncInfoBatch_InvalidAccountIdType fail' +
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    })

    /**
     * @tc.name QueryLastSyncInfoBatch_EmptyBundleInfosArray
     * @tc.desc Test queryLastSyncInfo with empty bundleInfos array
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoBatch_EmptyBundleInfosArray', 0, async function (done) {
      console.info('QueryLastSyncInfoBatch_EmptyBundleInfosArray');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [];
        await cloudData.Config.queryLastSyncInfo("test_account", bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('QueryLastSyncInfoBatch_EmptyBundleInfosArray fail' +
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    })

    /**
     * @tc.name QueryLastSyncInfoBatch_NullBundleInfos
     * @tc.desc Test queryLastSyncInfo with null bundleInfos
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoBatch_NullBundleInfos', 0, async function (done) {
      console.info('QueryLastSyncInfoBatch_NullBundleInfos');
      try {
        await cloudData.Config.queryLastSyncInfo("test_account", null);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('QueryLastSyncInfoBatch_NullBundleInfos fail' +
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 401).assertTrue();
        done();
      }
    })

    /**
     * @tc.name QueryLastSyncInfoBatch_UndefinedBundleInfos
     * @tc.desc Test queryLastSyncInfo with undefined bundleInfos
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoBatch_UndefinedBundleInfos', 0, async function (done) {
      console.info('QueryLastSyncInfoBatch_UndefinedBundleInfos');
      try {
        await cloudData.Config.queryLastSyncInfo("test_account", undefined);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('QueryLastSyncInfoBatch_UndefinedBundleInfos fail' +
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 401).assertTrue();
        done();
      }
    })

    /**
     * @tc.name QueryLastSyncInfoBatch_InvalidBundleInfosType
     * @tc.desc Test queryLastSyncInfo with invalid bundleInfos type (number)
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoBatch_InvalidBundleInfosType', 0, async function (done) {
      console.info('QueryLastSyncInfoBatch_InvalidBundleInfosType');
      try {
        await cloudData.Config.queryLastSyncInfo("test_account", 12345);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('QueryLastSyncInfoBatch_InvalidBundleInfosType fail' +
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 401).assertTrue();
        done();
      }
    })

    /**
     * @tc.name QueryLastSyncInfoBatch_EmptyBundleName
     * @tc.desc Test queryLastSyncInfo with empty bundleName in BundleInfo
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoBatch_EmptyBundleName', 0, async function (done) {
      console.info('QueryLastSyncInfoBatch_EmptyBundleName');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [
          { bundleName: "" }
        ];
        await cloudData.Config.queryLastSyncInfo("test_account", bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('QueryLastSyncInfoBatch_EmptyBundleName fail' +
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    })

    /**
     * @tc.name QueryLastSyncInfoBatch_NullBundleName
     * @tc.desc Test queryLastSyncInfo with null bundleName in BundleInfo
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoBatch_NullBundleName', 0, async function (done) {
      console.info('QueryLastSyncInfoBatch_NullBundleName');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [
          { bundleName: null }
        ];
        await cloudData.Config.queryLastSyncInfo("test_account", bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('QueryLastSyncInfoBatch_NullBundleName fail' +
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    })

    /**
     * @tc.name QueryLastSyncInfoBatch_NoPermission_SingleBundle
     * @tc.desc Test queryLastSyncInfo with no 202 permission for single bundle
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoBatch_NoPermission_SingleBundle', 0, async function (done) {
      console.info('QueryLastSyncInfoBatch_NoPermission_SingleBundle');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [
          { bundleName: "com.example.app1" }
        ];
        await cloudData.Config.queryLastSyncInfo("test_account", bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('QueryLastSyncInfoBatch_NoPermission_SingleBundle fail' +
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 202).assertTrue();
        done();
      }
    })

    /**
     * @tc.name QueryLastSyncInfoBatch_NoPermission_MultipleBundles
     * @tc.desc Test queryLastSyncInfo with no 202 permission for multiple bundles
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoBatch_NoPermission_MultipleBundles', 0, async function (done) {
      console.info('QueryLastSyncInfoBatch_NoPermission_MultipleBundles');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [
          { bundleName: "com.example.app1" },
          { bundleName: "com.example.app2" }
        ];
        await cloudData.Config.queryLastSyncInfo("test_account", bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('QueryLastSyncInfoBatch_NoPermission_MultipleBundles fail' +
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 202).assertTrue();
        done();
      }
    })

    /**
     * @tc.name QueryLastSyncInfoBatch_NoPermission_WithStoreId
     * @tc.desc Test queryLastSyncInfo with no 202 permission and with storeId
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoBatch_NoPermission_WithStoreId', 0, async function (done) {
      console.info('QueryLastSyncInfoBatch_NoPermission_WithStoreId');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [
          { bundleName: "com.example.app1", storeId: "db1" }
        ];
        await cloudData.Config.queryLastSyncInfo("test_account", bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('QueryLastSyncInfoBatch_NoPermission_WithStoreId fail' +
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 202).assertTrue();
        done();
      }
    })

    /**
     * @tc.name QueryLastSyncInfoBatch_MissingAllParams
     * @tc.desc Test queryLastSyncInfo with no parameters
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoBatch_MissingAllParams', 0, async function (done) {
      console.info('QueryLastSyncInfoBatch_MissingAllParams');
      try {
        await cloudData.Config.queryLastSyncInfo();
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('QueryLastSyncInfoBatch_MissingAllParams fail' +
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 401).assertTrue();
        done();
      }
    })

    /**
     * @tc.name QueryLastSyncInfoBatch_MissingBundleInfosParam
     * @tc.desc Test queryLastSyncInfo with only accountId parameter
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoBatch_MissingBundleInfosParam', 0, async function (done) {
      console.info('QueryLastSyncInfoBatch_MissingBundleInfosParam');
      try {
        await cloudData.Config.queryLastSyncInfo("test_account");
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('QueryLastSyncInfoBatch_MissingBundleInfosParam fail' +
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 401).assertTrue();
        done();
      }
    })

    /**
     * @tc.name QueryLastSyncInfoBatch_Exactly30Items
     * @tc.desc Test queryLastSyncInfo with exactly 30 BundleInfo items (boundary test)
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoBatch_Exactly30Items', 0, async function (done) {
      console.info('QueryLastSyncInfoBatch_Exactly30Items');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [];
        for (let i = 0; i < 30; i++) {
          bundleInfos.push({ bundleName: "com.example.app" + i });
        }
        await cloudData.Config.queryLastSyncInfo("test_account", bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('QueryLastSyncInfoBatch_Exactly30Items fail' +
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 202).assertTrue();
        done();
      }
    })

    /**
     * @tc.name QueryLastSyncInfoBatch_31Items
     * @tc.desc Test queryLastSyncInfo with 31 BundleInfo items (should fail)
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('QueryLastSyncInfoBatch_31Items', 0, async function (done) {
      console.info('QueryLastSyncInfoBatch_31Items');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [];
        for (let i = 0; i < 31; i++) {
          bundleInfos.push({ bundleName: "com.example.app" + i });
        }
        await cloudData.Config.queryLastSyncInfo("test_account", bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('QueryLastSyncInfoBatch_31Items fail' + `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    })

    // ==================== onSyncInfoChanged Tests ====================

    /**
     * @tc.name OnSyncInfoChanged_EmptyBundleInfosArray
     * @tc.desc Test onSyncInfoChanged with empty bundleInfos array
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('OnSyncInfoChanged_EmptyBundleInfosArray', 0, function (done) {
      console.info('OnSyncInfoChanged_EmptyBundleInfosArray');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [];
        cloudData.Config.onSyncInfoChanged(bundleInfos, (data) => {});
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('OnSyncInfoChanged_EmptyBundleInfosArray fail' + 
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    });

 
    /**
     * @tc.name OnSyncInfoChanged_NullBundleInfos
     * @tc.desc Test onSyncInfoChanged with null bundleInfos
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('OnSyncInfoChanged_NullBundleInfos', 0, function (done) {
      console.info('OnSyncInfoChanged_NullBundleInfos');
      try {
        cloudData.Config.onSyncInfoChanged(null, (data) => {});
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('OnSyncInfoChanged_NullBundleInfos fail' + 
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    });
 
    /**
     * @tc.name OnSyncInfoChanged_UndefinedBundleInfos
     * @tc.desc Test onSyncInfoChanged with undefined bundleInfos
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('OnSyncInfoChanged_UndefinedBundleInfos', 0, function (done) {
      console.info('OnSyncInfoChanged_UndefinedBundleInfos');
      try {
        cloudData.Config.onSyncInfoChanged(undefined, (data) => {});
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('OnSyncInfoChanged_UndefinedBundleInfos fail' + 
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    });
 
    /**
     * @tc.name OnSyncInfoChanged_InvalidBundleInfosType
     * @tc.desc Test onSyncInfoChanged with invalid bundleInfos type (string)
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('OnSyncInfoChanged_InvalidBundleInfosType', 0, function (done) {
      console.info('OnSyncInfoChanged_InvalidBundleInfosType');
      try {
        cloudData.Config.onSyncInfoChanged("invalid" as any, (data) => {});
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('OnSyncInfoChanged_InvalidBundleInfosType fail' + 
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    });
 
    /**
     * @tc.name OnSyncInfoChanged_NullCallback
     * @tc.desc Test onSyncInfoChanged with null callback
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('OnSyncInfoChanged_NullCallback', 0, function (done) {
      console.info('OnSyncInfoChanged_NullCallback');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [
          { bundleName: "com.example.app1" }
        ];
        cloudData.Config.onSyncInfoChanged(bundleInfos, null);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('OnSyncInfoChanged_NullCallback fail' + 
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    });
 
    /**
     * @tc.name OnSyncInfoChanged_UndefinedCallback
     * @tc.desc Test onSyncInfoChanged with undefined callback
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('OnSyncInfoChanged_UndefinedCallback', 0, function (done) {
      console.info('OnSyncInfoChanged_UndefinedCallback');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [
          { bundleName: "com.example.app1" }
        ];
        cloudData.Config.onSyncInfoChanged(bundleInfos, undefined);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('OnSyncInfoChanged_UndefinedCallback fail' + 
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    });
 
    /**
     * @tc.name OnSyncInfoChanged_InvalidCallbackType
     * @tc.desc Test onSyncInfoChanged with invalid callback type (number)
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('OnSyncInfoChanged_InvalidCallbackType', 0, function (done) {
      console.info('OnSyncInfoChanged_InvalidCallbackType');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [
          { bundleName: "com.example.app1" }
        ];
        cloudData.Config.onSyncInfoChanged(bundleInfos, 12345 as any);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('OnSyncInfoChanged_InvalidCallbackType fail' + 
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    });
 
    /**
     * @tc.name OnSyncInfoChanged_EmptyBundleName
     * @tc.desc Test onSyncInfoChanged with empty bundleName in BundleInfo
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('OnSyncInfoChanged_EmptyBundleName', 0, function (done) {
      console.info('OnSyncInfoChanged_EmptyBundleName');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [
          { bundleName: "" }
        ];
        cloudData.Config.onSyncInfoChanged(bundleInfos, (data) => {});
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('OnSyncInfoChanged_EmptyBundleName fail' + 
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    });
 
    /**
     * @tc.name OnSyncInfoChanged_NullBundleName
     * @tc.desc Test onSyncInfoChanged with null bundleName in BundleInfo
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('OnSyncInfoChanged_NullBundleName', 0, function (done) {
      console.info('OnSyncInfoChanged_NullBundleName');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [
          { bundleName: null }
        ];
        cloudData.Config.onSyncInfoChanged(bundleInfos, (data) => {});
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('OnSyncInfoChanged_NullBundleName fail' + 
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    });
 
    /**
     * @tc.name OnSyncInfoChanged_NoPermission_SingleBundle
     * @tc.desc Test onSyncInfoChanged with no 202 permission for single bundle
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('OnSyncInfoChanged_NoPermission_SingleBundle', 0, function (done) {
      console.info('OnSyncInfoChanged_NoPermission_SingleBundle');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [
          { bundleName: "com.example.app1" }
        ];
        cloudData.Config.onSyncInfoChanged(bundleInfos, (data) => {});
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('OnSyncInfoChanged_NoPermission_SingleBundle fail' + 
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 202).assertTrue();
        done();
      }
    });
 
    /**
     * @tc.name OnSyncInfoChanged_NoPermission_MultipleBundles
     * @tc.desc Test onSyncInfoChanged with no 202 permission for multiple bundles
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('OnSyncInfoChanged_NoPermission_MultipleBundles', 0, function (done) {
      console.info('OnSyncInfoChanged_NoPermission_MultipleBundles');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [
          { bundleName: "com.example.app1" },
          { bundleName: "com.example.app2" }
        ];
        cloudData.Config.onSyncInfoChanged(bundleInfos, (data) => {});
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('OnSyncInfoChanged_NoPermission_MultipleBundles fail' + 
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 202).assertTrue();
        done();
      }
    });
 
    /**
     * @tc.name OnSyncInfoChanged_NoPermission_WithStoreId
     * @tc.desc Test onSyncInfoChanged with no 202 permission and with storeId
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('OnSyncInfoChanged_NoPermission_WithStoreId', 0, function (done) {
      console.info('OnSyncInfoChanged_NoPermission_WithStoreId');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [
          { bundleName: "com.example.app1", storeId: "db1" }
        ];
        cloudData.Config.onSyncInfoChanged(bundleInfos, (data) => {});
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('OnSyncInfoChanged_NoPermission_WithStoreId fail' + 
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 202).assertTrue();
        done();
      }
    });
 
    /**
     * @tc.name OnSyncInfoChanged_MissingAllParams
     * @tc.desc Test onSyncInfoChanged with no parameters
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('OnSyncInfoChanged_MissingAllParams', 0, function (done) {
      console.info('OnSyncInfoChanged_MissingAllParams');
      try {
        cloudData.Config.onSyncInfoChanged();
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('OnSyncInfoChanged_MissingAllParams fail' + 
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    });
 
    /**
     * @tc.name OnSyncInfoChanged_MissingCallbackParam
     * @tc.desc Test onSyncInfoChanged with only bundleInfos parameter
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('OnSyncInfoChanged_MissingCallbackParam', 0, function (done) {
      console.info('OnSyncInfoChanged_MissingCallbackParam');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [
          { bundleName: "com.example.app1" }
        ];
        cloudData.Config.onSyncInfoChanged(bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('OnSyncInfoChanged_MissingCallbackParam fail' + 
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    });
 
    /**
     * @tc.name OnSyncInfoChanged_31Items
     * @tc.desc Test onSyncInfoChanged with 31 BundleInfo items (should fail)
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('OnSyncInfoChanged_31Items', 0, function (done) {
      console.info('OnSyncInfoChanged_31Items');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [];
        for (let i = 0; i < 31; i++) {
          bundleInfos.push({ bundleName: "com.example.app" + i });
        }
        cloudData.Config.onSyncInfoChanged(bundleInfos, (data) => {});
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('OnSyncInfoChanged_31Items fail' +
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    });

    // ==================== offSyncInfoChanged Tests ====================
 
    /**
     * @tc.name OffSyncInfoChanged_EmptyBundleInfosArray
     * @tc.desc Test offSyncInfoChanged with empty bundleInfos array
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('OffSyncInfoChanged_EmptyBundleInfosArray', 0, function (done) {
      console.info('OffSyncInfoChanged_EmptyBundleInfosArray');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [];
        cloudData.Config.offSyncInfoChanged(bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('OffSyncInfoChanged_EmptyBundleInfosArray fail' + 
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    });
 
    /**
     * @tc.name OffSyncInfoChanged_InvalidBundleInfosType
     * @tc.desc Test offSyncInfoChanged with invalid bundleInfos type
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('OffSyncInfoChanged_InvalidBundleInfosType', 0, function (done) {
      console.info('OffSyncInfoChanged_InvalidBundleInfosType');
      try {
        cloudData.Config.offSyncInfoChanged("invalid" as any);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('OffSyncInfoChanged_InvalidBundleInfosType fail' + 
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OffSyncInfoChanged_31Items
     * @tc.desc Test offSyncInfoChanged with 31 BundleInfo items (should fail)
     * @tc.type: FUNC
     * @tc.require: issueNumber
     */
    it('OffSyncInfoChanged_31Items', 0, function (done) {
      console.info('OffSyncInfoChanged_31Items');
      try {
        let bundleInfos: cloudData.BundleInfo[] = [];
        for (let i = 0; i < 31; i++) {
          bundleInfos.push({ bundleName: "com.example.app" + i });
        }
        cloudData.Config.offSyncInfoChanged(bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        console.error('OffSyncInfoChanged_31Items fail' +
          `, error code is ${e.code}, message is ${e.message}`);
        expect(e.code == 14800001).assertTrue();
        done();
      }
    });
  })
}