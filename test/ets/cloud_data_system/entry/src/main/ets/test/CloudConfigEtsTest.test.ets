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

// @ts-nocheck
import { describe, beforeAll, beforeEach, afterEach, afterAll, it, expect } from '@ohos/hypium';
import cloudData from '@ohos.data.cloudData';
import { BusinessError } from '@ohos.base'

export default function CloudConfigSystemEtsTest() {
  describe('CloudConfigSystemEtsTest', () => {
    // Defines a test suite. Two parameters are supported: test suite name and test suite function.
    beforeAll(() => {
      // Presets an action, which is performed only once before all test cases of the test suite start.
      // This API supports only one parameter: preset action function.
    })
    beforeEach(() => {
      // Presets an action, which is performed before each unit test case starts.
      // The number of execution times is the same as the number of test cases defined by **it**.
      // This API supports only one parameter: preset action function.
    })
    afterEach(() => {
      // Presets a clear action, which is performed after each unit test case ends.
      // The number of execution times is the same as the number of test cases defined by **it**.
      // This API supports only one parameter: clear action function.
    })
    afterAll(() => {
      // Presets a clear action, which is performed after all test cases of the test suite end.
      // This API supports only one parameter: clear action function.
    })
    /**
     * @tc.name changeAppCloudSwitch001
     * @tc.desc Test changeAppCloudSwitch with complete SwitchConfig including tableInfo
     * @tc.type: FUNC
     * @tc.require:
     */
    it('changeAppCloudSwitch001', 0, async (done: () => void) => {
      let dbSwitchInfo: cloudData.DBSwitchInfo = {
        enable: true,
        tableInfo: {
          'user_table': true,
          'order_table': false,
          'product_table': true
        }
      };

      let dbSwitchInfo2: cloudData.DBSwitchInfo = {
        enable: false,
        tableInfo: {
          'log_table': false
        }
      };

      let dbInfos: Record<string, cloudData.DBSwitchInfo> = {
        'main_db': dbSwitchInfo,
        'log_db': dbSwitchInfo2
      };

      let config: cloudData.SwitchConfig = {
        dbInfo: dbInfos
      };

      try {
        await cloudData.Config.changeAppCloudSwitch("test_account_001", "com.example.app", true, config);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('changeAppCloudSwitch001 fail' + `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code != 401).assertTrue();
        done();
      }
    });

    /**
     * @tc.name changeAppCloudSwitch002
     * @tc.desc Test changeAppCloudSwitch with empty SwitchConfig (only dbInfo with empty tableInfo)
     * @tc.type: FUNC
     * @tc.require:
     */
    it('changeAppCloudSwitch002', 0, async (done: () => void) => {
      let dbSwitchInfo: cloudData.DBSwitchInfo = {
        enable: false
      };

      let dbInfos: Record<string, cloudData.DBSwitchInfo> = {
        'default_db': dbSwitchInfo
      };

      let config: cloudData.SwitchConfig = {
        dbInfo: dbInfos
      };

      try {
        await cloudData.Config.changeAppCloudSwitch("test_account_002", "com.example.app2", false, config);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('changeAppCloudSwitch002 fail' + `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code != 401).assertTrue();
        done();
      }
    });

    /**
     * @tc.name changeAppCloudSwitch003
     * @tc.desc Test changeAppCloudSwitch with multiple databases in SwitchConfig
     * @tc.type: FUNC
     * @tc.require:
     */
    it('changeAppCloudSwitch003', 0, async (done: () => void) => {
      let userDbInfo: cloudData.DBSwitchInfo = {
        enable: true,
        tableInfo: {
          'users': true,
          'profiles': true,
          'settings': false
        }
      };

      let orderDbInfo: cloudData.DBSwitchInfo = {
        enable: true,
        tableInfo: {
          'orders': true,
          'order_items': true,
          'payments': true
        }
      };

      let analyticsDbInfo: cloudData.DBSwitchInfo = {
        enable: false
      };

      let dbInfos: Record<string, cloudData.DBSwitchInfo> = {
        'user_database': userDbInfo,
        'order_database': orderDbInfo,
        'analytics_database': analyticsDbInfo
      };

      let config: cloudData.SwitchConfig = {
        dbInfo: dbInfos
      };

      try {
        await cloudData.Config.changeAppCloudSwitch("test_account_003", "com.example.business", true, config);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('changeAppCloudSwitch003 fail' + `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code != 401).assertTrue();
        done();
      }
    });

    /**
     * @tc.name changeAppCloudSwitch004
     * @tc.desc Test changeAppCloudSwitch interface with the config parameter as null
     * @tc.type: FUNC
     * @tc.require:
     */
    it('changeAppCloudSwitch004', 0, async (done: () => void) => {
      try {
        await cloudData.Config.changeAppCloudSwitch("test_account_004", "com.example.simple", true, null);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('changeAppCloudSwitch004 fail' + `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 401).assertTrue();
        done();
      }
    });

    /**
     * @tc.name changeAppCloudSwitch005
     * @tc.desc Test changeAppCloudSwitch with empty ClearConfig (empty dbInfo)
     * @tc.type: FUNC
     * @tc.require:
     */
    it('changeAppCloudSwitch005', 0, async (done: () => void) => {
      let config: cloudData.SwitchConfig = {
        dbInfo: {}
      };
      try {
        await cloudData.Config.changeAppCloudSwitch("test_account_005", "com.example.simple", true, config);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('changeAppCloudSwitch005 fail' + `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 401).assertTrue();
        done();
      }
    });
    /**
     * @tc.name clear001
     * @tc.desc Test clear with complete ClearConfig including tableInfo with all ClearAction types
     * @tc.type: FUNC
     * @tc.require:
     */
    it('clear001', 0, async (done: () => void) => {
      let appActions: Record<string, cloudData.ClearAction> = {
        'com.example.app1': cloudData.ClearAction.CLEAR_CLOUD_DATA_AND_INFO,
        'com.example.app2': cloudData.ClearAction.CLEAR_CLOUD_INFO,
        'com.example.app3': cloudData.ClearAction.CLEAR_CLOUD_NONE
      };

      let dbActionInfo1: cloudData.DBActionInfo = {
        action: cloudData.ClearAction.CLEAR_CLOUD_DATA_AND_INFO,
        tableInfo: {
          'sensitive_table': cloudData.ClearAction.CLEAR_CLOUD_DATA_AND_INFO,
          'normal_table': cloudData.ClearAction.CLEAR_CLOUD_INFO,
          'cache_table': cloudData.ClearAction.CLEAR_CLOUD_NONE
        }
      };

      let dbActionInfo2: cloudData.DBActionInfo = {
        action: cloudData.ClearAction.CLEAR_CLOUD_INFO,
        tableInfo: {
          'log_table': cloudData.ClearAction.CLEAR_CLOUD_INFO,
          'temp_table': cloudData.ClearAction.CLEAR_CLOUD_DATA_AND_INFO
        }
      };

      let dbActionInfo3: cloudData.DBActionInfo = {
        action: cloudData.ClearAction.CLEAR_CLOUD_NONE
      };

      let clearConfig: Record<string, cloudData.ClearConfig> = {
        'com.example.app1': {
          dbInfo: {
            'main_db': dbActionInfo1,
            'log_db': dbActionInfo2
          }
        },
        'com.example.app2': {
          dbInfo: {
            'user_db': dbActionInfo3
          }
        }
      };

      try {
        await cloudData.Config.clear("test_account_001", appActions, clearConfig);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('clear001 fail' + `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code != 401).assertTrue();
        done();
      }
    });

    /**
     * @tc.name clear002
     * @tc.desc Test clear with minimal ClearConfig (only dbInfo without tableInfo)
     * @tc.type: FUNC
     * @tc.require:
     */
    it('clear002', 0, async (done: () => void) => {
      let appActions: Record<string, cloudData.ClearAction> = {
        'com.example.simple': cloudData.ClearAction.CLEAR_CLOUD_INFO
      };

      let dbActionInfo: cloudData.DBActionInfo = {
        action: cloudData.ClearAction.CLEAR_CLOUD_INFO
      };

      let clearConfig: Record<string, cloudData.ClearConfig> = {
        'com.example.simple': {
          dbInfo: {
            'default_db': dbActionInfo
          }
        }
      };

      try {
        await cloudData.Config.clear("test_account_002", appActions, clearConfig);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('clear002 fail' + `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code != 401).assertTrue();
        done();
      }
    });

    /**
     * @tc.name clear003
     * @tc.desc Test clear with mixed ClearAction types in tableInfo
     * @tc.type: FUNC
     * @tc.require:
     */
    it('clear003', 0, async (done: () => void) => {
      let appActions: Record<string, cloudData.ClearAction> = {
        'com.example.mixed': cloudData.ClearAction.CLEAR_CLOUD_DATA_AND_INFO
      };

      let dbActionInfo: cloudData.DBActionInfo = {
        action: cloudData.ClearAction.CLEAR_CLOUD_INFO,
        tableInfo: {
          'user_data': cloudData.ClearAction.CLEAR_CLOUD_DATA_AND_INFO,
          'app_config': cloudData.ClearAction.CLEAR_CLOUD_INFO,
          'local_cache': cloudData.ClearAction.CLEAR_CLOUD_NONE
        }
      };

      let clearConfig: Record<string, cloudData.ClearConfig> = {
        'com.example.mixed': {
          dbInfo: {
            'mixed_db': dbActionInfo
          }
        }
      };

      try {
        await cloudData.Config.clear("test_account_003", appActions, clearConfig);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('clear003 fail' + `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code != 401).assertTrue();
        done();
      }
    });

    /**
     * @tc.name clear004
     * @tc.desc Test the clear interface with the config parameter as null
     * @tc.type: FUNC
     * @tc.require:
     */
    it('clear004', 0, async (done: () => void) => {
      let appActions: Record<string, cloudData.ClearAction> = {
        'com.example.noconfig': cloudData.ClearAction.CLEAR_CLOUD_INFO,
        'com.example.another': cloudData.ClearAction.CLEAR_CLOUD_DATA_AND_INFO
      };

      try {
        await cloudData.Config.clear("test_account_004", appActions, null);
        expect(true).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('clear004 fail' + `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 401).assertTrue();
        done();
      }
    });

    /**
     * @tc.name clear005
     * @tc.desc Test clear with empty ClearConfig (empty dbInfo)
     * @tc.type: FUNC
     * @tc.require:
     */
    it('clear005', 0, async (done: () => void) => {
      let appActions: Record<string, cloudData.ClearAction> = {
        'com.example.empty': cloudData.ClearAction.CLEAR_CLOUD_INFO
      };

      let clearConfig: Record<string, cloudData.ClearConfig> = {
        'com.example.empty': {
          dbInfo: {}
        }
      };

      try {
        await cloudData.Config.clear("test_account_005", appActions, clearConfig);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('clear005 fail' + `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 401).assertTrue();
        done();
      }
    });

    /**
     * @tc.name clear006
     * @tc.desc Test clear with multiple applications and nested ClearConfig
     * @tc.type: FUNC
     * @tc.require:
     */
    it('clear006', 0, async (done: () => void) => {
      let appActions: Record<string, cloudData.ClearAction> = {
        'app.commerce': cloudData.ClearAction.CLEAR_CLOUD_DATA_AND_INFO,
        'app.social': cloudData.ClearAction.CLEAR_CLOUD_INFO,
        'app.utility': cloudData.ClearAction.CLEAR_CLOUD_NONE
      };

      let clearConfig: Record<string, cloudData.ClearConfig> = {
        'app.commerce': {
          dbInfo: {
            'product_db': {
              action: cloudData.ClearAction.CLEAR_CLOUD_DATA_AND_INFO,
              tableInfo: {
                'products': cloudData.ClearAction.CLEAR_CLOUD_DATA_AND_INFO,
                'inventory': cloudData.ClearAction.CLEAR_CLOUD_INFO
              }
            },
            'order_db': {
              action: cloudData.ClearAction.CLEAR_CLOUD_INFO
            }
          }
        },
        'app.social': {
          dbInfo: {
            'user_db': {
              action: cloudData.ClearAction.CLEAR_CLOUD_INFO,
              tableInfo: {
                'profiles': cloudData.ClearAction.CLEAR_CLOUD_INFO,
                'messages': cloudData.ClearAction.CLEAR_CLOUD_DATA_AND_INFO,
                'notifications': cloudData.ClearAction.CLEAR_CLOUD_NONE
              }
            }
          }
        },
        'app.utility': {
          dbInfo: {
            'settings_db': {
              action: cloudData.ClearAction.CLEAR_CLOUD_NONE
            }
          }
        }
      };

      try {
        await cloudData.Config.clear("test_account_006", appActions, clearConfig);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('clear006 fail' + `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code != 401).assertTrue();
        done();
      }
    });
    /**
     * @tc.name clear007
     * @tc.desc Test clear with invalid ClearAction enum value in DBActionInfo.action field
     * @tc.type: FUNC
     * @tc.require:
     */
    it('clear007', 0, async (done: () => void) => {
      let appActions: Record<string, cloudData.ClearAction> = {
        'com.example.test': cloudData.ClearAction.CLEAR_CLOUD_INFO
      };

      let invalidDbActionInfo: cloudData.DBActionInfo = {
        action: 999,
        tableInfo: {
          'normal_table': cloudData.ClearAction.CLEAR_CLOUD_INFO
        }
      };

      let clearConfig: Record<string, cloudData.ClearConfig> = {
        'com.example.test': {
          dbInfo: {
            'test_db': invalidDbActionInfo
          }
        }
      };

      try {
        await cloudData.Config.clear("test_account_007", appActions, clearConfig);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('clear007 fail' + `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 401).assertTrue();
        done();
      }
    });

    /**
     * @tc.name clear008
     * @tc.desc Test clear with invalid ClearAction enum value in tableInfo values
     * @tc.type: FUNC
     * @tc.require:
     */
    it('clear008', 0, async (done: () => void) => {
      let appActions: Record<string, cloudData.ClearAction> = {
        'com.example.test': cloudData.ClearAction.CLEAR_CLOUD_DATA_AND_INFO
      };

      let dbActionInfo: cloudData.DBActionInfo = {
        action: cloudData.ClearAction.CLEAR_CLOUD_INFO,
        tableInfo: {
          'table1': cloudData.ClearAction.CLEAR_CLOUD_INFO,
          'table2': 888,
          'table3': cloudData.ClearAction.CLEAR_CLOUD_DATA_AND_INFO,
          'table4': -1
        }
      };

      let clearConfig: Record<string, cloudData.ClearConfig> = {
        'com.example.test': {
          dbInfo: {
            'test_db': dbActionInfo
          }
        }
      };

      try {
        await cloudData.Config.clear("test_account_008", appActions, clearConfig);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('clear008 fail' + `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 401).assertTrue();
        done();
      }
    });

    /**
     * @tc.name clear009
     * @tc.desc Test clear with both DBActionInfo.action and tableInfo values having invalid enum values
     * @tc.type: FUNC
     * @tc.require:
     */
    it('clear009', 0, async (done: () => void) => {
      let appActions: Record<string, cloudData.ClearAction> = {
        'com.example.mixed': cloudData.ClearAction.CLEAR_CLOUD_INFO
      };

      let dbActionInfo: cloudData.DBActionInfo = {
        action: 777,
        tableInfo: {
          'table_a': cloudData.ClearAction.CLEAR_CLOUD_INFO,
          'table_b': 666,
          'table_c': cloudData.ClearAction.CLEAR_CLOUD_NONE,
          'table_d': 555
        }
      };

      let clearConfig: Record<string, cloudData.ClearConfig> = {
        'com.example.mixed': {
          dbInfo: {
            'mixed_db': dbActionInfo,
            'another_db': {
              action: cloudData.ClearAction.CLEAR_CLOUD_DATA_AND_INFO,
              tableInfo: {
                'table_x': 444
              }
            }
          }
        }
      };

      try {
        await cloudData.Config.clear("test_account_009", appActions, clearConfig);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('clear009 fail' + `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 401).assertTrue();
        done();
      }
    });

    /**
     * @tc.name QueryLastSyncInfoBatch_EmptyAccountId
     * @tc.desc Test queryLastSyncInfo with empty accountId string
     * @tc.type: FUNC
     * @tc.require:
     */
    it('QueryLastSyncInfoBatch_EmptyAccountId', 0, async (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [
        { bundleName: "com.example.app1" }
      ];

      try {
        await cloudData.Config.queryLastSyncInfo("", bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('QueryLastSyncInfoBatch_EmptyAccountId fail' +
          `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 14800001).assertTrue();
        done();
      }
    });

    /**
     * @tc.name QueryLastSyncInfoBatch_NullAccountId
     * @tc.desc Test queryLastSyncInfo with null accountId
     * @tc.type: FUNC
     * @tc.require:
     */
    it('QueryLastSyncInfoBatch_NullAccountId', 0, async (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [
        { bundleName: "com.example.app1" }
      ];

      try {
        await cloudData.Config.queryLastSyncInfo(null, bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('QueryLastSyncInfoBatch_NullAccountId fail' +
          `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 14800001).assertTrue();
        done();
      }
    });

    /**
     * @tc.name QueryLastSyncInfoBatch_InvalidBundleNameType
     * @tc.desc Test queryLastSyncInfo with invalid bundleName type (number)
     * @tc.type: FUNC
     * @tc.require:
     */
    it('QueryLastSyncInfoBatch_InvalidBundleNameType', 0, async (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [
        { bundleName: 12345 as any }
      ];

      try {
        await cloudData.Config.queryLastSyncInfo("test_account", bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('QueryLastSyncInfoBatch_InvalidBundleNameType fail' +
          `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 14800001).assertTrue();
        done();
      }
    });

    /**
     * @tc.name QueryLastSyncInfoBatch_InvalidStoreIdType
     * @tc.desc Test queryLastSyncInfo with invalid storeId type (number)
     * @tc.type: FUNC
     * @tc.require:
     */
    it('QueryLastSyncInfoBatch_InvalidStoreIdType', 0, async (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [
        { bundleName: "com.example.app1", storeId: 12345 as any }
      ];

      try {
        await cloudData.Config.queryLastSyncInfo("test_account", bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('QueryLastSyncInfoBatch_InvalidStoreIdType fail' +
          `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 14800001).assertTrue();
        done();
      }
    });

    /**
     * @tc.name QueryLastSyncInfoBatch_EmptyBundleInfosArray
     * @tc.desc Test queryLastSyncInfo with empty bundleInfos array
     * @tc.type: FUNC
     * @tc.require:
     */
    it('QueryLastSyncInfoBatch_EmptyBundleInfosArray', 0, async (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [];

      try {
        await cloudData.Config.queryLastSyncInfo("test_account", bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('QueryLastSyncInfoBatch_EmptyBundleInfosArray fail' +
          `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 14800001).assertTrue();
        done();
      }
    });

    /**
     * @tc.name QueryLastSyncInfoBatch_ExceedMaxLimit
     * @tc.desc Test queryLastSyncInfo with 31 BundleInfo items (exceeds max limit 30)
     * @tc.type: FUNC
     * @tc.require:
     */
    it('QueryLastSyncInfoBatch_ExceedMaxLimit', 0, async (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [];
      
      for (let i = 0; i < 31; i++) {
        bundleInfos.push({
          bundleName: `com.example.app${i}`,
          storeId: `db${i % 10}`
        });
      }

      try {
        let results = await cloudData.Config.queryLastSyncInfo("test_account", bundleInfos);
        console.info('QueryLastSyncInfoBatch_ExceedMaxLimit should not reach here');
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('QueryLastSyncInfoBatch_ExceedMaxLimit fail' +
          `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 14800001).assertTrue();
        done();
      }
    });

    // ==================== onSyncInfoChanged Tests ====================

    /**
     * @tc.name OnSyncInfoChanged_System_EmptyBundleInfosArray
     * @tc.desc Test onSyncInfoChanged with empty bundleInfos array
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OnSyncInfoChanged_System_EmptyBundleInfosArray', 0, (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [];

      try {
        cloudData.Config.onSyncInfoChanged(bundleInfos, (data) => {});
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OnSyncInfoChanged_System_EmptyBundleInfosArray fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 14800001).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OnSyncInfoChanged_System_NullBundleInfos
     * @tc.desc Test onSyncInfoChanged with null bundleInfos
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OnSyncInfoChanged_System_NullBundleInfos', 0, (done: () => void) => {
      try {
        cloudData.Config.onSyncInfoChanged(null as any, (data) => {});
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OnSyncInfoChanged_System_NullBundleInfos fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 14800001).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OnSyncInfoChanged_System_InvalidBundleNameType
     * @tc.desc Test onSyncInfoChanged with invalid bundleName type (number)
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OnSyncInfoChanged_System_InvalidBundleNameType', 0, (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [
        { bundleName: 12345 as any }
      ];

      try {
        cloudData.Config.onSyncInfoChanged(bundleInfos, (data) => {});
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OnSyncInfoChanged_System_InvalidBundleNameType fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 14800001).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OnSyncInfoChanged_System_InvalidStoreIdType
     * @tc.desc Test onSyncInfoChanged with invalid storeId type (number)
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OnSyncInfoChanged_System_InvalidStoreIdType', 0, (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [
        { bundleName: "com.example.app1", storeId: 12345 as any }
      ];

      try {
        cloudData.Config.onSyncInfoChanged(bundleInfos, (data) => {});
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OnSyncInfoChanged_System_InvalidStoreIdType fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 14800001).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OnSyncInfoChanged_System_NullCallback
     * @tc.desc Test onSyncInfoChanged with null callback
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OnSyncInfoChanged_System_NullCallback', 0, (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [
        { bundleName: "com.example.app1" }
      ];

      try {
        cloudData.Config.onSyncInfoChanged(bundleInfos, null as any);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OnSyncInfoChanged_System_NullCallback fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 14800001).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OnSyncInfoChanged_System_InvalidCallbackType
     * @tc.desc Test onSyncInfoChanged with invalid callback type (string)
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OnSyncInfoChanged_System_InvalidCallbackType', 0, (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [
        { bundleName: "com.example.app1" }
      ];

      try {
        cloudData.Config.onSyncInfoChanged(bundleInfos, "invalid" as any);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OnSyncInfoChanged_System_InvalidCallbackType fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 14800001).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OnSyncInfoChanged_SingleBundle_OnlyBundleName
     * @tc.desc Test onSyncInfoChanged with single BundleInfo containing only bundleName
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OnSyncInfoChanged_SingleBundle_OnlyBundleName', 0, (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [
        { bundleName: "com.example.app1" }
      ];

      try {
        cloudData.Config.onSyncInfoChanged(bundleInfos, (data) => {
          console.info('OnSyncInfoChanged_SingleBundle_OnlyBundleName callback: ' + 
            JSON.stringify(data));
        });
        console.info('OnSyncInfoChanged_SingleBundle_OnlyBundleName subscribe success');
        
        cloudData.Config.offSyncInfoChanged(bundleInfos);
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OnSyncInfoChanged_SingleBundle_OnlyBundleName fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(false).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OnSyncInfoChanged_SingleBundle_WithStoreId
     * @tc.desc Test onSyncInfoChanged with single BundleInfo containing both bundleName and storeId
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OnSyncInfoChanged_SingleBundle_WithStoreId', 0, (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [
        { bundleName: "com.example.app1", storeId: "db1" }
      ];

      try {
        cloudData.Config.onSyncInfoChanged(bundleInfos, (data) => {
          console.info('OnSyncInfoChanged_SingleBundle_WithStoreId callback: ' + 
            JSON.stringify(data));
        });
        console.info('OnSyncInfoChanged_SingleBundle_WithStoreId subscribe success');
        
        cloudData.Config.offSyncInfoChanged(bundleInfos);
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OnSyncInfoChanged_SingleBundle_WithStoreId fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(false).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OnSyncInfoChanged_MultipleBundles
     * @tc.desc Test onSyncInfoChanged with multiple BundleInfo objects
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OnSyncInfoChanged_MultipleBundles', 0, (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [
        { bundleName: "com.example.app1", storeId: "db1" },
        { bundleName: "com.example.app2" },
        { bundleName: "com.example.app3", storeId: "db3" }
      ];

      try {
        cloudData.Config.onSyncInfoChanged(bundleInfos, (data) => {
          console.info('OnSyncInfoChanged_MultipleBundles callback: ' + 
            JSON.stringify(data));
        });
        console.info('OnSyncInfoChanged_MultipleBundles subscribe success');
        
        cloudData.Config.offSyncInfoChanged(bundleInfos);
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OnSyncInfoChanged_MultipleBundles fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(false).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OnSyncInfoChanged_DuplicateSubscribe
     * @tc.desc Test onSyncInfoChanged with duplicate subscription
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OnSyncInfoChanged_DuplicateSubscribe', 0, (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [
        { bundleName: "com.example.app1", storeId: "db1" }
      ];

      let callback = (data: Record<string, Record<string, cloudData.SyncInfo>>) => {
        console.info('OnSyncInfoChanged_DuplicateSubscribe callback: ' + 
          JSON.stringify(data));
      };

      try {
        cloudData.Config.onSyncInfoChanged(bundleInfos, callback);
        console.info('OnSyncInfoChanged_DuplicateSubscribe first subscribe success');
        
        cloudData.Config.onSyncInfoChanged(bundleInfos, callback);
        console.info('OnSyncInfoChanged_DuplicateSubscribe second subscribe success');
        
        cloudData.Config.offSyncInfoChanged(bundleInfos);
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OnSyncInfoChanged_DuplicateSubscribe fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(false).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OnSyncInfoChanged_DifferentCallbacksSameBundleInfos
     * @tc.desc Test onSyncInfoChanged with same bundleInfos but different callbacks
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OnSyncInfoChanged_DifferentCallbacksSameBundleInfos', 0, (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [
        { bundleName: "com.example.app1", storeId: "db1" }
      ];

      let callback1 = (data: Record<string, Record<string, cloudData.SyncInfo>>) => {
        console.info('OnSyncInfoChanged_DifferentCallbacksSameBundleInfos callback1: ' + 
          JSON.stringify(data));
      };

      let callback2 = (data: Record<string, Record<string, cloudData.SyncInfo>>) => {
        console.info('OnSyncInfoChanged_DifferentCallbacksSameBundleInfos callback2: ' + 
          JSON.stringify(data));
      };

      try {
        cloudData.Config.onSyncInfoChanged(bundleInfos, callback1);
        console.info('OnSyncInfoChanged_DifferentCallbacksSameBundleInfos first subscribe success');
        
        cloudData.Config.onSyncInfoChanged(bundleInfos, callback2);
        console.info('OnSyncInfoChanged_DifferentCallbacksSameBundleInfos second subscribe success');
        
        cloudData.Config.offSyncInfoChanged(bundleInfos);
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OnSyncInfoChanged_DifferentCallbacksSameBundleInfos fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(false).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OnSyncInfoChanged_DuplicateBundleNames
     * @tc.desc Test onSyncInfoChanged with duplicate bundleName in BundleInfo array
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OnSyncInfoChanged_DuplicateBundleNames', 0, (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [
        { bundleName: "com.example.app1", storeId: "db1" },
        { bundleName: "com.example.app1", storeId: "db2" },
        { bundleName: "com.example.app1" }
      ];

      try {
        cloudData.Config.onSyncInfoChanged(bundleInfos, (data) => {
          console.info('OnSyncInfoChanged_DuplicateBundleNames callback: ' + 
            JSON.stringify(data));
        });
        console.info('OnSyncInfoChanged_DuplicateBundleNames subscribe success');
        
        cloudData.Config.offSyncInfoChanged(bundleInfos);
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OnSyncInfoChanged_DuplicateBundleNames fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(false).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OnSyncInfoChanged_LargeArray
     * @tc.desc Test onSyncInfoChanged with large array of BundleInfo (30 items)
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OnSyncInfoChanged_LargeArray', 0, (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [];
      
      for (let i = 0; i < 30; i++) {
        bundleInfos.push({
          bundleName: `com.example.app${i}`,
          storeId: `db${i % 10}`
        });
      }

      try {
        cloudData.Config.onSyncInfoChanged(bundleInfos, (data) => {
          console.info('OnSyncInfoChanged_LargeArray callback: ' + 
            JSON.stringify(data));
        });
        console.info('OnSyncInfoChanged_LargeArray subscribe success');
        
        cloudData.Config.offSyncInfoChanged(bundleInfos);
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OnSyncInfoChanged_LargeArray fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(false).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OnSyncInfoChanged_EmptyStoreId
     * @tc.desc Test onSyncInfoChanged with empty storeId string
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OnSyncInfoChanged_EmptyStoreId', 0, (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [
        { bundleName: "com.example.app1", storeId: "" }
      ];

      try {
        cloudData.Config.onSyncInfoChanged(bundleInfos, (data) => {
          console.info('OnSyncInfoChanged_EmptyStoreId callback: ' + 
            JSON.stringify(data));
        });
        console.info('OnSyncInfoChanged_EmptyStoreId subscribe success');
        
        cloudData.Config.offSyncInfoChanged(bundleInfos);
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OnSyncInfoChanged_EmptyStoreId fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(false).assertTrue();
        done();
      }
    });

    // ==================== offSyncInfoChanged Tests ====================

    /**
     * @tc.name OffSyncInfoChanged_System_EmptyBundleInfosArray
     * @tc.desc Test offSyncInfoChanged with empty bundleInfos array
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OffSyncInfoChanged_System_EmptyBundleInfosArray', 0, (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [];

      try {
        cloudData.Config.offSyncInfoChanged(bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OffSyncInfoChanged_System_EmptyBundleInfosArray fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 14800001).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OffSyncInfoChanged_System_NullBundleInfos
     * @tc.desc Test offSyncInfoChanged with null bundleInfos
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OffSyncInfoChanged_System_NullBundleInfos', 0, (done: () => void) => {
      try {
        cloudData.Config.offSyncInfoChanged(null as any);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OffSyncInfoChanged_System_NullBundleInfos fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 14800001).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OffSyncInfoChanged_System_InvalidBundleNameType
     * @tc.desc Test offSyncInfoChanged with invalid bundleName type
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OffSyncInfoChanged_System_InvalidBundleNameType', 0, (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [
        { bundleName: 12345 as any }
      ];

      try {
        cloudData.Config.offSyncInfoChanged(bundleInfos);
        expect(false).assertTrue();
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OffSyncInfoChanged_System_InvalidBundleNameType fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(error.code == 14800001).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OffSyncInfoChanged_WithCallback
     * @tc.desc Test offSyncInfoChanged with callback parameter
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OffSyncInfoChanged_WithCallback', 0, (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [
        { bundleName: "com.example.app1", storeId: "db1" }
      ];

      let callback = (data: Record<string, Record<string, cloudData.SyncInfo>>) => {
        console.info('OffSyncInfoChanged_WithCallback callback: ' + 
          JSON.stringify(data));
      };

      try {
        cloudData.Config.onSyncInfoChanged(bundleInfos, callback);
        console.info('OffSyncInfoChanged_WithCallback subscribe success');
        
        cloudData.Config.offSyncInfoChanged(bundleInfos, callback);
        console.info('OffSyncInfoChanged_WithCallback unsubscribe success');
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OffSyncInfoChanged_WithCallback fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(false).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OffSyncInfoChanged_WithoutCallback
     * @tc.desc Test offSyncInfoChanged without callback parameter
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OffSyncInfoChanged_WithoutCallback', 0, (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [
        { bundleName: "com.example.app1", storeId: "db1" }
      ];

      try {
        cloudData.Config.onSyncInfoChanged(bundleInfos, (data) => {
          console.info('OffSyncInfoChanged_WithoutCallback callback: ' + 
            JSON.stringify(data));
        });
        console.info('OffSyncInfoChanged_WithoutCallback subscribe success');
        
        cloudData.Config.offSyncInfoChanged(bundleInfos);
        console.info('OffSyncInfoChanged_WithoutCallback unsubscribe success');
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OffSyncInfoChanged_WithoutCallback fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(false).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OffSyncInfoChanged_NotSubscribed
     * @tc.desc Test offSyncInfoChanged when not subscribed
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OffSyncInfoChanged_NotSubscribed', 0, (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [
        { bundleName: "com.example.app1", storeId: "db1" }
      ];

      try {
        cloudData.Config.offSyncInfoChanged(bundleInfos);
        console.info('OffSyncInfoChanged_NotSubscribed success');
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OffSyncInfoChanged_NotSubscribed fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(false).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OffSyncInfoChanged_PartialMatch
     * @tc.desc Test offSyncInfoChanged with partial match
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OffSyncInfoChanged_PartialMatch', 0, (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [
        { bundleName: "com.example.app1", storeId: "db1" },
        { bundleName: "com.example.app2", storeId: "db2" }
      ];

      let partialBundleInfos: cloudData.BundleInfo[] = [
        { bundleName: "com.example.app1", storeId: "db1" }
      ];

      try {
        cloudData.Config.onSyncInfoChanged(bundleInfos, (data) => {
          console.info('OffSyncInfoChanged_PartialMatch callback: ' + 
            JSON.stringify(data));
        });
        console.info('OffSyncInfoChanged_PartialMatch subscribe success');
        
        cloudData.Config.offSyncInfoChanged(partialBundleInfos);
        console.info('OffSyncInfoChanged_PartialMatch unsubscribe success');
        
        cloudData.Config.offSyncInfoChanged(bundleInfos);
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OffSyncInfoChanged_PartialMatch fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(false).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OffSyncInfoChanged_MultipleSubscriptions
     * @tc.desc Test offSyncInfoChanged with multiple subscriptions
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OffSyncInfoChanged_MultipleSubscriptions', 0, (done: () => void) => {
      let bundleInfos1: cloudData.BundleInfo[] = [
        { bundleName: "com.example.app1", storeId: "db1" }
      ];

      let bundleInfos2: cloudData.BundleInfo[] = [
        { bundleName: "com.example.app2", storeId: "db2" }
      ];

      try {
        cloudData.Config.onSyncInfoChanged(bundleInfos1, (data) => {
          console.info('OffSyncInfoChanged_MultipleSubscriptions callback1: ' + 
            JSON.stringify(data));
        });
        console.info('OffSyncInfoChanged_MultipleSubscriptions subscribe1 success');
        
        cloudData.Config.onSyncInfoChanged(bundleInfos2, (data) => {
          console.info('OffSyncInfoChanged_MultipleSubscriptions callback2: ' + 
            JSON.stringify(data));
        });
        console.info('OffSyncInfoChanged_MultipleSubscriptions subscribe2 success');
        
        cloudData.Config.offSyncInfoChanged(bundleInfos1);
        cloudData.Config.offSyncInfoChanged(bundleInfos2);
        console.info('OffSyncInfoChanged_MultipleSubscriptions unsubscribe success');
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OffSyncInfoChanged_MultipleSubscriptions fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(false).assertTrue();
        done();
      }
    });

    /**
     * @tc.name OffSyncInfoChanged_AllSubscriptions
     * @tc.desc Test offSyncInfoChanged to cancel all subscriptions
     * @tc.type: FUNC
     * @tc.require:
     */
    it('OffSyncInfoChanged_AllSubscriptions', 0, (done: () => void) => {
      let bundleInfos: cloudData.BundleInfo[] = [
        { bundleName: "com.example.app1", storeId: "db1" },
        { bundleName: "com.example.app2", storeId: "db2" }
      ];

      try {
        cloudData.Config.onSyncInfoChanged(bundleInfos, (data) => {
          console.info('OffSyncInfoChanged_AllSubscriptions callback: ' + 
            JSON.stringify(data));
        });
        console.info('OffSyncInfoChanged_AllSubscriptions subscribe success');
        
        cloudData.Config.offSyncInfoChanged(bundleInfos);
        console.info('OffSyncInfoChanged_AllSubscriptions unsubscribe all success');
        done();
      } catch (e) {
        let error = e as BusinessError;
        console.error('OffSyncInfoChanged_AllSubscriptions fail' + 
          `, error code is ${error.code}, message is ${error.message}`);
        expect(false).assertTrue();
        done();
      }
    });
  })
}