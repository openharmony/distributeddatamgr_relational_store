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
  })
}