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

export default function CloudConfigNoPermissionEtsTest() {
  describe('CloudConfigNoPermissionEtsTest', () => {
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
        expect(error.code == 201).assertTrue();
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
        expect(error.code == 201).assertTrue();
        done();
      }
    });
  })
}