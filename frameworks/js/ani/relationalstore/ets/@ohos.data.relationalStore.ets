/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { AsyncCallback, Callback } from '@ohos.base'
import Context from 'application.BaseContext'

export default namespace relationalStore {

  loadLibrary("relationalstore_ani")

  export enum AssetStatus {
    ASSET_NORMAL,
    ASSET_INSERT,
    ASSET_UPDATE,
    ASSET_DELETE,
    ASSET_ABNORMAL,
    ASSET_DOWNLOADING
  }

  export interface Asset {
    name: string;
    uri: string;
    path: string;
    createTime: string;
    modifyTime: string;
    size: string;
    status?: AssetStatus;
  }

  type Assets = Asset[];

  type ValueType = null | number | string | boolean | Uint8Array | Asset | Assets | Float32Array | bigint;

  export type ValuesBucket = Record<string, ValueType>;

  export interface ResultSet {
    getColumnIndex(columnName: string): number;
    getString(columnIndex: number): string;
    getLong(columnIndex: number): number;
  }

  class ResultSetInner implements ResultSet {
    private nativePtr: long = 0;

    native getColumnIndex(columnName: string): number;
    native getString(columnIndex: number): string;
    native getLong(columnIndex: number): number;
  }

  export enum SecurityLevel {
    S1 = 1,
    S2 = 2,
    S3 = 3,
    S4 = 4
  }

  export interface StoreConfig {
    name: string;
    securityLevel: SecurityLevel;
    encrypt?: boolean;
    dataGroupId?: string;
    customDir?: string;
    autoCleanDirtyData?: boolean;
    isSearchable?: boolean;
    allowRebuild?: boolean;
    vector?: boolean;
    isReadOnly?: boolean;
    pluginLibs?: Array<string>;
    haMode?: HAMode;
    cryptoParam?: CryptoParam;
  }

  export enum HAMode {
    SINGLE = 0,
    MAIN_REPLICA
  }

  export interface CryptoParam {
    encryptionKey: Uint8Array;
    iterationCount?: number;
    encryptionAlgo?: EncryptionAlgo;
    hmacAlgo?: HmacAlgo;
    kdfAlgo?: KdfAlgo;
    cryptoPageSize?: number;
  }

  export enum EncryptionAlgo {
    AES_256_GCM = 0,
    AES_256_CBC
  }

  export enum HmacAlgo {
    SHA1 = 0,
    SHA256,
    SHA512
  }

  export enum KdfAlgo {
    KDF_SHA1 = 0,
    KDF_SHA256,
    KDF_SHA512
  }

  export interface RdbStore {
    batchInsert(table: string, values: Array<ValuesBucket>, callback: AsyncCallback<number>): void;
    batchInsert(table: string, values: Array<ValuesBucket>): Promise<number>;
    batchInsertSync(table: string, values: Array<ValuesBucket>): number;

    executeSql(sql: string, callback: AsyncCallback<void>): void;
    executeSql(sql: string, bindArgs: Array<ValueType>, callback: AsyncCallback<void>): void;
    executeSql(sql: string, bindArgs?: Array<ValueType>): Promise<void>;
    executeSqlSync(sql: string, args?: Array<ValueType>): void;

    beginTransaction(): void;

    commit(): void;
    commit(txId: number): Promise<void>;

    rollBack(): void;
    rollback(txId: number): Promise<void>;
  }

  class RdbStoreInner implements RdbStore {
    private nativePtr: long = 0;

    batchInsert(table: string, values: Array<ValuesBucket>, callback: AsyncCallback<number>): void {
    }
    batchInsert(table: string, values: Array<ValuesBucket>): Promise<number> {
      let p = new Promise<number>((resolve: (value: number) => void, reject: (error: Object) => void): void => {
      });
      return p
    }
    native batchInsertSync(table: string, values: Array<ValuesBucket>): number;

    executeSql(sql: string, callback: AsyncCallback<void>): void {
    }
    executeSql(sql: string, bindArgs: Array<ValueType>, callback: AsyncCallback<void>): void {
    }
    executeSql(sql: string, bindArgs?: Array<ValueType>): Promise<void> {
      let p = new Promise<void>((resolve: () => void, reject: (error: Object) => void): void => {
      });
      return p
    }
    native executeSqlSync(sql: string, args?: Array<ValueType>): void;

    native beginTransaction(): void;

    native commit(): void;
    commit(txId: number): Promise<void> {
      let p = new Promise<void>((resolve: () => void, reject: (error: Object) => void): void => {
      });
      return p
    }

    native rollBack(): void;
    rollback(txId: number): Promise<void> {
      let p = new Promise<void>((resolve: () => void, reject: (error: Object) => void): void => {
      });
      return p
    }
  }

  export native function getRdbStoreSync(context: Context, config: StoreConfig): RdbStore

  export function getRdbStore(context: Context, config: StoreConfig, callback: AsyncCallback<RdbStore>): void {
  }
  export function getRdbStore(context: Context, config: StoreConfig): Promise<RdbStore> {
    let p = new Promise<RdbStore>((resolve: (value: RdbStore) => void, reject: (error: Object) => void): void => {
      let p1 = taskpool.execute(getRdbStoreSync, context, config);
      p1.then((rdb: NullishType): void => {
        resolve(rdb as RdbStore);
      });
      p1.catch((err: NullishType): void => {
        reject(err as Object);
      });
    });
    return p
  }
}
