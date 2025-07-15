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
import dataSharePredicates from '@ohos.data.dataSharePredicates';
import { BusinessError } from '@ohos.base';

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

  class Cleaner {
    static callback(cleaner: Cleaner): void {
      cleaner.clean()
    }

    constructor(targetPtr: long) {
      this.targetPtr = targetPtr
    }

    native clean(): void
    private targetPtr: long = 0
  }

  class FinalizationAgent<T extends Object> {
    constructor(obj: T, ptr: long) {
      this.register(obj, ptr);
    }

    register(obj: T, ptr: long): void {
      this.unregisterToken = {};
      this.cleaner = new Cleaner(ptr);
      finalizer.register(obj, this.cleaner!, this.unregisterToken);
    }

    unregister(): void {
      finalizer.unregister(this.unregisterToken);
    }

    private cleaner: Cleaner | null = null;
    private unregisterToken: object;
  }

  let finalizer = new FinalizationRegistry<Cleaner>(Cleaner.callback)

  export class RdbPredicates {
    private nativePtr: long = 0
    private fzAgent: FinalizationAgent<RdbPredicates>

    constructor(name: string) {
      this.initNativePredicates(name)
      this.initFinalizer()
    }

    private initFinalizer() :void {
      this.fzAgent = new FinalizationAgent<RdbPredicates>(this, this.nativePtr)
    }
    private native initNativePredicates(name: string): void;
  }

  export interface ResultSet {
    getColumnIndex(columnName: string): number;
    getString(columnIndex: number): string;
    getLong(columnIndex: number): number;
    goToFirstRow(): boolean;
  }

  class ResultSetInner implements ResultSet {
    private nativePtr: long = 0;
    private fzAgent: FinalizationAgent<ResultSetInner>

    private initFinalizer() :void {
      this.fzAgent = new FinalizationAgent<ResultSetInner>(this, this.nativePtr)
    }

    native getColumnIndex(columnName: string): number;
    native getString(columnIndex: number): string;
    native getLong(columnIndex: number): number;
    native goToFirstRow(): boolean;
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

    deleteSync(predicates: RdbPredicates): number;
    delete(predicates: RdbPredicates): Promise<number>;
    delete(predicates: RdbPredicates, callback: AsyncCallback<number>): void;
    delete(table: string, predicates: dataSharePredicates.DataSharePredicates): Promise<number>;
    delete(table: string, predicates: dataSharePredicates.DataSharePredicates, callback: AsyncCallback<number>): void;

    executeSql(sql: string, callback: AsyncCallback<void>): void;
    executeSql(sql: string, bindArgs: Array<ValueType>, callback: AsyncCallback<void>): void;
    executeSql(sql: string, bindArgs?: Array<ValueType>): Promise<void>;

    beginTransaction(): void;
    commit(): void;
    rollBack(): void;

    querySqlSync(sql: string, bindArgs?: Array<ValueType>): ResultSet;
  }

  class RdbStoreInner implements RdbStore {
    private nativePtr: long = 0;
    private fzAgent: FinalizationAgent<RdbStoreInner>

    private initFinalizer() :void {
      this.fzAgent = new FinalizationAgent<RdbStoreInner>(this, this.nativePtr)
    }

    batchInsert(table: string, values: Array<ValuesBucket>, callback: AsyncCallback<number>): void {
      let cb = (): Object => {
          let num = this.batchInsertSync(table, values)
          return num as Object
      }
      let p1 = taskpool.execute(cb);
      p1.then((v: NullishType): void => {
        let error = new BusinessError<void>
        error.code = 0
        callback(error, v as number)
      });
      p1.catch((err: NullishType): void => {
        callback(err as BusinessError<void>, 0 as number)
      });
    }

    batchInsert(table: string, values: Array<ValuesBucket>): Promise<number> {
      let p = new Promise<number>((resolve: (value: number) => void, reject: (error: Error) => void): void => {
        let cb = (): Object => {
            let num = this.batchInsertSync(table, values)
            return num as Object
        }
        let p1 = taskpool.execute(cb);
        p1.then((v: NullishType): void => {
          resolve(v as number);
        });
        p1.catch((err: NullishType): void => {
          reject(err as Error);
        });
      });
      return p
    }
    native batchInsertSync(table: string, values: Array<ValuesBucket>): number;

    native deleteSync(predicates: RdbPredicates): number;

    delete(predicates: RdbPredicates): Promise<number> {
      let p = new Promise<number>((resolve: (data: number) => void, reject: (error: Error) => void): void => {
        let cb = (): Object => {
            let num = this.deleteSync(predicates)
            return num as Object
        }
        let p1 = taskpool.execute(cb);
        p1.then((v: NullishType): void => {
          resolve(v as number);
        });
        p1.catch((err: NullishType): void => {
          reject(err as Error);
        });
      });
      return p
    }

    delete(predicates: RdbPredicates, callback: AsyncCallback<number>): void {
      let cb = (): Object => {
          let num = this.deleteSync(predicates)
          return num as Object
      }
      let p1 = taskpool.execute(cb);
      p1.then((v: NullishType): void => {
        let error = new BusinessError
        error.code = 0
        callback(error, v as number)
      });
      p1.catch((err: NullishType): void => {
        callback(err as BusinessError, 0 as number)
      });
    }

    private native deleteShareSync(table: string, predicates: dataSharePredicates.DataSharePredicates): number;

    delete(table: string, predicates: dataSharePredicates.DataSharePredicates): Promise<number> {
      let p = new Promise<number>((resolve: (data: number) => void, reject: (error: Error) => void): void => {
        let cb = (): Object => {
            let num = this.deleteShareSync(table, predicates)
            return num as Object
        }
        let p1 = taskpool.execute(cb);
        p1.then((v: NullishType): void => {
          resolve(v as number);
        });
        p1.catch((err: NullishType): void => {
          reject(err as Error);
        });
      });
      return p
    }

    delete(table: string, predicates: dataSharePredicates.DataSharePredicates, callback: AsyncCallback<number>): void {
      let cb = (): Object => {
          let num = this.deleteShareSync(table, predicates)
          return num as Object
      }
      let p1 = taskpool.execute(cb);
      p1.then((v: NullishType): void => {
        let error = new BusinessError
        error.code = 0
        callback(error, v as number)
      });
      p1.catch((err: NullishType): void => {
        callback(err as BusinessError, 0 as number)
      });
    }

    executeSql(sql: string, callback: AsyncCallback<void>): void {
      let cb = (): undefined => {
          this.executeSqlSync(sql)
          return undefined
      }
      let p1 = taskpool.execute(cb);
      p1.then((v: NullishType): void => {
        let error = new BusinessError
        error.code = 0
        callback(error, undefined)
      });
      p1.catch((err: NullishType): void => {
        callback(err as BusinessError, undefined)
      });
    }

    executeSql(sql: string, bindArgs: Array<ValueType>, callback: AsyncCallback<void>): void {
      let cb = (): undefined => {
          this.executeSqlSync(sql, bindArgs)
          return undefined
      }
      let p1 = taskpool.execute(cb);
      p1.then((v: NullishType): void => {
        let error = new BusinessError
        error.code = 0
        callback(error, undefined)
      });
      p1.catch((err: NullishType): void => {
        callback(err as BusinessError, undefined)
      });
    }

    executeSql(sql: string, bindArgs?: Array<ValueType>): Promise<void> {
      let p = new Promise<void>((resolve: (v: PromiseLike<void>) => void, reject: (error: Error) => void): void => {
        let cb = (): undefined => {
            this.executeSqlSync(sql, bindArgs)
            return undefined
        }
        let p1 = taskpool.execute(cb);
        p1.then((v: NullishType): void => {
          resolve(v as PromiseLike<void>);
        });
        p1.catch((err: NullishType): void => {
          reject(err as Error);
        });
      });
      return p
    }

    private native executeSqlSync(sql: string, args?: Array<ValueType>): void;

    native beginTransaction(): void;
    native commit(): void;
    native rollBack(): void;

    native querySqlSync(sql: string, bindArgs?: Array<ValueType>): ResultSet;
  }

  export native function getRdbStoreSync(context: Context, config: StoreConfig): RdbStore

  export function getRdbStore(context: Context, config: StoreConfig, callback: AsyncCallback<RdbStore>): void {
    let p1 = taskpool.execute(getRdbStoreSync, context, config);
    p1.then((rdb: NullishType): void => {
      let error = new BusinessError
      error.code = 0
      callback(error, rdb as RdbStore)
    });
    p1.catch((err: NullishType): void => {
      let rdb = new RdbStoreInner()
      callback(err as BusinessError, rdb)
    });
  }
  export function getRdbStore(context: Context, config: StoreConfig): Promise<RdbStore> {
    let p = new Promise<RdbStore>((resolve: (value: RdbStore) => void, reject: (error: Error) => void): void => {
      let p1 = taskpool.execute(getRdbStoreSync, context, config);
      p1.then((rdb: NullishType): void => {
        resolve(rdb as RdbStore);
      });
      p1.catch((err: NullishType): void => {
        reject(err as Error);
      });
    });
    return p
  }
}

