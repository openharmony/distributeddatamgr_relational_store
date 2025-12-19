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

import relationalStore from '@ohos.data.relationalStore';
import rpc from '@ohos.rpc';
import cloudData from '@ohos.data.cloudData';

const TAG = 'cloudExtension';
const INVALID_STATE = -1;
const INVALID_STR = '';
const MAX_SIZE: long = 1024 * 1024 - 1;
const IPC_WAIT_TIME = 1000;

namespace cloudExtension {

  export type Participant = cloudData.sharing.Participant;

  export type Privilege = cloudData.sharing.Privilege;

  export type ParticipantState = cloudData.sharing.State;

  export type CloudAssets = Array<CloudAsset>;

  export type CloudType = null | long | double | string | boolean | Uint8Array | CloudAsset | CloudAssets;

  export interface CloudAsset extends relationalStore.Asset {
    assetId: string;
    hash: string;
  }

  export interface Result<T> {
    code: int;
    description?: string;
    value?: T;
  }

  export interface CloudInfo {
    cloudInfo: ServiceInfo;
    apps: Record<string, AppBriefInfo>;
  }

  export interface ServiceInfo {
    enableCloud: boolean;
    id: string;
    totalSpace: int;
    remainingSpace: int;
    user: int;
  }

  export interface AppBriefInfo {
    appId: string;
    bundleName: string;
    cloudSwitch: boolean;
    instanceId: int;
  }

  export interface AppSchema {
    bundleName: string;
    version: int;
    databases: Array<Database>;
  }

  export interface Database {
    name: string;
    alias: string;
    tables: Array<Table>;
  }

  export interface Table {
    alias: string;
    name: string;
    fields: Array<Field>;
  }

  export interface Field {
    alias: string;
    colName: string;
    type: FieldType;
    primary: boolean;
    nullable: boolean;
  }

  export interface SubscribeInfo {
    expirationTime: long;
    subscribe: Record<string, Array<SubscribeId>>;
  }

  export interface SubscribeId {
    databaseAlias: string;
    id: string;
  }

  export interface CloudData {
    nextCursor: string;
    hasMore: boolean;
    values: Array<Record<string, CloudType>>;
  }

  export interface LockInfo {
    interval: int;
    sessionId: int;
  }

  export interface CloudService {
    getServiceInfo(): Promise<ServiceInfo>;

    getAppBriefInfo(): Promise<Record<string, AppBriefInfo>>;

    getAppSchema(bundleName: string): Promise<Result<AppSchema>>;

    subscribe(
      subInfo: Record<string, Array<Database>>,
      expirationTime: int
    ): Promise<Result<SubscribeInfo>>;

    unsubscribe(unsubscribeInfo: Record<string, Array<string>>): Promise<int>;

    connectDB(bundleName: string, database: Database): Promise<rpc.RemoteObject>;

    connectAssetLoader(bundleName: string, database: Database): Promise<rpc.RemoteObject>;

    connectShareCenter(userId: int, bundleName: string): Promise<rpc.RemoteObject>;
  }

  export interface CloudDB {
    generateId(count: int): Promise<Result<string[]>>;

    insert(table: string, values: Array<Record<string, CloudType>>,
      extValues: Array<Record<string, CloudType>>): Promise<Array<Result<Record<string, CloudType>>>>;

    update(table: string, values: Array<Record<string, CloudType>>,
      extValues: Array<Record<string, CloudType>>): Promise<Array<Result<Record<string, CloudType>>>>;

    delete(table: string,
      extValues: Array<Record<string, CloudType>>): Promise<Array<Result<Record<string, CloudType>>>>;

    query(table: string, fields: string[], queryCount: int, queryCursor: string): Promise<Result<CloudData>>;

    lock(): Promise<Result<LockInfo>>;

    heartbeat(sessionId: int): Promise<Result<LockInfo>>;

    unlock(sessionId: int): Promise<Result<boolean>>;
  }

  export interface AssetLoader {
    download(table: string, gid: string, prefix: string, assets: CloudAsset[]): Promise<Result<CloudAsset>[]>;

    upload(table: string, gid: string, assets: CloudAsset[]): Promise<Result<CloudAsset>[]>;
  }

  export interface ShareCenter {
    share(
      userId: int,
      bundleName: string,
      sharingResource: string,
      participants: Array<cloudData.sharing.Participant>
    ): Promise<Result<Array<Result<cloudData.sharing.Participant>>>>;

    unshare(
      userId: int,
      bundleName: string,
      sharingResource: string,
      participants: Array<cloudData.sharing.Participant>
    ): Promise<Result<Array<Result<cloudData.sharing.Participant>>>>;

    exit(userId: int, bundleName: string, sharingResource: string): Promise<Result<void>>;

    changePrivilege(
      userId: int,
      bundleName: string,
      sharingResource: string,
      participants: Array<cloudData.sharing.Participant>
    ): Promise<Result<Array<Result<cloudData.sharing.Participant>>>>;

    queryParticipants(
      userId: int,
      bundleName: string,
      sharingResource: string
    ): Promise<Result<Array<cloudData.sharing.Participant>>>;

    queryParticipantsByInvitation(
      userId: int,
      bundleName: string,
      invitationCode: string
    ): Promise<Result<Array<cloudData.sharing.Participant>>>;

    confirmInvitation(
      userId: int,
      bundleName: string,
      invitationCode: string,
      state: cloudData.sharing.State
    ): Promise<Result<string>>;

    changeConfirmation(
      userId: int,
      bundleName: string,
      sharingResource: string,
      state: cloudData.sharing.State
    ): Promise<Result<void>>;
  }

  export enum FieldType {
    NULL = 0,
    NUMBER,
    REAL,
    TEXT,
    BOOL,
    BLOB,
    ASSET,
    ASSETS
  }

  export enum ErrorCode {
    SUCCESS = 0,
    UNKNOWN_ERROR = 1,
    NETWORK_ERROR = 2,
    CLOUD_DISABLED = 3,
    LOCKED_BY_OTHERS = 4,
    RECORD_LIMIT_EXCEEDED = 5,
    NO_SPACE_FOR_ASSET = 6
  }

  export enum ServiceOperation {
    ConnectShareCenter = 0,
    ConnectAssetLoader = 1,
    ConnectDatabase = 2,
    GetAppBriefInfo = 3,
    GetServiceInfo = 4,
    GetAppSchema = 5,
    Subscribe = 6,
    Unsubscribe = 7
  }

  export enum ShareOperation {
    Share = 0,
    Unshare = 1,
    Exit = 2,
    ChangePrivilege = 3,
    QueryParticipants = 4,
    QueryParticipantsByInvitation = 5,
    ConfirmInvitation = 6,
    ChangeConfirmation = 7
  }


  export enum DatabaseOperation {
    GenerateIds = 0,
    Insert = 1,
    Update = 2,
    Delete = 3,
    Query = 4,
    Lock = 5,
    Unlock = 6,
    Heartbeat = 7
  }

  export enum AssetOperation {
    Download = 0,
    Upload = 1
  }

  const toFieldType = (value: int): cloudExtension.FieldType => {
    switch (value) {
      case 0:
        return cloudExtension.FieldType.NULL;
      case 1:
        return cloudExtension.FieldType.NUMBER;
      case 2:
        return cloudExtension.FieldType.REAL;
      case 3:
        return cloudExtension.FieldType.TEXT;
      case 4:
        return cloudExtension.FieldType.BOOL;
      case 5:
        return cloudExtension.FieldType.BLOB;
      case 6:
        return cloudExtension.FieldType.ASSET;
      case 7:
        return cloudExtension.FieldType.ASSETS;
      default:
        return cloudExtension.FieldType.NULL;
    }
  }

  class CloudServiceStub extends rpc.RemoteObject {
    cloudService: CloudService;

    constructor(descriptor: string, cloudService: CloudService) {
      super(descriptor);
      this.cloudService = cloudService;
    }

    async onRemoteMessageRequest(code: int, data: rpc.MessageSequence, reply: rpc.MessageSequence,
      option: rpc.MessageOption): Promise<boolean> {
      option.setWaitTime(IPC_WAIT_TIME);
      let descriptor = this.getDescriptor();
      switch (code) {
        case ServiceOperation.GetServiceInfo.valueOf():
          let serviceInfo: ServiceInfo = await this.cloudService.getServiceInfo();
          this.marshallingCloudInfo(reply, serviceInfo);
          return true;
        case ServiceOperation.GetAppBriefInfo.valueOf():
          let appBriefInfo: Record<string, AppBriefInfo> = await this.cloudService.getAppBriefInfo();
          this.marshallingAppBriefInfo(reply, appBriefInfo);
          return true;
        case ServiceOperation.GetAppSchema.valueOf():
          let bundleName = data.readString();
          if (!bundleName) {
            reply.writeInt(ErrorCode.UNKNOWN_ERROR);
            return false;
          }
          let appSchema: Result<AppSchema> = await this.cloudService.getAppSchema(bundleName);
          reply.writeInt(appSchema.code);
          if (appSchema.code === ErrorCode.SUCCESS) {
            this.marshallingAppSchema(reply, appSchema.value);
          }
          return true;
        case ServiceOperation.Subscribe.valueOf():
          let expirationTime: int = data.readInt();
          let subInfo: Record<string, cloudExtension.Database[]> = this.unMarshallingSubInfo(data);
          let subscribeResult: Result<SubscribeInfo> = await this.cloudService.subscribe(subInfo, expirationTime);
          reply.writeInt(subscribeResult.code);
          if (subscribeResult.code === ErrorCode.SUCCESS && subscribeResult.value !== undefined) {
            this.marshallingSubscribeInfo(reply, subscribeResult.value);
          }
          return true;
        case ServiceOperation.Unsubscribe.valueOf():
          let unsubInfo: Record<string, Array<string>> = this.unMarshallingUnSubInfo(data);
          let unsubscribeResult: int = await this.cloudService.unsubscribe(unsubInfo);
          reply.writeInt(unsubscribeResult > 0 ? ErrorCode.SUCCESS : ErrorCode.UNKNOWN_ERROR);
          return true;
        case ServiceOperation.ConnectDatabase.valueOf():
          let dbName = data.readString();
          let dbInfo: cloudExtension.Database = this.unMarshallingDatabase(data);
          let dbConnection: rpc.RemoteObject = await this.cloudService.connectDB(dbName, dbInfo);
          reply.writeRemoteObject(dbConnection);
          return true;
        case ServiceOperation.ConnectAssetLoader.valueOf():
          let assetLoaderName = data.readString();
          let assetLoaderInfo: cloudExtension.Database = this.unMarshallingDatabase(data);
          let assetLoaderConnection: rpc.RemoteObject =
            await this.cloudService.connectAssetLoader(assetLoaderName, assetLoaderInfo);
          reply.writeRemoteObject(assetLoaderConnection);
          return true;
        case ServiceOperation.ConnectShareCenter.valueOf():
          let userId = data.readInt();
          let shareCenterName = data.readString();
          let shareCenterConnection: rpc.RemoteObject =
            await this.cloudService.connectShareCenter(userId, shareCenterName);
          if (!shareCenterConnection) {
            return false;
          }
          reply.writeRemoteObject(shareCenterConnection);
          return true;
        default:
          return false;
      }

      return false;
    }

    marshallingCloudInfo(reply: rpc.MessageSequence, cloudInfo: ServiceInfo): void {
      reply.writeBoolean(cloudInfo.enableCloud);
      reply.writeString(cloudInfo.id);
      reply.writeLong(cloudInfo.totalSpace);
      reply.writeLong(cloudInfo.remainingSpace);
      reply.writeInt(cloudInfo.user);
    }

    marshallingAppBriefInfo(reply: rpc.MessageSequence, appBriefInfo: Record<string, AppBriefInfo>): void {
      let keys = Object.keys(appBriefInfo);
      reply.writeInt(keys.length);
      keys.forEach(key => {
        reply.writeString(key);
        let appInfo: AppBriefInfo | undefined = appBriefInfo[key];
        if (appInfo !== undefined) {
          reply.writeString(appInfo.appId);
          reply.writeString(appInfo.bundleName);
          reply.writeInt(appInfo.cloudSwitch ? 1 : 0);
          reply.writeInt(appInfo.instanceId);
        }
      });
    }

    marshallingAppSchema(reply: rpc.MessageSequence, appSchema: cloudExtension.AppSchema | undefined): void {
      reply.writeInt(appSchema?.version as int);
      reply.writeString(appSchema?.bundleName as string);
      reply.writeInt(appSchema?.databases.length as int);
      appSchema?.databases.forEach((database: cloudExtension.Database) => {
        reply.writeString(database.alias);
        reply.writeString(database.name);
        reply.writeInt(database.tables.length);
        database.tables.forEach((table: cloudExtension.Table) => {
          reply.writeString(table.alias);
          reply.writeString(table.name);
          reply.writeInt(table.fields.length);
          table.fields.forEach((field: cloudExtension.Field) => {
            reply.writeString(field.alias);
            reply.writeString(field.colName);
            reply.writeInt(field.type);
            reply.writeBoolean(field.primary);
            reply.writeBoolean(field.nullable);
          });
        });
      });
    }

    unMarshallingSubInfo(data: rpc.MessageSequence): Record<string, cloudExtension.Database[]> {
      let key = data.readString();
      let subInfo: Record<string, cloudExtension.Database[]> = {};
      let count = data.readInt();
      subInfo[key] = [];
      if (count < 0 || count > MAX_SIZE) {
        return subInfo;
      }
      for (let i = 0; i < count; i++) {
        subInfo[key]?.push(this.unMarshallingDatabase(data));
      }
      return subInfo;
    }

    unMarshallingDatabase(data: rpc.MessageSequence): cloudExtension.Database {
      let database: cloudExtension.Database = {
        alias: '',
        name: '',
        tables: []
      };
      database.name = data.readString();
      database.alias = data.readString();
      database.tables = [];
      let tableCount = data.readInt();
      if (tableCount < 0 || tableCount > MAX_SIZE) {
        return database;
      }
      for (let i = 0; i < tableCount; i++) {
        let tableAlias = data.readString();
        let tableName = data.readString();
        let table: cloudExtension.Table = {
          alias: tableAlias,
          name: tableName,
          fields: []
        };
        database.tables.push(table);
        let fieldCount = data.readInt();
        if (fieldCount < 0 || fieldCount > MAX_SIZE) {
          continue;
        }
        for (let j = 0; j < fieldCount; j++) {
          let field: cloudExtension.Field = {
            alias: data.readString(),
            colName: data.readString(),
            type: toFieldType(data.readInt()),
            primary: data.readBoolean(),
            nullable: data.readBoolean()
          };
          database.tables[i].fields.push(field);
        }
      }
      return database;
    }

    marshallingSubscribeInfo(reply: rpc.MessageSequence,
      subscribeInfo: cloudExtension.SubscribeInfo | undefined): void {
      if (subscribeInfo !== undefined) {
        reply.writeLong((subscribeInfo as cloudExtension.SubscribeInfo)?.expirationTime as long);
        let keys: string[] = Object.keys(subscribeInfo.subscribe);
        reply.writeInt(keys.length);
        keys.forEach(key => {
          reply.writeString(key);
          let subscribeDatabase: cloudExtension.SubscribeId[] =
            subscribeInfo?.subscribe[key] as cloudExtension.SubscribeId[];
          reply.writeInt(subscribeDatabase.length);
          subscribeDatabase.forEach(database => {
            reply.writeString(database.databaseAlias);
            reply.writeString(database.id);
          })
        })
      }
    }

    unMarshallingUnSubInfo(data: rpc.MessageSequence): Record<string, string[]> {
      let unsubInfo: Record<string, string[]> = {};
      let keyCount = data.readInt();
      if (keyCount < 0 || keyCount > MAX_SIZE) {
        return unsubInfo;
      }
      for (let i = 0; i < keyCount; i++) {
        let key = data.readString();
        unsubInfo[key] = [];
        let idCount = data.readInt();
        if (idCount < 0 || idCount > MAX_SIZE) {
          continue;
        }
        for (let j = 0; j < idCount; j++) {
          unsubInfo[key]?.push(data.readString());
        }
      }
      return unsubInfo;
    }
  }

  export class CloudDbStub extends rpc.RemoteObject {
    cloudDb: cloudExtension.CloudDB;

    constructor(descriptor: string, cloudDb: cloudExtension.CloudDB) {
      super(descriptor);
      this.cloudDb = cloudDb;
    }

    async onRemoteMessageRequest(code: int, data: rpc.MessageSequence, reply: rpc.MessageSequence,
      option: rpc.MessageOption): Promise<boolean> {
      if (this.cloudDb === undefined) {
        return false;
      }
      let descriptor = this.getDescriptor();
      option.setWaitTime(IPC_WAIT_TIME);
      switch (code) {
        case DatabaseOperation.GenerateIds.valueOf():
          let count = data.readInt();
          let idsResult: Result<Array<string>> = await this.cloudDb.generateId(count);
          reply.writeInt(idsResult.code);
          if (idsResult.code === 0) {
            reply.writeInt((idsResult as Result<Array<string>>).value?.length as int);
            (idsResult as Result<Array<string>>).value?.forEach((id: string) => {
              reply.writeString(id);
            });
          }
          return true;
        case DatabaseOperation.Insert.valueOf():
          let tableName = data.readString();
          let values: Record<string, cloudExtension.CloudType>[] = this.unMarshallingValuesBuckets(data);
          let assets: Record<string, cloudExtension.CloudType>[] = this.unMarshallingValuesBuckets(data);
          if (values.length === 0) {
            reply.writeInt(0);
            return true;
          }
          try {
            let insertResult: Array<Result<Record<string, cloudExtension.CloudType>>> =
              await this.cloudDb.insert(tableName, values, assets);
            this.marshallingResultValueBucket(reply, insertResult);
          } catch (error) {
            reply.writeInt(ErrorCode.UNKNOWN_ERROR);
          }
          return true;
        case DatabaseOperation.Update.valueOf():
          let updateTableName = data.readString();
          let updateValues: Record<string, cloudExtension.CloudType>[] = this.unMarshallingValuesBuckets(data);
          let updateAssets: Record<string, cloudExtension.CloudType>[] = this.unMarshallingValuesBuckets(data);
          try {
            let updateResult: Array<Result<Record<string, cloudExtension.CloudType>>> =
              await this.cloudDb.update(updateTableName, updateValues, updateAssets);
            this.marshallingResultValueBucket(reply, updateResult);
          } catch (error) {
            reply.writeInt(ErrorCode.UNKNOWN_ERROR);
          }
          return true;
        case DatabaseOperation.Delete.valueOf():
          let deleteTableName = data.readString();
          let deleteValues: Record<string, cloudExtension.CloudType>[] = this.unMarshallingValuesBuckets(data);
          try {
            let deleteResult: Array<Result<Record<string, cloudExtension.CloudType>>> =
              await this.cloudDb.delete(deleteTableName, deleteValues);
            this.marshallingResultValueBucket(reply, deleteResult);
          } catch (error) {
            reply.writeInt(ErrorCode.UNKNOWN_ERROR);
          }
          return true;
        case DatabaseOperation.Query.valueOf():
          let queryTableName = data.readString();
          let queryFields: Array<string> = this.unMarshallingFiledArray(data);
          let queryLimit = data.readInt();
          let queryCursor = data.readString();
          if (queryCursor === '') {
            queryCursor = '0';
          }
          try {
            let queryResult: Result<CloudData> =
              await this.cloudDb.query(queryTableName, queryFields, queryLimit, queryCursor);
            reply.writeInt(queryResult.code);
            if (queryResult.code === 0) {
              this.marshallingCloudData(reply, queryResult.value);
            }
          } catch (error) {
            reply.writeInt(ErrorCode.UNKNOWN_ERROR);
          }
          return true;
        case DatabaseOperation.Lock.valueOf():
          let lockResult: Result<LockInfo> = await this.cloudDb.lock() as Result<LockInfo>;
          reply.writeInt(lockResult.code);
          if (lockResult.code === 0) {
            reply.writeInt(lockResult.value?.interval as int);
            reply.writeInt(lockResult.value?.sessionId as int);
          }
          return true;
        case DatabaseOperation.Heartbeat.valueOf():
          let lockId = data.readInt();
          let date: Result<LockInfo> = await this.cloudDb.heartbeat(lockId) as Result<LockInfo>;
          reply.writeInt(date.code);
          if (date.code === 0) {
            reply.writeInt((date as Result<LockInfo>).value?.interval as int);
            reply.writeInt((date as Result<LockInfo>).value?.sessionId as int);
          }
          return true;
        case DatabaseOperation.Unlock.valueOf():
          let unlockLockId = data.readInt();
          let unlockResult: Result<boolean> = await this.cloudDb.unlock(unlockLockId);
          reply.writeInt(unlockResult.code);
          if (unlockResult.code === 0) {
            reply.writeBoolean(unlockResult.value as boolean);
          }
          return true;
        default:
          break;
      }
      return false;
    }

    marshallingResultValueBucket(reply: rpc.MessageSequence,
      result: Array<Result<Record<string, cloudExtension.CloudType>>>): void {
      if (result.length > MAX_SIZE) {
        return;
      }
      reply.writeInt(result.length);
      for (let i = 0; i < result.length; i++) {
        reply.writeInt(result[i].code);
        if (result[i].value) {
          let value: Record<string, cloudExtension.CloudType> =
            result[i].value as Record<string, cloudExtension.CloudType>;
          this.marshallingValueBucket(reply, value);
        } else {
          reply.writeInt(0);
        }
      }
    }

    marshallingValueBucket(reply: rpc.MessageSequence,
      valueBucket: Record<string, cloudExtension.CloudType> | undefined): void {
      if (valueBucket !== undefined) {
        let keys = Object.keys(valueBucket);
        reply.writeInt(keys.length as int);
        keys.forEach(key => {
          reply.writeString(key);
          let value: cloudExtension.CloudType = valueBucket[key] as cloudExtension.CloudType;
          if (value === undefined || value === null) {
            reply.writeInt(FieldType.NULL);
          } else {
            if (typeof value === 'number') {
              if (value!.toString().indexOf('.') !== -1) {
                reply.writeInt(FieldType.REAL)
                reply.writeFloat(value as double);
              } else {
                reply.writeInt(FieldType.NUMBER);
                reply.writeLong(value as long);
              }
            } else if (typeof value === 'string') {
              reply.writeInt(FieldType.TEXT);
              reply.writeString(value as string);
            } else if (typeof value === 'boolean') {
              reply.writeInt(FieldType.BOOL);
              reply.writeBoolean(value as boolean);
            } else {
              if (value instanceof Array) {
                reply.writeInt(FieldType.ASSETS);
                reply.writeInt(value.length);
                (value as cloudExtension.CloudAsset[]).forEach((asset: cloudExtension.CloudAsset) => {
                  reply.writeString(asset.name);
                  reply.writeString(asset.uri);
                  reply.writeString(asset.path);
                  reply.writeString(asset.createTime);
                  reply.writeString(asset.modifyTime);
                  reply.writeString(asset.size);
                  const cloudAsset = asset as cloudExtension.CloudAsset;
                  if (cloudAsset?.status) {
                    reply.writeInt(this.getAssetStatusValue(cloudAsset?.status));
                  } else {
                    reply.writeInt(relationalStore.AssetStatus.ASSET_NORMAL);
                  }
                  reply.writeString(asset.assetId);
                  reply.writeString(asset.hash);
                });
              } else if (value instanceof Uint8Array) {
                reply.writeInt(FieldType.BLOB);
                const byteArray: double[] = Array.from(value);
                reply.writeDoubleArray(byteArray);
              } else {
                reply.writeInt(FieldType.ASSET);
                reply.writeString((value as cloudExtension.CloudAsset)?.name as string);
                reply.writeString((value as cloudExtension.CloudAsset)?.uri as string);
                reply.writeString((value as cloudExtension.CloudAsset)?.path as string);
                reply.writeString((value as cloudExtension.CloudAsset)?.createTime as string);
                reply.writeString((value as cloudExtension.CloudAsset)?.modifyTime as string);
                reply.writeString((value as cloudExtension.CloudAsset)?.size as string);
                const asset = value as cloudExtension.CloudAsset;
                if (asset?.status) {
                  reply.writeInt(this.getAssetStatusValue(asset?.status));
                } else {
                  reply.writeInt(relationalStore.AssetStatus.ASSET_NORMAL);
                }
                reply.writeString((value as cloudExtension.CloudAsset)?.assetId as string);
                reply.writeString((value as cloudExtension.CloudAsset)?.hash as string);
              }
            }
          }
        });
      }
    }

    private getAssetStatusValue(status: relationalStore.AssetStatus | undefined): int {
      if (status === undefined || status.valueOf === undefined) {
        return relationalStore.AssetStatus.ASSET_NORMAL;
      }
      return status.valueOf();
    }

    marshallingValuesBuckets(reply: rpc.MessageSequence,
      valueBuckets: Array<Record<string, CloudType>> | undefined): void {
      if (valueBuckets !== undefined) {
        if (valueBuckets.length > MAX_SIZE) {
          return;
        }
        reply.writeInt(valueBuckets.length);
        for (let i = 0; i < valueBuckets.length; i++) {
          this.marshallingValueBucket(reply, (valueBuckets as Array<Record<string, CloudType>>)[i]);
        }
      }
    }


    unMarshallingFiledArray(data: rpc.MessageSequence): Array<string> {
      let fields: Array<string> = [];
      let count = data.readInt();
      if (count < 0 || count > MAX_SIZE) {
        return fields;
      }
      for (let i = 0; i < count; i++) {
        fields.push(data.readString());
      }
      return fields;
    }

    marshallingCloudData(reply: rpc.MessageSequence, cloudData: CloudData | undefined): void {
      reply.writeString(cloudData?.nextCursor as string);
      reply.writeBoolean(cloudData?.hasMore as boolean);
      this.marshallingValuesBuckets(reply, cloudData?.values);
    }

    unMarshallingValuesBuckets(data: rpc.MessageSequence): Array<Record<string, CloudType>> {
      let count = data.readInt();
      let valueBuckets: Array<Record<string, CloudType>> = [];
      if (count < 0 || count > MAX_SIZE) {
        return valueBuckets;
      }
      for (let i = 0; i < count; i++) {
        valueBuckets.push(this.unMarshallingValuesBucket(data));
      }
      return valueBuckets;
    }

    unMarshallingValuesBucket(data: rpc.MessageSequence): Record<string, CloudType> {
      let valueBucket: Record<string, CloudType> = {};
      let count = data.readInt();
      if (count < 0 || count > MAX_SIZE) {
        return valueBucket;
      }
      for (let i = 0; i < count; i++) {
        let key = data.readString();
        let value: cloudExtension.CloudType = this.unMarshallingValueType(data);
        valueBucket[key] = value;
      }
      return valueBucket;
    }

    unMarshallingValueType(data: rpc.MessageSequence): cloudExtension.CloudType {
      let type = data.readInt();
      switch (type) {
        case FieldType.NULL.valueOf(): // null
          return null;
        case FieldType.NUMBER.valueOf(): // number
          return data.readLong();
        case FieldType.REAL.valueOf(): // number
          return data.readFloat();
        case FieldType.TEXT.valueOf(): // string
          return data.readString()
        case FieldType.BOOL.valueOf(): // boolean
          return data.readBoolean();
        case FieldType.BLOB.valueOf(): // Uint8Array
          return Uint8Array.from(data.readIntArray());
        case FieldType.ASSET.valueOf(): // Asset
          return {
            name: data.readString(),
            uri: data.readString(),
            path: data.readString(),
            createTime: data.readString(),
            modifyTime: data.readString(),
            size: data.readString(),
            status: toAssetStatus(data.readInt()),
            assetId: data.readString(),
            hash: data.readString(),
          } as CloudAsset;
        case FieldType.ASSETS.valueOf(): // Assets
          let assetCount = data.readInt();
          let assets: CloudAssets = [];
          if (assetCount < 0 || assetCount > MAX_SIZE) {
            return assets;
          }
          for (let i = 0; i < assetCount; i++) {
            assets.push({
              name: data.readString(),
              uri: data.readString(),
              path: data.readString(),
              createTime: data.readString(),
              modifyTime: data.readString(),
              size: data.readString(),
              status: toAssetStatus(data.readInt()),
              assetId: data.readString(),
              hash: data.readString(),
            });
          }
          return assets;
      }
      return null;
    }
  }

  function toAssetStatus(value: int): relationalStore.AssetStatus {
    switch (value) {
      case 0:
        return relationalStore.AssetStatus.ASSET_NORMAL;
      case 1:
        return relationalStore.AssetStatus.ASSET_INSERT;
      case 2:
        return relationalStore.AssetStatus.ASSET_UPDATE;
      case 3:
        return relationalStore.AssetStatus.ASSET_DELETE;
      case 4:
        return relationalStore.AssetStatus.ASSET_ABNORMAL;
      case 5:
        return relationalStore.AssetStatus.ASSET_DOWNLOADING;
      default:
        return relationalStore.AssetStatus.ASSET_NORMAL;
    }
  }

  export class AssetLoaderStub extends rpc.RemoteObject {
    assetLoader: cloudExtension.AssetLoader;

    constructor(descriptor: string, assetLoader: cloudExtension.AssetLoader) {
      super(descriptor);
      this.assetLoader = assetLoader;
    }

    async onRemoteMessageRequest(code: int, data: rpc.MessageSequence, reply: rpc.MessageSequence,
      option: rpc.MessageOption): Promise<boolean> {
      option.setWaitTime(IPC_WAIT_TIME);
      let descriptor = this.getDescriptor();
      let tableName = data.readString();
      let assetId = data.readString();
      let localPath = data.readString();

      switch (code) {
        case AssetOperation.Download.valueOf():
          let downloadAssets: cloudExtension.CloudAsset[] = this.unmarshallingAssets(data);
          let downloadResult: Result<cloudExtension.CloudAsset>[] =
            await this.assetLoader.download(tableName, assetId, localPath, downloadAssets);
          this.marshallingAssets(reply, downloadResult);
          return true;
        case AssetOperation.Upload.valueOf():
          let uploadAssets: cloudExtension.CloudAsset[] = this.unmarshallingAssets(data);
          let uploadResult: Result<cloudExtension.CloudAsset>[] =
            await this.assetLoader.upload(tableName, assetId, uploadAssets);
          this.marshallingAssets(reply, uploadResult);
          return true;
      }
      return false;
    }

    unmarshallingAssets(data: rpc.MessageSequence): cloudExtension.CloudAsset[] {
      let count = data.readInt();
      let assets: cloudExtension.CloudAsset[] = [];
      if (count < 0 || count > MAX_SIZE) {
        return assets;
      }
      for (let i = 0; i < count; i++) {
        assets.push({
          name: data.readString(),
          uri: data.readString(),
          path: data.readString(),
          createTime: data.readString(),
          modifyTime: data.readString(),
          size: data.readString(),
          status: toAssetStatus(data.readInt()) as relationalStore.AssetStatus,
          assetId: data.readString(),
          hash: data.readString()
        });
      }
      return assets;
    }

    marshallingAssets(reply: rpc.MessageSequence, assets: Result<cloudExtension.CloudAsset>[]): void {
      reply.writeInt(assets.length);
      if (assets.length > MAX_SIZE) {
        return;
      }
      for (let i = 0; i < assets.length; i++) {
        reply.writeInt(assets[i].code);
        reply.writeString((assets[i]?.value as cloudExtension.CloudAsset).name as string);
        reply.writeString((assets[i]?.value as cloudExtension.CloudAsset).uri as string);
        reply.writeString((assets[i]?.value as cloudExtension.CloudAsset).path as string);
        reply.writeString((assets[i]?.value as cloudExtension.CloudAsset).createTime as string);
        reply.writeString((assets[i]?.value as cloudExtension.CloudAsset).modifyTime as string);
        reply.writeString((assets[i]?.value as cloudExtension.CloudAsset).size as string);
        reply.writeInt(this.getAssetStatusValue((assets[i]?.value as cloudExtension.CloudAsset).status));
        reply.writeString((assets[i]?.value as cloudExtension.CloudAsset).assetId as string);
        reply.writeString((assets[i]?.value as cloudExtension.CloudAsset).hash as string);
      }
    }

    private getAssetStatusValue(status: relationalStore.AssetStatus | undefined): int {
      if (status === undefined) {
        return relationalStore.AssetStatus.ASSET_NORMAL;
      }
      return status.valueOf();
    }
  }

  export class ShareCenterProxy extends rpc.RemoteObject {
    shareCenter: cloudExtension.ShareCenter;

    constructor(descriptor: string, shareCenter: cloudExtension.ShareCenter) {
      super(descriptor);
      this.shareCenter = shareCenter;
    }

    async onRemoteMessageRequest(code: int, data: rpc.MessageSequence, reply: rpc.MessageSequence,
      option: rpc.MessageOption): Promise<boolean> {
      if (this.shareCenter == undefined) {
        return false;
      }
      option.setWaitTime(IPC_WAIT_TIME);
      switch (code) {
        case ShareOperation.Share.valueOf():
          let userId = data.readInt();
          let bundleName = data.readString();
          let tableName = data.readString();
          let participants: Participant[] = this.unMarshallingParticipants(data);
          let shareResult: Result<Array<Result<Participant>>> =
            await this.shareCenter.share(userId, bundleName, tableName, participants);
          this.marshallingResults(reply, shareResult);
          return true;
        case ShareOperation.Unshare.valueOf():
          let unshareUserId = data.readInt();
          let unshareBundleName = data.readString();
          let unshareTableName = data.readString();
          let unshareParticipants: Participant[] = this.unMarshallingParticipants(data);
          let unshareResult: Result<Array<Result<cloudData.sharing.Participant>>> =
            await this.shareCenter.unshare(unshareUserId, unshareBundleName, unshareTableName, unshareParticipants);
          this.marshallingResults(reply, unshareResult);
          return true;
        case ShareOperation.Exit.valueOf():
          let exitUserId = data.readInt();
          let exitBundleName = data.readString();
          let exitTableName = data.readString();
          let exitResult: Result<void> = await this.shareCenter.exit(exitUserId, exitBundleName, exitTableName);
          reply.writeInt(exitResult.code);
          if (exitResult.description) {
            reply.writeString(exitResult?.description as string);
          } else {
            reply.writeString(INVALID_STR);
          }
          return true;
        case ShareOperation.ChangePrivilege.valueOf():
          let changeUserId = data.readInt();
          let changeBundleName = data.readString();
          let changeTableName = data.readString();
          let changeParticipants: Participant[] = this.unMarshallingParticipants(data);
          let changeResult: Result<Array<Result<cloudData.sharing.Participant>>> =
            await this.shareCenter.changePrivilege(changeUserId, changeBundleName, changeTableName, changeParticipants);
          this.marshallingResults(reply, changeResult);
          return true;
        case ShareOperation.QueryParticipants.valueOf():
          let queryUserId = data.readInt();
          let queryBundleName = data.readString();
          let queryTableName = data.readString();
          let queryResult: Result<Array<Participant>> =
            await this.shareCenter.queryParticipants(queryUserId, queryBundleName, queryTableName);
          this.marshallingResultsArray(reply, queryResult);
          return true;
        case ShareOperation.QueryParticipantsByInvitation.valueOf():
          let inviteUserId = data.readInt();
          let inviteBundleName = data.readString();
          let inviteTableName = data.readString();
          let inviteQueryResult: Result<Array<Participant>> =
            await this.shareCenter.queryParticipantsByInvitation(inviteUserId, inviteBundleName, inviteTableName);
          this.marshallingResultsArray(reply, inviteQueryResult);
          return true;
        case ShareOperation.ConfirmInvitation.valueOf():
          let confirmUserId: int = data.readInt();
          let confirmBundleName = data.readString();
          let confirmTableName = data.readString();
          let confirmStatus: cloudData.sharing.State = this.toState(data.readInt());
          let confirmResult: Result<string> =
            await this.shareCenter.confirmInvitation(confirmUserId, confirmBundleName, confirmTableName, confirmStatus);
          reply.writeInt(confirmResult.code);
          if (confirmResult.description) {
            reply.writeString(confirmResult?.description as string);
          } else {
            reply.writeString(INVALID_STR);
          }
          if (confirmResult.value) {
            reply.writeString(confirmResult?.value as string);
          } else {
            reply.writeString(INVALID_STR);
          }
          return true;
        case ShareOperation.ChangeConfirmation.valueOf():
          let changeConfirmUserId: int = data.readInt();
          let changeConfirmBundleName = data.readString();
          let changeConfirmTableName = data.readString();
          let changeConfirmStatus: cloudData.sharing.State = this.toState(data.readInt());
          let changeConfirmResult: Result<void> =
            await this.shareCenter.changeConfirmation(changeConfirmUserId, changeConfirmBundleName,
              changeConfirmTableName, changeConfirmStatus);
          reply.writeInt(changeConfirmResult.code);
          if (changeConfirmResult.description) {
            reply.writeString(changeConfirmResult?.description as string);
          } else {
            reply.writeString(INVALID_STR);
          }
          return true;
        default:
          break;
      }
      return false;
    }

    unMarshallingParticipants(data: rpc.MessageSequence): Participant[] {
      let participants: Participant[] = [];
      let count = data.readInt();
      if (count < 0 || count > MAX_SIZE) {
        return participants;
      }
      for (let i = 0; i < count; i++) {
        participants.push(this.unMarshallingParticipant(data));
      }
      return participants;
    }

    unMarshallingParticipant(data: rpc.MessageSequence): Participant {
      let identity = data.readString();
      let participant: Participant;
      let role = this.toRole(data.readInt());
      let state = this.toState(data.readInt());
      participant = {
        identity: identity,
        role: role == INVALID_STATE ? undefined : role,
        state: state == INVALID_STATE ? undefined : state,
        privilege: this.unMarshallingPrivilege(data),
        attachInfo: data.readString(),
      };
      return participant;
    }

    toState(value: int): cloudData.sharing.State {
      switch (value) {
        case 0:
          return cloudData.sharing.State.STATE_UNKNOWN;
        case 1:
          return cloudData.sharing.State.STATE_ACCEPTED;
        case 2:
          return cloudData.sharing.State.STATE_REJECTED;
        case 3:
          return cloudData.sharing.State.STATE_SUSPENDED;
        case 4:
          return cloudData.sharing.State.STATE_UNAVAILABLE;
        default:
          return cloudData.sharing.State.STATE_UNKNOWN;
      }
    }

    toRole(value: int): cloudData.sharing.Role {
      switch (value) {
        case 0:
          return cloudData.sharing.Role.ROLE_INVITER;
        case 1:
          return cloudData.sharing.Role.ROLE_INVITEE;
        default:
          return cloudData.sharing.Role.ROLE_INVITER;
      }
    }

    unMarshallingPrivilege(data: rpc.MessageSequence): Privilege {
      let privilege: Privilege;
      privilege = {
        writable: data.readBoolean(),
        readable: data.readBoolean(),
        creatable: data.readBoolean(),
        deletable: data.readBoolean(),
        shareable: data.readBoolean(),
      };
      return privilege;
    }

    marshallingResultsArray(reply: rpc.MessageSequence, result: Result<Array<Participant>>): void {
      reply.writeInt(result.code);
      if (result.description) {
        reply.writeString(result?.description as string);
      } else {
        reply.writeString(INVALID_STR);
      }
      if (result.value) {
        reply.writeInt((result?.value as Array<Participant>).length as int);
        (result?.value as Array<Participant>).forEach((participant: Participant) => {
          this.marshallingParticipant(reply, participant);
        });
      }
    }

    marshallingResults(reply: rpc.MessageSequence, result: Result<Array<Result<Participant>>>): void {
      reply.writeInt(result.code);
      if (result.description) {
        reply.writeString(result?.description as string);
      } else {
        reply.writeString(INVALID_STR);
      }
      if (result?.value) {
        reply.writeInt((result?.value as Array<Result<Participant>>).length as int);
        (result?.value as Array<Result<Participant>>).forEach((item: Result<Participant>) => {
          reply.writeInt(item.code);
          if (item.description) {
            reply.writeString(item.description as string);
          } else {
            reply.writeString(INVALID_STR);
          }
        });
      }
    }

    private getParticipantRoleValue(status: cloudData.sharing.Role | undefined): int {
      if (status === undefined) {
        return cloudData.sharing.Role.ROLE_INVITER
      }
      return status.valueOf();
    }

    private getParticipantStateValue(status: cloudData.sharing.State | undefined): int {
      if (status === undefined) {
        return cloudData.sharing.State.STATE_UNKNOWN
      }
      return status.valueOf();
    }

    marshallingParticipant(reply: rpc.MessageSequence, participant: Participant): void {
      reply.writeString(participant.identity);
      if (typeof participant.role !== 'undefined') {
        reply.writeInt(this.getParticipantRoleValue(participant?.role));
      } else {
        reply.writeInt(-1);
      }
      if (typeof participant.state !== 'undefined') {
        reply.writeInt(this.getParticipantStateValue(participant?.state));
      } else {
        reply.writeInt(-1);
      }
      if (participant.privilege) {
        this.marshallingPrivilege(reply, participant.privilege);
      } else {
        reply.writeBoolean(false);
        reply.writeBoolean(false);
        reply.writeBoolean(false);
        reply.writeBoolean(false);
        reply.writeBoolean(false);
      }
      if (participant.attachInfo) {
        reply.writeString(participant?.attachInfo as string);
      } else {
        reply.writeString(INVALID_STR);
      }
    }

    marshallingPrivilege(reply: rpc.MessageSequence, privilege: Privilege | undefined): void {
      reply.writeBoolean(privilege?.writable as boolean);
      reply.writeBoolean(privilege?.readable as boolean);
      reply.writeBoolean(privilege?.creatable as boolean);
      reply.writeBoolean(privilege?.deletable as boolean);
      reply.writeBoolean(privilege?.shareable as boolean);
    }
  }

  export async function createCloudServiceStub(cloudService: CloudService): Promise<CloudServiceStub> {
    return new CloudServiceStub("CloudServiceStub", cloudService);
  }

  export async function createCloudDBStub(cloudDb: cloudExtension.CloudDB): Promise<CloudDbStub> {
    return new CloudDbStub("CloudDbProxy", cloudDb);
  }

  export async function createAssetLoaderStub(assetLoader: cloudExtension.AssetLoader): Promise<AssetLoaderStub> {
    return new AssetLoaderStub("AssetLoaderProxy", assetLoader);
  }

  export async function createShareServiceStub(shareCenter: ShareCenter): Promise<ShareCenterProxy> {
    return new ShareCenterProxy('ShareCenterProxy', shareCenter);
  }

}

export default cloudExtension;