/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

const TAG = 'cloudExtension';
const INVALID_STATE = -1;
const INVALID_STR = '';
const MAX_SIZE = 4 * 1024 * 1024 * 1024 - 1;

export namespace cloudExtension {
  export enum FieldType {
    NULL = 0,
    NUMBER = 1,
    REAL = 2,
    TEXT = 3,
    BOOL = 4,
    BLOB = 5,
    ASSET = 6,
    ASSETS = 7
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

  export class CloudServiceStub extends rpc.RemoteObject {
    private cloudService: ESObject;

    constructor(descriptor: string, cloudService: ESObject) {
      super(descriptor);
      this.cloudService = cloudService;
    }

    async onRemoteMessageRequest(code: number, data: rpc.MessageSequence, reply: rpc.MessageSequence,
      option: rpc.MessageOption): Promise<boolean> {
      option.setWaitTime(1000);
      let descriptor = this.getDescriptor();
      switch (code) {
        case ServiceOperation.GetServiceInfo:
          let serviceInfo: ESObject = await this.cloudService.getServiceInfo();
          this.marshallingCloudInfo(reply, serviceInfo);
          return true;
        case ServiceOperation.GetAppBriefInfo:
          let appBriefInfo: ESObject = await this.cloudService.getAppBriefInfo();
          this.marshallingAppBriefInfo(reply, appBriefInfo);
          return true;
        case ServiceOperation.GetAppSchema:
          let bundleName = data.readString();
          let appSchema: ESObject = await this.cloudService.getAppSchema(bundleName);
          reply.writeInt(appSchema.code);
          if (appSchema.code === ErrorCode.SUCCESS) {
            this.marshallingAppSchema(reply, appSchema.value);
          }
          return true;
        case ServiceOperation.Subscribe:
          let tokenId = data.readLong();
          let subInfo: ESObject = this.unMarshallingSubInfo(data);
          let subscribeResult: ESObject = await this.cloudService.subscribe(subInfo, tokenId);
          reply.writeInt(subscribeResult.code);
          if (subscribeResult.code === ErrorCode.SUCCESS) {
            this.marshallingSubscribeInfo(reply, subscribeResult.value);
          }
          return true;
        case ServiceOperation.Unsubscribe:
          let unsubInfo: ESObject = this.unMarshallingUnSubInfo(data);
          let unsubscribeResult: ESObject = await this.cloudService.unsubscribe(unsubInfo);
          reply.writeInt(unsubscribeResult > 0 ? ErrorCode.SUCCESS : ErrorCode.UNKNOWN_ERROR);
          return true;
        case ServiceOperation.ConnectDatabase:
          let dbName = data.readString();
          let dbInfo: ESObject = this.unMarshallingDatabase(data);
          let dbConnection: ESObject = await this.cloudService.connectDB(dbName, dbInfo);
          reply.writeRemoteObject(dbConnection);
          return true;
        case ServiceOperation.ConnectAssetLoader:
          let assetLoaderName = data.readString();
          let assetLoaderInfo: ESObject = this.unMarshallingDatabase(data);
          let assetLoaderConnection: ESObject =
            await this.cloudService.connectAssetLoader(assetLoaderName, assetLoaderInfo);
          reply.writeRemoteObject(assetLoaderConnection);
          return true;
        case ServiceOperation.ConnectShareCenter:
          let userId = data.readInt();
          let shareCenterName = data.readString();
          let shareCenterConnection: ESObject = await this.cloudService.connectShareCenter(userId, shareCenterName);
          if (shareCenterConnection == null) {
            return false;
          }
          reply.writeRemoteObject(shareCenterConnection);
          return true;
        default:
          false;
      }

      return false;
    }

    private marshallingCloudInfo(reply: rpc.MessageSequence, cloudInfo: ESObject): void {
      reply.writeBoolean(cloudInfo.enableCloud);
      reply.writeString(cloudInfo.id);
      reply.writeLong(cloudInfo.totalSpace);
      reply.writeLong(cloudInfo.remainingSpace);
      reply.writeInt(cloudInfo.user);
    }

    private marshallingAppBriefInfo(reply: rpc.MessageSequence, appBriefInfo: ESObject): void {
      let keys = Object.keys(appBriefInfo);
      reply.writeInt(keys.length);
      keys.forEach(key => {
        reply.writeString(key);
        let appInfo: ESObject = appBriefInfo[key];
        reply.writeString(appInfo.appId);
        reply.writeString(appInfo.bundleName);
        reply.writeInt(appInfo.cloudSwitch ? 1 : 0);
        reply.writeInt(appInfo.instanceId);
      });
    }

    private marshallingAppSchema(reply: rpc.MessageSequence, appSchema: ESObject): void {
      reply.writeInt(appSchema.version);
      reply.writeString(appSchema.bundleName);
      reply.writeInt(appSchema.databases.length);
      appSchema.databases.forEach((database: ESObject) => {
        reply.writeString(database.alias);
        reply.writeString(database.name);
        reply.writeInt(database.tables.length);
        database.tables.forEach((table: ESObject) => {
          reply.writeString(table.alias);
          reply.writeString(table.name);
          reply.writeInt(table.fields.length);
          table.fields.forEach((field: ESObject) => {
            reply.writeString(field.alias);
            reply.writeString(field.colName);
            reply.writeInt(field.type);
            reply.writeBoolean(field.primary);
            reply.writeBoolean(field.nullable);
          });
        });
      });
    }

    private unMarshallingSubInfo(data: rpc.MessageSequence): ESObject {
      let key = data.readString();
      let subInfo: ESObject = {};
      let count = data.readInt();
      subInfo[key] = [];
      if (count < 0 || count > MAX_SIZE) {
        return subInfo;
      }
      for (let i = 0; i < count; i++) {
        subInfo[key].push(this.unMarshallingDatabase(data));
      }
      return subInfo;
    }

    private unMarshallingDatabase(data: rpc.MessageSequence): ESObject {
      let database: ESObject = {
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
        let table: ESObject = {
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
          let field: ESObject = {
            alias: data.readString(),
            colName: data.readString(),
            type: data.readInt(),
            primary: data.readBoolean(),
            nullable: data.readBoolean()
          };
          database.tables[i].fields.push(field);
        }
      }
      return database;
    }

    private marshallingSubscribeInfo(reply: rpc.MessageSequence, subscribeInfo: ESObject): void {
      reply.writeLong(subscribeInfo.expirationTime);
      let keys = Object.keys(subscribeInfo.subscribe);
      reply.writeInt(keys.length);
      keys.forEach(key => {
        reply.writeString(key);
        let subscriptions: ESObject = subscribeInfo.subscribe[key];
        reply.writeInt(subscriptions.length);
        subscriptions.forEach((subscription: ESObject) => {
          reply.writeString(subscription.databaseAlias);
          reply.writeString(subscription.id);
        });
      });
    }

    private unMarshallingUnSubInfo(data: rpc.MessageSequence): ESObject {
      let unsubInfo: ESObject = {};
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
          unsubInfo[key].push(data.readString());
        }
      }
      return unsubInfo;
    }
  }

  export class CloudDbStub extends rpc.RemoteObject {
    private cloudDb: ESObject;

    constructor(descriptor: string, cloudDb: ESObject) {
      super(descriptor);
      this.cloudDb = cloudDb;
    }

    async onRemoteMessageRequest(code: number, data: rpc.MessageSequence, reply: rpc.MessageSequence,
      option: rpc.MessageOption): Promise<boolean> {
      if (this.cloudDb === undefined) {
        return false;
      }
      let descriptor = this.getDescriptor();
      option.setWaitTime(1500);
      switch (code) {
        case DatabaseOperation.GenerateIds:
          let count = data.readInt();
          let idsResult: ESObject = await this.cloudDb.generateId(count);
          reply.writeInt(idsResult.code);
          if (idsResult.code === 0) {
            reply.writeInt(idsResult.value.length);
            idsResult.value.forEach((id: string) => {
              reply.writeString(id);
            });
          }
          return true;
        case DatabaseOperation.Insert:
          let tableName = data.readString();
          let values: ESObject = this.unMarshallingValuesBuckets(data);
          let assets: ESObject = this.unMarshallingValuesBuckets(data);
          if (values.length === 0) {
            reply.writeInt(0);
            return true;
          }
          try {
            let insertResult: ESObject = await this.cloudDb.insert(tableName, values, assets);
            this.marshallingResultValueBucket(reply, insertResult);
          } catch (error) {
            reply.writeInt(ErrorCode.UNKNOWN_ERROR);
          }
          return true;
        case DatabaseOperation.Update:
          let updateTableName = data.readString();
          let updateValues: ESObject = this.unMarshallingValuesBuckets(data);
          let updateAssets: ESObject = this.unMarshallingValuesBuckets(data);
          try {
            let updateResult: ESObject = await this.cloudDb.update(updateTableName, updateValues, updateAssets);
            this.marshallingResultValueBucket(reply, updateResult);
          } catch (error) {
            reply.writeInt(ErrorCode.UNKNOWN_ERROR);
          }
          return true;
        case DatabaseOperation.Delete:
          let deleteTableName = data.readString();
          let deleteValues: ESObject = this.unMarshallingValuesBuckets(data);
          try {
            let deleteResult: ESObject = await this.cloudDb.delete(deleteTableName, deleteValues);
            this.marshallingResultValueBucket(reply, deleteResult);
          } catch (error) {
            reply.writeInt(ErrorCode.UNKNOWN_ERROR);
          }
          return true;
        case DatabaseOperation.Query:
          let queryTableName = data.readString();
          let queryFields = this.unMarshallingFiledArray(data);
          let queryLimit = data.readInt();
          let queryCursor = data.readString();
          if (queryCursor === '') {
            queryCursor = '0';
          }
          try {
            let queryResult: ESObject = await this.cloudDb.query(queryTableName, queryFields, queryLimit, queryCursor);
            reply.writeInt(queryResult.code);
            if (queryResult.code === 0) {
              this.marshallingCloudData(reply, queryResult.value);
            }
          } catch (error) {
            reply.writeInt(ErrorCode.UNKNOWN_ERROR);
          }
          return true;
        case DatabaseOperation.Lock:
          let lockResult: ESObject = await this.cloudDb.lock();
          reply.writeInt(lockResult.code);
          if (lockResult.code === 0) {
            reply.writeInt(lockResult.value.interval);
            reply.writeInt(lockResult.value.lockId);
          }
          return true;
        case DatabaseOperation.Heartbeat:
          let lockId = data.readInt();
          let heartbeatResult: ESObject = await this.cloudDb.heartbeat(lockId);
          reply.writeInt(heartbeatResult.code);
          if (heartbeatResult.code === 0) {
            reply.writeInt(heartbeatResult.value.interval);
            reply.writeInt(heartbeatResult.value.lockId);
          }
          return true;
        case DatabaseOperation.Unlock:
          let unlockLockId = data.readInt();
          let unlockResult: ESObject = await this.cloudDb.unlock(unlockLockId);
          reply.writeInt(unlockResult.code);
          if (unlockResult.code === 0) {
            reply.writeBoolean(unlockResult.value);
          }
          return true;
        default:
          break;
      }
      return false
    }

    private unMarshallingFiledArray(data: rpc.MessageSequence): string[] {
      let fields: string[] = [];
      let count = data.readInt();
      if (count < 0 || count > MAX_SIZE) {
        return fields;
      }
      for (let i = 0; i < count; i++) {
        fields.push(data.readString());
      }
      return fields;
    }

    private marshallingCloudData(reply: rpc.MessageSequence, cloudData: ESObject): void {
      reply.writeString(cloudData.nextCursor);
      reply.writeBoolean(cloudData.hasMore);
      this.marshallingValuesBuckets(reply, cloudData.values);
    }

    private marshallingResultValueBucket(reply: rpc.MessageSequence, result: ESObject[]): void {
      if (result.length > MAX_SIZE) {
        return;
      }
      reply.writeInt(result.length);
      for (let i = 0; i < result.length; i++) {
        reply.writeInt(result[i].code);
        if (result[i].value) {
          let value: ESObject = result[i].value;
          this.marshallingValueBucket(reply, value);
        } else {
          reply.writeInt(0);
        }
      }
    }

    private marshallingValueBucket(reply: rpc.MessageSequence, valueBucket: ESObject): void {
      let keys = Object.keys(valueBucket);
      reply.writeInt(keys.length);
      keys.forEach(key => {
        reply.writeString(key);
        let value: ESObject = valueBucket[key];
        if (value === undefined || value === null) {
          reply.writeInt(FieldType.NULL);
        } else {
          if (typeof value === 'number') {
            if (Number(value).toString().indexOf('.') !== -1) {
              reply.writeInt(FieldType.REAL);
              reply.writeFloat(value);
            } else {
              reply.writeInt(FieldType.NUMBER);
              reply.writeLong(value);
            }
          } else if (typeof value === 'string') {
            reply.writeInt(FieldType.TEXT);
            reply.writeString(value);
          } else if (typeof value === 'boolean') {
            reply.writeInt(FieldType.BOOL);
            reply.writeBoolean(value);
          } else {
            if (value instanceof Array) {
              reply.writeInt(FieldType.ASSETS);
              reply.writeInt(value.length);
              value.forEach((asset: ESObject) => {
                reply.writeString(asset.name);
                reply.writeString(asset.uri);
                reply.writeString(asset.path);
                reply.writeString(asset.createTime);
                reply.writeString(asset.modifyTime);
                reply.writeString(asset.size);
                if (asset.status) {
                  reply.writeInt(asset.status);
                } else {
                  reply.writeInt(relationalStore.AssetStatus.ASSET_NORMAL);
                }
                reply.writeString(asset.assetId);
                reply.writeString(asset.hash);
              });
            } else if (value instanceof Uint8Array) {
              reply.writeInt(FieldType.BLOB);
              let array: number[] = [];
              for (let i = 0; i < value.length; i++) {
                array.push(value[i]);
              }
              reply.writeIntArray(array);
            } else {
              reply.writeInt(FieldType.ASSET);
              reply.writeString(value.name);
              reply.writeString(value.uri);
              reply.writeString(value.path);
              reply.writeString(value.createTime);
              reply.writeString(value.modifyTime);
              reply.writeString(value.size);
              if (value.status) {
                reply.writeInt(value.status);
              } else {
                reply.writeInt(relationalStore.AssetStatus.ASSET_NORMAL);
              }
              reply.writeString(value.assetId);
              reply.writeString(value.hash);
            }
          }
        }
      });
    }

    private marshallingValuesBuckets(reply: rpc.MessageSequence, valueBuckets: ESObject[]): void {
      if (valueBuckets.length > MAX_SIZE) {
        return;
      }
      reply.writeInt(valueBuckets.length);
      for (let i = 0; i < valueBuckets.length; i++) {
        this.marshallingValueBucket(reply, valueBuckets[i]);
      }
    }

    private unMarshallingValuesBuckets(data: rpc.MessageSequence): ESObject[] {
      let count = data.readInt();
      let valueBuckets: ESObject[] = [];
      if (count < 0 || count > MAX_SIZE) {
        return valueBuckets;
      }
      for (let i = 0; i < count; i++) {
        valueBuckets.push(this.unMarshallingValuesBucket(data));
      }
      return valueBuckets;
    }

    private unMarshallingValuesBucket(data: rpc.MessageSequence): ESObject {
      let valueBucket: ESObject = {};
      let count = data.readInt();
      if (count < 0 || count > MAX_SIZE) {
        return valueBucket;
      }
      for (let i = 0; i < count; i++) {
        let key = data.readString();
        let value: ESObject = this.unMarshallingValueType(data);
        valueBucket[key] = value;
      }
      return valueBucket;
    }

    private unMarshallingValueType(data: rpc.MessageSequence): ESObject {
      let type = data.readInt();
      switch (type) {
        case FieldType.NULL: // null
          return null;
        case FieldType.NUMBER: // number
          return data.readLong();
        case FieldType.REAL: // number
          return data.readFloat();
        case FieldType.TEXT: // string
          return data.readString();
        case FieldType.BOOL: // boolean
          return data.readBoolean();
        case FieldType.BLOB: // Uint8Array
          return Uint8Array.from(data.readIntArray());
        case FieldType.ASSET: // Asset
          return {
            name: data.readString(),
            uri: data.readString(),
            path: data.readString(),
            createTime: data.readString(),
            modifyTime: data.readString(),
            size: data.readString(),
            status: data.readInt(),
            assetId: data.readString(),
            hash: data.readString(),
          };
        case FieldType.ASSETS: // Assets
          let assetCount = data.readInt();
          let assets: ESObject[] = [];
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
              status: data.readInt(),
              assetId: data.readString(),
              hash: data.readString(),
            });
          }
          return assets;
      }
      return null;
    }
  }


  export class AssetLoaderStub extends rpc.RemoteObject {
    private assetLoader: ESObject;

    constructor(descriptor: string, assetLoader: ESObject) {
      super(descriptor);
      this.assetLoader = assetLoader;
    }

    async onRemoteMessageRequest(code: number, data: rpc.MessageSequence, reply: rpc.MessageSequence,
      option: rpc.MessageOption): Promise<boolean> {
      option.setWaitTime(500);
      let descriptor = this.getDescriptor();
      let tableName = data.readString();
      let assetId = data.readString();
      let localPath = data.readString();
      switch (code) {
        case AssetOperation.Download:
          let downloadAssets: ESObject = this.unmarshallingAssets(data);
          let downloadResult: ESObject = await this.assetLoader.download(tableName, assetId, localPath, downloadAssets);
          this.marshallingAssets(reply, downloadResult);
          return true;
        case AssetOperation.Upload:
          let uploadAssets: ESObject = this.unmarshallingAssets(data);
          let uploadResult: ESObject = await this.assetLoader.upload(tableName, assetId, uploadAssets);
          this.marshallingAssets(reply, uploadResult);
          return true;
      }
      return false;
    }

    private unmarshallingAssets(data: rpc.MessageSequence): ESObject[] {
      let count = data.readInt();
      let assets: ESObject[] = [];
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
          status: data.readInt(),
          assetId: data.readString(),
          hash: data.readString()
        });
      }
      return assets;
    }

    private marshallingAssets(reply: rpc.MessageSequence, assets: ESObject[]): void {
      reply.writeInt(assets.length);
      if (assets.length > MAX_SIZE) {
        return;
      }
      for (let i = 0; i < assets.length; i++) {
        reply.writeInt(assets[i].code);
        reply.writeString(assets[i].value.name);
        reply.writeString(assets[i].value.uri);
        reply.writeString(assets[i].value.path);
        reply.writeString(assets[i].value.createTime);
        reply.writeString(assets[i].value.modifyTime);
        reply.writeString(assets[i].value.size);
        reply.writeInt(assets[i].value.status);
        reply.writeString(assets[i].value.assetId);
        reply.writeString(assets[i].value.hash);
      }
    }
  }

  export class ShareCenterProxy extends rpc.RemoteObject {
    private shareCenter: ESObject;

    constructor(descriptor: string, shareCenter: ESObject) {
      super(descriptor);
      this.shareCenter = shareCenter;
    }

    async onRemoteMessageRequest(code: number, data: rpc.MessageSequence, reply: rpc.MessageSequence, option: rpc.MessageOption): Promise<boolean> {
      if (this.shareCenter == undefined) {
        return false;
      }
      option.setWaitTime(1500);
      switch (code) {
        case ShareOperation.Share:
          let userId = data.readInt();
          let bundleName = data.readString();
          let tableName = data.readString();
          let participants: ESObject = this.unMarshallingParticipants(data);
          let shareResult: ESObject = await this.shareCenter.share(userId, bundleName, tableName, participants);
          this.marshallingResults(reply, shareResult);
          return true;
        case ShareOperation.Unshare:
          let unshareUserId = data.readInt();
          let unshareBundleName = data.readString();
          let unshareTableName = data.readString();
          let unshareParticipants: ESObject = this.unMarshallingParticipants(data);
          let unshareResult: ESObject =
            await this.shareCenter.unshare(unshareUserId, unshareBundleName, unshareTableName, unshareParticipants);
          this.marshallingResults(reply, unshareResult);
          return true;
        case ShareOperation.Exit:
          let exitUserId = data.readInt();
          let exitBundleName = data.readString();
          let exitTableName = data.readString();
          let exitResult: ESObject = await this.shareCenter.exit(exitUserId, exitBundleName, exitTableName);
          reply.writeInt(exitResult.code);
          if (exitResult.description) {
            reply.writeString(exitResult.description);
          } else {
            reply.writeString(INVALID_STR);
          }
          return true;
        case ShareOperation.ChangePrivilege:
          let changeUserId = data.readInt();
          let changeBundleName = data.readString();
          let changeTableName = data.readString();
          let changeParticipants: ESObject = this.unMarshallingParticipants(data);
          let changeResult: ESObject =
            await this.shareCenter.changePrivilege(changeUserId, changeBundleName, changeTableName, changeParticipants);
          this.marshallingResults(reply, changeResult);
          return true;
        case ShareOperation.QueryParticipants:
          let queryUserId = data.readInt();
          let queryBundleName = data.readString();
          let queryTableName = data.readString();
          let queryResult: ESObject =
            await this.shareCenter.queryParticipants(queryUserId, queryBundleName, queryTableName);
          this.marshallingResultsArray(reply, queryResult);
          return true;
        case ShareOperation.QueryParticipantsByInvitation:
          let inviteUserId = data.readInt();
          let inviteBundleName = data.readString();
          let inviteTableName = data.readString();
          let inviteQueryResult: ESObject =
            await this.shareCenter.queryParticipantsByInvitation(inviteUserId, inviteBundleName, inviteTableName);
          this.marshallingResultsArray(reply, inviteQueryResult);
          return true;
        case ShareOperation.ConfirmInvitation:
          let confirmUserId = data.readInt();
          let confirmBundleName = data.readString();
          let confirmTableName = data.readString();
          let confirmStatus = data.readInt();
          let confirmResult: ESObject =
            await this.shareCenter.confirmInvitation(confirmUserId, confirmBundleName, confirmTableName, confirmStatus);
          reply.writeInt(confirmResult.code);
          if (confirmResult.description) {
            reply.writeString(confirmResult.description);
          } else {
            reply.writeString(INVALID_STR);
          }
          if (confirmResult.value) {
            reply.writeString(confirmResult.value);
          } else {
            reply.writeString(INVALID_STR);
          }
          return true;
        case ShareOperation.ChangeConfirmation:
          let changeConfirmUserId = data.readInt();
          let changeConfirmBundleName = data.readString();
          let changeConfirmTableName = data.readString();
          let changeConfirmStatus = data.readInt();
          let changeConfirmResult: ESObject =
            await this.shareCenter.changeConfirmation(changeConfirmUserId, changeConfirmBundleName,
              changeConfirmTableName, changeConfirmStatus);
          reply.writeInt(changeConfirmResult.code);
          if (changeConfirmResult.description) {
            reply.writeString(changeConfirmResult.description);
          } else {
            reply.writeString(INVALID_STR);
          }
          return true;
        default:
          break;
      }
      return false;
    }

    private unMarshallingParticipants(data: rpc.MessageSequence): ESObject[] {
      let participants: ESObject[] = [];
      let count = data.readInt();
      if (count < 0 || count > MAX_SIZE) {
        return participants;
      }
      for (let i = 0; i < count; i++) {
        participants.push(this.unMarshallingParticipant(data));
      }
      return participants;
    }


    private unMarshallingParticipant(data: rpc.MessageSequence): ESObject {
      let identity = data.readString();
      let participant: ESObject;
      let role = data.readInt();
      let state = data.readInt();
      participant = {
        identity: identity,
        role: role == INVALID_STATE ? undefined : role,
        state: state == INVALID_STATE ? undefined : state,
        privilege: this.unMarshallingPrivilege(data),
        attachInfo: data.readString(),
      };
      return participant;
    }

    private unMarshallingPrivilege(data: rpc.MessageSequence): ESObject {
      let privilege: ESObject;
      privilege = {
        writable: data.readBoolean(),
        readable: data.readBoolean(),
        creatable: data.readBoolean(),
        deletable: data.readBoolean(),
        shareable: data.readBoolean(),
      };
      return privilege;
    }

    private marshallingResultsArray(reply: rpc.MessageSequence, result: ESObject): void {
      reply.writeInt(result.code);
      if (result.description) {
        reply.writeString(result.description);
      } else {
        reply.writeString(INVALID_STR);
      }
      if (result.value) {
        reply.writeInt(result.value.length);
        result.value.forEach((participant: ESObject) => {
          this.marshallingParticipant(reply, participant);
        });
      }
    }

    private marshallingResults(reply: rpc.MessageSequence, result: ESObject): void {
      reply.writeInt(result.code);
      if (result.description) {
        reply.writeString(result.description);
      } else {
        reply.writeString(INVALID_STR);
      }
      if (result.value) {
        reply.writeInt(result.value.length);
        result.value.forEach((item: ESObject) => {
          reply.writeInt(item.code);
          if (item.description) {
            reply.writeString(item.description);
          } else {
            reply.writeString(INVALID_STR);
          }
        });
      }
    }

    private marshallingParticipant(reply: rpc.MessageSequence, participant: ESObject): void {
      reply.writeString(participant.identity);
      if (typeof participant.role !== 'undefined') {
        reply.writeInt(participant.role);
      } else {
        reply.writeInt(-1);
      }
      if (typeof participant.state !== 'undefined') {
        reply.writeInt(participant.state);
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
        reply.writeString(participant.attachInfo);
      } else {
        reply.writeString(INVALID_STR);
      }
    }

    private marshallingPrivilege(reply: rpc.MessageSequence, privilege: ESObject): void {
      reply.writeBoolean(privilege.writable);
      reply.writeBoolean(privilege.readable);
      reply.writeBoolean(privilege.creatable);
      reply.writeBoolean(privilege.deletable);
      reply.writeBoolean(privilege.shareable);
    }
  }


  export async function createCloudServiceStub(cloudService: ESObject): Promise<CloudServiceStub> {
    return new CloudServiceStub("CloudServiceProxy", cloudService);
  }

  export async function createCloudDBStub(cloudDb: ESObject): Promise<CloudDbStub> {
    return new CloudDbStub("CloudDbProxy", cloudDb);
  }

  export async function createAssetLoaderStub(assetLoader: ESObject): Promise<AssetLoaderStub> {
    return new AssetLoaderStub("AssetLoaderProxy", assetLoader);
  }

  export async function createShareServiceStub(shareCenter: ESObject): Promise<ShareCenterProxy> {
    return new ShareCenterProxy('ShareCenterProxy', shareCenter);
  }

}