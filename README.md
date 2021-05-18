# distributeddatamgr_appdatamgr

- [Introduction](#section11660541593)
- [Directory Structure](#section1464106163817)
- [Constraints](#section1718733212019)
- [Architecture](#section159991817144514)
- [Available APIs](#section11510542164514)
- [Usage Guidelines](#section1685211117463)
- [Repositories Involved](#section10365113863719)

## Introduction<a name="section11660541593"></a>
The distributed data management service allows you to manage data in a convenient, efficient, and secure way. It reduces development costs and creates a consistent and smooth user experience across devices.

> Currently, it supports storage of local lightweight key-value (KV) pairs. In the future, more data types will be supported.
Lightweight key-value pairs are structured and transaction-related (to be supported in the future). Dedicated APIs related to key-value pairs are provided.

> Lightweight key-value (KV) data: The data is structured, the file is lightweight, and transactional (supported in the future), and a dedicated key-value pair interface is provided separately

![输入图片说明](https://images.gitee.com/uploads/images/2021/0422/200748_51a0cbd1_8046977.png "屏幕截图.png")

The lightweight KV store is developed based on the KV storage capabilities provided by Utils, and provides key-value pair management capabilities for apps. On a platform with processes, the key-value pair management capabilities provided by the KV store can only be accessed by a specific process. On such a platform, the KV store is loaded in the app process as a basic library so that it cannot be accessed by other processes.

The distributed data management service abstracts data operation APIs of different platforms into unified APIs for file operations. In this way, you do not need to pay attention to the file system differences between chip platforms.

## Directory Structure<a name="section1464106163817"></a>
```
foundation/distributeddatamgr/appdatamgr/
└─appdatamgr_lite
    │  BUILD.gn
    │
    ├─dbm_kv_store
    │  │  BUILD.gn
    │  │
    │  ├─inc
    │  │      dbm_def.h
    │  │
    │  ├─innerkits
    │  │      dbm_kv_store.h
    │  │      dbm_kv_store_env.h
    │  │
    │  └─src
    │      ├─kv_store_impl_hal
    │      │      dbm_kv_store.c
    │      │
    │      └─kv_store_impl_posix
    │              dbm_kv_store.c
    │
    └─include
            dbm_config.h
            dbm_errno.h
```

## Constraints<a name="section1718733212019"></a>
### Lightweight Key-Value Pairs
-The platform should have file creation, reading, writing, deletion, modification, and locking capabilities. The semantic functions of APIs should be kept the same for different platforms (such as the LiteOS Cortex-M and LiteOS Cortex-A).
-Due to the differences in platform capabilities, the KV store capabilities need to be tailored accordingly. Internal implementation may be different for different platforms.

## Architecture<a name="section159991817144514"></a>
### Lightweight Key-Value Pairs
The KV store inherits capacities from Utils. In addition, the KV store provides data deletion and binary value reading and writing capabilities while ensuring the atomicity of operations. Capabilities specific to different platforms are abstracted separately and provided by each platform.
>- The mini system generally has poor performance and insufficient memory and computing capabilities. In data management scenarios, reading operations are much more than writing operations, and memory usage is sensitive.、
>- File operation APIs used by a platform are provided by the file system. These APIs are generallynot process-safe.
>- The mini system may have no lock capabilities or lock mechanism. In that case, concurrency is guaranteed by the service. If a lock mechanism is needed, a hook should be registered by the service.

## Available APIs<a name="section11510542164514"></a>
- **Lightweight KV store**

    ```
    typedef struct DBM *KVStoreHandle;
    // storeFullPath is a valid directory. The key-value pairs of the KV store will be stored in this directory.
    // If you pass an empty string, key-value pairs of the KV store will be stored in the current directory.
    int DBM_GetKVStore(const char* storeFullPath, KVStoreHandle* kvStore);
    
    int DBM_Get(KVStoreHandle db, const char* key, void* value, unsigned int count, unsigned int* realValueLen);
    int DBM_Put(KVStoreHandle db, const char* key, void* value, unsigned int len);
    int DBM_Delete(KVStoreHandle db, const char* key);
    
    int DBM_CloseKVStore(KVStoreHandle db);
    // Ensure that all KVStore objects in the specified directory are closed before you delete the KV store.
    int DBM_DeleteKVStore(const char* storeFullPath);

## Usage Guidelines <a name="section1685211117463"></a>
- **Lightweight KV store**

    ```
    // Create or open the kvStore.
    const char storeFullPath[] = "";  // A valid directory or an empty string
    KVStoreHandle kvStore = NULL;
    int ret = DBM_GetKVStore(storeFullPath, &kvStore);
    
    // Insert or update a key-value pair.
    char key[] = "rw.sys.version";
    struct {
        int num;
        char content[200];
    } value;
    memset_s(&value, sizeof(value), 0, sizeof(value));
    value.num = 1;
    strcpy_s(value.content, sizeof(value.content), "Hello world !");
    ret = DBM_Put(kvStore, key, (void*)&value, sizeof(value));
    
    // Read a key-value pair.
    memset_s(&value, sizeof(value), 0, sizeof(value));
    unsigned int realValLen = 0;
    ret = DBM_Get(g_KVStoreHandle, key, &value, sizeof(value), &realValLen);
    
    // Delete a key-value pair.
    ret = DBM_Delete(kvStore, key);
    
    // Close the KV store.
    ret = DBM_CloseKVStore(kvStore);
    
    // Delete the KV store and remove all key-value pairs.
    ret = DBM_DeleteKVStore(storeFullPath);
    
    ```

## Repositories Involved<a name="section10365113863719"></a>
distributeddatamgr_appdatamgr