# distributeddatamgr_appdatamgr

- [Introduction](#section11660541593)
- [Contents](#section1464106163817)
- [Constraints](#section1718733212019)
- [Software Architecture](#section159991817144514)
- [Interface](#section11510542164514)
- [Use](#section1685211117463)
- [Involving warehouse](#section10365113863719)

## Introduction<a name="section11660541593"></a>
Reduce development costs and create a consistent and smooth user experience across devices.

> Currently, it first supports lightweight key-value (KV) local data storage capabilities, and will gradually support other richer data types in the future.

![输入图片说明](https://images.gitee.com/uploads/images/2021/0422/200748_51a0cbd1_8046977.png "屏幕截图.png")

> Lightweight key-value (KV) data: The data is structured, the file is lightweight, and transactional (supported in the future), and a dedicated key-value pair interface is provided separately

The lightweight KV database is developed based on the KV storage capabilities provided by the current public basic library, and provides key-value pair parameter management capabilities for applications. On a platform with processes, the parameter management provided by KV storage is for single process access and cannot be used by other processes. On such platforms, KV storage is loaded in the application process as a basic library to protect it from being accessed by other processes.

Distributed data management services on different platforms form an abstract layer of data operation interfaces for unified file operations, so that manufacturers do not need to pay attention to the differences in file systems of different chip platforms.

## Table of Contents<a name="section1464106163817"></a>
> To be added after the code is developed

## Constraints<a name="section1718733212019"></a>
### Lightweight key value (KV) data
-Relying on the platform to have normal file creation, reading, writing, deleting, modifying, and locking capabilities, and to show the same semantic functions of the interface as possible for different platforms
-Due to the difference in platform capabilities, database capabilities need to be tailored accordingly, and the internal implementation of different platforms may be different

## Software Architecture<a name="section159991817144514"></a>
### Lightweight key value (KV) data
The KV storage capacity is inherited from the original design of the public basic library, and is enhanced on the basis of the original capacity. The addition of data deletion and binary value reading and writing capabilities are added to ensure the atomicity of the operation; in order to distinguish between platform differences, it will rely on the content of platform differences Separate abstraction, provided by the corresponding product platform.
>- LO equipment generally has poor performance, insufficient memory and computing power, and most data management scenarios read more and write less, and are sensitive to memory usage;
>- The KV implemented for some platforms has a lock mechanism, but the lock is only effective for the cache and not for file operations. The file operation interface used by the platform is provided by the system. Generally speaking, the file operation interface itself is not process safe. Please Pay extra attention
>- On the LO platform, there is no lock capability and no lock mechanism is provided. Concurrency is guaranteed by the business. If a lock mechanism needs to be provided, this needs to provide a hook and register by the business.

## Interface<a name="section11510542164514"></a>
- **lite KV store**

    ```
    typedef struct DBM *KVStoreHandle;
    // storeFullPath is a legitimate directory, and the KV created will have created entries for this directory
    // empty string is passed in and created with the current directory
    int DBM_GetKVStore(const char* storeFullPath, KVStoreHandle* kvStore);

    int DBM_Get(KVStoreHandle db, const char* key, void* value, unsigned int count, unsigned int* realValueLen);
    int DBM_Put(KVStoreHandle db, const char* key, void* value, unsigned int len);
    int DBM_Delete(KVStoreHandle db, const char* key);

    int DBM_CloseKVStore(KVStoreHandle db);
    // Make sure that all database objects for the directory are closed before deleting the database
    int DBM_DeleteKVStore(const char* storeFullPath);

## Use <a name="section1685211117463"></a>
- **lite KV store**

    ```
    // create or open the kvStore
    const char storeFullPath[] = "";  // legal dir path or empty
    KVStoreHandle kvStore = NULL;
    int ret = DBM_GetKVStore(storeFullPath, &kvStore);

    // insert or update data
    char key[] = "rw.sys.version";
    struct {
        int num;
        char content[200];
    } value;
    memset_s(&value, sizeof(value), 0, sizeof(value));
    value.num = 1;
    strcpy_s(value.content, sizeof(value.content), "Hello world !");
    ret = DBM_Put(kvStore, key, (void*)&value, sizeof(value));

    // read KV data
    memset_s(&value, sizeof(value), 0, sizeof(value));
    unsigned int realValLen = 0;
    ret = DBM_Get(g_KVStoreHandle, key, &value, sizeof(value), &realValLen);

    // delete one KV data item
    ret = DBM_Delete(kvStore, key);

    // close kvstore
    ret = DBM_CloseKVStore(kvStore);

    // delete kvtore and remove all KV
    ret = DBM_DeleteKVStore(storeFullPath);

    ```

## Involved warehouse<a name="section10365113863719"></a>
distributeddatamgr_appdatamgr
