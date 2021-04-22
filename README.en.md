# distributeddatamgr_appdatamgr

-[Introduction](#section11660541593)
-[Contents](#section1464106163817)
-[Constraints](#section1718733212019)
-[Software Architecture](#section159991817144514)
-[Interface](#section11510542164514)
-[Use](#section1685211117463)
-[Involving warehouse](#section10365113863719)

## Introduction<a name="section11660541593"></a>
Data management services provide applications and users with more convenient, efficient and safe data management capabilities. Reduce development costs and create a consistent and smooth user experience across devices.
> Currently, it first supports lightweight key-value (KV) local data storage capabilities, and will gradually support other richer data types in the future.
![输入图片说明](https://images.gitee.com/uploads/images/2021/0422/193406_a3e03a96_8046977.png "屏幕截图.png")
>-Lightweight key-value (KV) data: The data is structured, the file is lightweight, and transactional, and a dedicated key-value pair interface is provided separately
The lightweight KV database is developed based on the KV storage capabilities provided by the current public basic library, and provides key-value pair parameter management capabilities for applications. On platforms with processes, KV storage provides parameter management for single process access and cannot be used by other applications. On such platforms, KV storage is loaded in the application process as a basic library to protect it from being accessed by other processes.

Distributed data management services on different platforms form an abstract layer of data operation interfaces for unified file operations, so that manufacturers do not need to pay attention to the differences in file systems of different chip platforms.

## Table of Contents<a name="section1464106163817"></a>
> To be added after the code is developed

## Constraints<a name="section1718733212019"></a>
### Lightweight key value (KV) data
Since the dependent platform has normal file creation, read/write, delete, modify, and lock capabilities, the semantic functions of the interface should remain unchanged for different platforms as much as possible. Due to the difference in platform capabilities, database capabilities need to be tailored, and the internal implementation of different platforms may be different.

## Software Architecture<a name="section159991817144514"></a>
### Lightweight key value (KV) data
The KV storage capacity is inherited from the original design of the public basic library, and is enhanced on the basis of the original capacity. The addition of data deletion and binary value reading and writing capabilities are added to ensure the atomicity of the operation; in order to distinguish between platform differences, it will rely on the content of platform differences Separate abstraction, provided by the corresponding product platform.
>LO devices generally have poor performance, insufficient memory and computing capabilities, and most data management scenarios read more and write less, and are sensitive to memory usage;
>The KV implemented for some platforms has a lock mechanism, but the lock is only effective for the cache and not for file operations. The file operation interface used by the platform is provided by the system. Generally, the file operation interface itself is not process safe, please be extra note;
>LO platform, there is no lock capability, no lock mechanism is provided, and the concurrency is guaranteed by the business. If a lock mechanism needs to be provided, it needs to provide a hook and register by the business.

## Interface<a name="section11510542164514"></a>
> To be added after the code is developed

## Use <a name="section1685211117463"></a>
> To be added after the code is developed

## Involved warehouse<a name="section10365113863719"></a>
distributeddatamgr_appdatamgr
