/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef DATASHARE_EXT_ABILITY_H
#define DATASHARE_EXT_ABILITY_H

#include "extension_base.h"
#include "datashare_values_bucket.h"
#include "datashare_result.h"
#include "datashare_predicates.h"
#include "datashare_abstract_result_set.h"
#include "datashare_operation.h"

namespace OHOS {
namespace AAFwk {
class IDataAbilityObserver;
}
namespace AbilityRuntime {
class Runtime;
}
namespace DataShare {
using namespace AbilityRuntime;
class DataShareExtAbilityContext;
/**
 * @brief Basic datashare extension ability components.
 */
class DataShareExtAbility : public ExtensionBase<DataShareExtAbilityContext> {
public:
    DataShareExtAbility() = default;
    virtual ~DataShareExtAbility() = default;

    /**
     * @brief Init the extension.
     *
     * @param record the extension record.
     * @param application the application info.
     * @param handler the extension handler.
     * @param token the remote token.
     */
    virtual void Init(const std::shared_ptr<AbilityLocalRecord> &record,
        const std::shared_ptr<OHOSApplication> &application,
        std::shared_ptr<AbilityHandler> &handler,
        const sptr<IRemoteObject> &token) override;

    /**
     * @brief Create Extension.
     *
     * @param runtime The runtime.
     * @return The DataShareExtAbility instance.
     */
    static DataShareExtAbility* Create(const std::unique_ptr<Runtime>& runtime);

    /**
     * @brief Obtains the MIME types of files supported.
     *
     * @param uri Indicates the path of the files to obtain.
     * @param mimeTypeFilter Indicates the MIME types of the files to obtain. This parameter cannot be null.
     *
     * @return Returns the matched MIME types. If there is no match, null is returned.
     */
    virtual std::vector<std::string> GetFileTypes(const Uri &uri, const std::string &mimeTypeFilter);

    /**
     * @brief Opens a file in a specified remote path.
     *
     * @param uri Indicates the path of the file to open.
     * @param mode Indicates the file open mode, which can be "r" for read-only access, "w" for write-only access
     * (erasing whatever data is currently in the file), "wt" for write access that truncates any existing file,
     * "wa" for write-only access to append to any existing data, "rw" for read and write access on any existing data,
     *  or "rwt" for read and write access that truncates any existing file.
     *
     * @return Returns the file descriptor.
     */
    virtual int OpenFile(const Uri &uri, const std::string &mode);

    /**
     * @brief This is like openFile, open a file that need to be able to return sub-sections of files，often assets
     * inside of their .hap.
     *
     * @param uri Indicates the path of the file to open.
     * @param mode Indicates the file open mode, which can be "r" for read-only access, "w" for write-only access
     * (erasing whatever data is currently in the file), "wt" for write access that truncates any existing file,
     * "wa" for write-only access to append to any existing data, "rw" for read and write access on any existing
     * data, or "rwt" for read and write access that truncates any existing file.
     *
     * @return Returns the RawFileDescriptor object containing file descriptor.
     */
    virtual int OpenRawFile(const Uri &uri, const std::string &mode);

    /**
     * @brief Inserts a single data record into the database.
     *
     * @param uri Indicates the path of the data to operate.
     * @param value  Indicates the data record to insert. If this parameter is null, a blank row will be inserted.
     *
     * @return Returns the index of the inserted data record.
     */
    virtual int Insert(const Uri &uri, const DataShareValuesBucket &value);

    /**
     * @brief Updates data records in the database.
     *
     * @param uri Indicates the path of data to update.
     * @param value Indicates the data to update. This parameter can be null.
     * @param predicates Indicates filter criteria. You should define the processing logic when this parameter is null.
     *
     * @return Returns the number of data records updated.
     */
    virtual int Update(const Uri &uri, const DataShareValuesBucket &value,
        const DataSharePredicates &predicates);

    /**
     * @brief Deletes one or more data records from the database.
     *
     * @param uri Indicates the path of the data to operate.
     * @param predicates Indicates filter criteria. You should define the processing logic when this parameter is null.
     *
     * @return Returns the number of data records deleted.
     */
    virtual int Delete(const Uri &uri, const DataSharePredicates &predicates);

    /**
     * @brief Deletes one or more data records from the database.
     *
     * @param uri Indicates the path of data to query.
     * @param columns Indicates the columns to query. If this parameter is null, all columns are queried.
     * @param predicates Indicates filter criteria. You should define the processing logic when this parameter is null.
     *
     * @return Returns the query result.
     */
    virtual std::shared_ptr<DataShareAbstractResultSet> Query(
        const Uri &uri, std::vector<std::string> &columns, const DataSharePredicates &predicates);

    /**
     * @brief Obtains the MIME type matching the data specified by the URI of the Data ability. This method should be
     * implemented by a Data ability. Data abilities supports general data types, including text, HTML, and JPEG.
     *
     * @param uri Indicates the URI of the data.
     *
     * @return Returns the MIME type that matches the data specified by uri.
     */
    virtual std::string GetType(const Uri &uri);

    /**
     * @brief Inserts multiple data records into the database.
     *
     * @param uri Indicates the path of the data to operate.
     * @param values Indicates the data records to insert.
     *
     * @return Returns the number of data records inserted.
     */
    virtual int BatchInsert(const Uri &uri, const std::vector<DataShareValuesBucket> &values);

    /**
     * @brief Registers an observer to DataObsMgr specified by the given Uri.
     *
     * @param uri, Indicates the path of the data to operate.
     * @param dataObserver, Indicates the IDataAbilityObserver object.
     */
    virtual bool RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver);

    /**
     * @brief Deregisters an observer used for DataObsMgr specified by the given Uri.
     *
     * @param uri, Indicates the path of the data to operate.
     * @param dataObserver, Indicates the IDataAbilityObserver object.
     */
    virtual bool UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver);

    /**
     * @brief Notifies the registered observers of a change to the data resource specified by Uri.
     *
     * @param uri, Indicates the path of the data to operate.
     *
     * @return Return true if success. otherwise return false.
     */
    virtual bool NotifyChange(const Uri &uri);

    /**
     * @brief Converts the given uri that refer to the Data ability into a normalized URI. A normalized URI can be used
     * across devices, persisted, backed up, and restored. It can refer to the same item in the Data ability even if
     * the context has changed. If you implement URI normalization for a Data ability, you must also implement
     * denormalizeUri(ohos.utils.net.Uri) to enable URI denormalization. After this feature is enabled, URIs passed to
     * any method that is called on the Data ability must require normalization verification and denormalization. The
     * default implementation of this method returns null, indicating that this Data ability does not support URI
     * normalization.
     *
     * @param uri Indicates the Uri object to normalize.
     *
     * @return Returns the normalized Uri object if the Data ability supports URI normalization; returns null otherwise.
     */
    virtual Uri NormalizeUri(const Uri &uri);

    /**
     * @brief Converts the given normalized uri generated by normalizeUri(ohos.utils.net.Uri) into a denormalized one.
     * The default implementation of this method returns the original URI passed to it.
     *
     * @param uri uri Indicates the Uri object to denormalize.
     *
     * @return Returns the denormalized Uri object if the denormalization is successful; returns the original Uri
     * passed to this method if there is nothing to do; returns null if the data identified by the original Uri cannot
     * be found in the current environment.
     */
    virtual Uri DenormalizeUri(const Uri &uri);

    /**
     * @brief Performs batch operations on the database.
     *
     * @param operations Indicates a list of database operations on the database.
     * @return Returns the result of each operation, in array.
     */
    virtual std::vector<std::shared_ptr<DataShareResult>> ExecuteBatch(
        const std::vector<std::shared_ptr<DataShareOperation>> &operations);
};
}  // namespace DataShare
}  // namespace OHOS
#endif  // DATASHARE_EXT_ABILITY_H