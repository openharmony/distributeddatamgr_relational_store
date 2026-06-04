
    /**
     * @brief Register auto start up callback for system api.
     * @param callback The point of JsAbilityAutoStartupCallBack.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t RegisterAutoStartupSystemCallback(const sptr<IRemoteObject> &callback)
    {
        return 0;
    }

    /**
     * @brief Unregister auto start up callback for system api.
     * @param callback The point of JsAbilityAutoStartupCallBack.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t UnregisterAutoStartupSystemCallback(const sptr<IRemoteObject> &callback)
    {
        return 0;
    }

    /**
     * @brief Set every application auto start up state.
     * @param info The auto startup info,include bundle name, module name, ability name.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t SetApplicationAutoStartup(const AutoStartupInfo &info)
    {
        return 0;
    }

    /**
     * @brief Cancel every application auto start up .
     * @param info The auto startup info,include bundle name, module name, ability name.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t CancelApplicationAutoStartup(const AutoStartupInfo &info)
    {
        return 0;
    }

    /**
     * @brief Query auto startup state all application.
     * @param infoList Output parameters, return auto startup info list.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t QueryAllAutoStartupApplications(std::vector<AutoStartupInfo> &infoList)
    {
        return 0;
    }

    /**
     * @brief Retrieves the auto startup status of the current application.
     * @param isAutoStartEnabled Indicates whether auto startup is enabled for the current application.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t GetAutoStartupStatusForSelf(bool &isAutoStartEnabled)
    {
        return 0;
    }

    /**
     * @brief Manual start auto startup apps, EDM use only.
     * @param userId Indicates which user's auto startup apps to be started.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t ManualStartAutoStartupApps(int32_t userId)
    {
        return 0;
    }

    /**
     * @brief Query the caller's Token ID for anco.
     * @param userId Indicates the user ID.
     * @param asCallerForAncoSessionId Indicates the anco session Id of cached information.
     * @param callerTokenId Indicates the output caller Token ID.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode QueryCallerTokenIdForAnco(int32_t userId, const std::string &asCallerForAncoSessionId,
        uint32_t &callerTokenId)
    {
        return ERR_OK;
    }

    /**
     * @brief Launch game customized with game SA verification.
     * @param bundleName Name of the game application.
     * @param userId Indicates the user ID.
     * @param appIndex app clone index. Currently, only appIndex = 0 is supported.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t LaunchGameCustomized(const std::string &bundleName, int32_t userId, int32_t appIndex = 0)
    {
        return 0;
    }

    /**
     * @brief Set game prelaunch complete time.
     * @param userId Indicates the user ID.
     * @param completeTime The complete time for game prelaunch.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode SetGamePreLaunchCompleteTime(int32_t userId, int64_t completeTime)
    {
        return ERR_OK;
    }

    /**
     * PrepareTerminateAbilityBySCB, prepare to terminate ability by scb.
     *
     * @param sessionInfo the session info of the ability to start.
     * @param isPrepareTerminate the result of ability onPrepareToTerminate
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int PrepareTerminateAbilityBySCB(const sptr<SessionInfo> &sessionInfo, bool &isPrepareTerminate)
    {
        return 0;
    }

    /**
     * @brief Register app debug listener.
     * @param listener App debug listener.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t RegisterAppDebugListener(sptr<AppExecFwk::IAppDebugListener> listener) = 0;

    /**
     * @brief Unregister app debug listener.
     * @param listener App debug listener.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t UnregisterAppDebugListener(sptr<AppExecFwk::IAppDebugListener> listener) = 0;

    /**
     * @brief Attach app debug.
     * @param bundleName The application bundle name.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t AttachAppDebug(const std::string &bundleName, bool isDebugFromLocal) = 0;

    /**
     * @brief Detach app debug.
     * @param bundleName The application bundle name.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t DetachAppDebug(const std::string &bundleName, bool isDebugFromLocal) = 0;

    /**
     * @brief Execute intent.
     * @param key The key of intent executing client.
     * @param callerToken Caller ability token.
     * @param param The Intent execute param.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t ExecuteIntent(uint64_t key, const sptr<IRemoteObject> &callerToken,
        const InsightIntentExecuteParam &param) = 0;

    /**
      * @brief Execute intent for distributed scenario.
      *
      * @param want The want containing intent execution information.
      * @param srcDeviceId The source device id.
      * @param requestCode The Intent id.
      * @param specifiedFullTokenId The caller token id.
      * @return Returns ERR_OK on success, others on failure.
      */
    virtual int32_t ExecuteIntentForDistributed(const Want &want, const std::string &srcDeviceId,
        uint64_t requestCode, uint64_t specifiedFullTokenId = 0)
    {
        return 0;
    }

    /**
     * @brief Check if ability controller can start.
     * @param want The want of ability to start.
     * @return Return true to allow ability to start, or false to reject.
     */
    virtual bool IsAbilityControllerStart(const Want &want)
    {
        return true;
    }

    /**
     * @brief Called when insight intent execute finished.
     *
     * @param token ability's token.
     * @param intentId insight intent id.
     * @param result insight intent execute result.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t ExecuteInsightIntentDone(const sptr<IRemoteObject> &token, uint64_t intentId,
        const InsightIntentExecuteResult &result) = 0;

    /**
     * @brief Set application auto start up state by EDM.
     * @param info The auto startup info, include bundle name, module name, ability name.
     * @param flag Indicate whether the application is prohibited from changing the auto start up state.
     * @param isHiddenStart Indicate whether the application is hidden start.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t SetApplicationAutoStartupByEDM(const AutoStartupInfo &info, bool flag,
        bool isHiddenStart = false) = 0;

    /**
     * @brief Cancel application auto start up state by EDM.
     * @param info The auto startup info, include bundle name, module name, ability name.
     * @param flag Indicate whether the application is prohibited from changing the auto start up state.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t CancelApplicationAutoStartupByEDM(const AutoStartupInfo &info, bool flag) = 0;

    /**
     * @brief Get foreground ui abilities.
     * @param list Foreground ui abilities.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t GetForegroundUIAbilities(std::vector<AppExecFwk::AbilityStateData> &list) = 0;

    /**
     * @brief Open file by uri.
     * @param uri The file uri.
     * @param flag Want::FLAG_AUTH_READ_URI_PERMISSION or Want::FLAG_AUTH_WRITE_URI_PERMISSION.
     * @return int The file descriptor.
     */
    virtual int32_t OpenFile(const Uri& uri, uint32_t flag)
    {
        return 0;
    }

    /**
     * @brief Update session info.
     * @param sessionInfos The vector of session info.
     */
    virtual int32_t UpdateSessionInfoBySCB(std::list<SessionInfo> &sessionInfos, int32_t userId,
        std::vector<int32_t> &sessionIds)
    {
        return 0;
    }

    /**
     * @brief Restart app self.
     * @param want The ability type must be UIAbility.
     * @param isAppRecovery True indicates that the app is restarted because of recovery.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t RestartApp(const AAFwk::Want &want, bool isAppRecovery = false)
    {
        return 0;
    }

    /**
     * @brief Get host info of root caller.
     *
     * @param token The ability token.
     * @param hostInfo The host info of root caller.
     * @param userId The user id.
     * @return int32_t Returns 0 on success, others on failure.
     */
    virtual int32_t GetUIExtensionRootHostInfo(const sptr<IRemoteObject> token, UIExtensionHostInfo &hostInfo,
        int32_t userId = DEFAULT_INVAL_VALUE)
    {
        return 0;
    }

    /**
     * @brief Get ui extension session info
     *
     * @param token The ability token.
     * @param uiExtensionSessionInfo The ui extension session info.
     * @param userId The user id.
     * @return int32_t Returns ERR_OK on success, others on failure.
     */
    virtual int32_t GetUIExtensionSessionInfo(const sptr<IRemoteObject> token,
        UIExtensionSessionInfo &uiExtensionSessionInfo, int32_t userId = DEFAULT_INVAL_VALUE)
    {
        return 0;
    }

    /**
     * Open link of ability and atomic service.
     *
     * @param want Ability want.
     * @param callerToken Caller ability token.
     * @param userId User ID.
     * @param requestCode Ability request code.
     * @return Returns ERR_OK on success, others on failure.
    */
    virtual int32_t OpenLink(const Want &want, sptr<IRemoteObject> callerToken, int32_t userId = DEFAULT_INVAL_VALUE,
        int requestCode = DEFAULT_INVAL_VALUE, bool hideFailureTipDialog = false)
    {
        return 0;
    }

    /**
     * @brief Pop-up launch of full-screen atomic service.
     * @param want The want with parameters.
     * @param callerToken caller ability token.
     * @param requestCode Ability request code.
     * @param userId The User ID.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t OpenAtomicService(Want& want, const StartOptions &options, sptr<IRemoteObject> callerToken,
        int32_t requestCode = DEFAULT_INVAL_VALUE, int32_t userId = DEFAULT_INVAL_VALUE)
    {
        return 0;
    }

    /*
     * Set the enable status for starting and stopping resident processes.
     * The caller application can only set the resident status of the configured process.
     * @param bundleName The bundle name of the resident process.
     * @param enable Set resident process enable status.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t SetResidentProcessEnabled(const std::string &bundleName, bool enable)
    {
        return 0;
    }

    /**
     * @brief Querying whether to allow embedded startup of atomic service.
     *
     * @param token The caller UIAbility token.
     * @param appId The ID of the application to which this bundle belongs.
     * @return Returns true to allow ability to start, or false to reject.
     */
    virtual bool IsEmbeddedOpenAllowed(sptr<IRemoteObject> callerToken, const std::string &appId)
    {
        return true;
    }

    /**
     * @brief Request to display assert fault dialog.
     * @param callback Listen for user operation callbacks.
     * @param wantParams Assert dialog box display information.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t RequestAssertFaultDialog(const sptr<IRemoteObject> &callback, const AAFwk::WantParams &wantParams)
    {
        return -1;
    }

    /**
     * @brief Notify the operation status of the user.
     * @param assertFaultSessionId Indicates the request ID of AssertFault.
     * @param userStatus Operation status of the user.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t NotifyDebugAssertResult(uint64_t assertFaultSessionId, AAFwk::UserStatus userStatus)
    {
        return -1;
    }

    /**
     * Starts a new ability with specific start options.
     *
     * @param want, the want of the ability to start.
     * @param startOptions Indicates the options used to start.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t StartShortcut(const Want &want, const StartOptions &startOptions)
    {
        return 0;
    }

    /**
     * Get ability state by persistent id.
     *
     * @param persistentId, the persistentId of the session.
     * @param state Indicates the ability state.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t GetAbilityStateByPersistentId(int32_t persistentId, bool &state)
    {
        return 0;
    }

    /**
     * Transfer resultCode & want to ability manager service.
     *
     * @param resultCode, the resultCode of the ability to terminate.
     * @param resultWant, the Want of the ability to return.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t TransferAbilityResultForExtension(const sptr<IRemoteObject> &callerToken, int32_t resultCode,
        const Want &want)
    {
        return 0;
    }

    /**
     * Notify ability manager service frozen process.
     *
     * @param pidList, the pid list of the frozen process.
     * @param uid, the uid of the frozen process.
     */
    virtual void NotifyFrozenProcessByRSS(const std::vector<int32_t> &pidList, int32_t uid)
    {
        return;
    }

    /**
     *  Request to clean UIAbility from user.
     *
     * @param sessionInfo the session info of the ability to clean.
     * @param sceneFlag the reason info of the ability to terminate.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t CleanUIAbilityBySCB(const sptr<SessionInfo> &sessionInfo, bool isUserRequestedExit,
        uint32_t sceneFlag = 0)
    {
        return 0;
    }

    /**
     * Open atomic service window prior to finishing free install.
     *
     * @param bundleName, the bundle name of the atomic service.
     * @param moduleName, the module name of the atomic service.
     * @param abilityName, the ability name of the atomic service.
     * @param startTime, the starting time of the free install task.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t PreStartMission(const std::string& bundleName, const std::string& moduleName,
        const std::string& abilityName, const std::string& startTime)
    {
        return 0;
    }

    /**
     * Terminate the mission.
     *
     * @param missionId, The mission id of the UIAbility need to be terminated.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t TerminateMission(int32_t missionId)
    {
        return 0;
    }

    /**
     * Notify ability manager to set the flag to block all apps from starting.
     * Needs to apply for ohos.permission.BLOCK_ALL_APP_START.
     * @param flag, The flag to block all apps from starting
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t BlockAllAppStart(bool flag)
    {
        return 0;
    }

    /**
     * update associate config list by rss.
     *
     * @param configs The rss config info.
     * @param exportConfigs The rss export config info.
     * @param flag UPDATE_CONFIG_FLAG_COVER is cover config, UPDATE_CONFIG_FLAG_APPEND is append config.
     */
    virtual int32_t UpdateAssociateConfigList(const std::map<std::string, std::list<std::string>>& configs,
        const std::list<std::string>& exportConfigs, int32_t flag)
    {
        return 0;
    }

    /**
     * Set keep-alive flag for application under a specific user.
     * @param bundleName Bundle name.
     * @param userId User Id.
     * @param flag Keep-alive flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t SetApplicationKeepAlive(const std::string &bundleName, int32_t userId, bool flag)
    {
        return 0;
    }

    /**
     * Get keep-alive applications.
     * @param appType Application type.
     * @param userId User Id.
     * @param list List of Keep-alive information.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t QueryKeepAliveApplications(int32_t appType, int32_t userId, std::vector<KeepAliveInfo> &list)
    {
        return 0;
    }

    /**
     * Set keep-alive flag for application under a specific user by EDM.
     * @param bundleName Bundle name.
     * @param userId User Id.
     * @param flag Keep-alive flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t SetApplicationKeepAliveByEDM(const std::string &bundleName, int32_t userId,
        bool flag, bool isAllowUserToCancel = false)
    {
        return 0;
    }

    /**
     * Get keep-alive applications by EDM.
     * @param appType Application type.
     * @param userId User Id.
     * @param list List of Keep-alive information.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t QueryKeepAliveApplicationsByEDM(int32_t appType, int32_t userId, std::vector<KeepAliveInfo> &list)
    {
        return 0;
    }

    virtual int32_t GetAllIntentExemptionInfo(std::vector<AppExecFwk::IntentExemptionInfo> &info)
    {
        return 0;
    }

    /**
     * Add query ERMS observer.
     *
     * @param callerToken, The caller ability token.
     * @param observer, The observer of the ability to query ERMS.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t AddQueryERMSObserver(sptr<IRemoteObject> callerToken,
        sptr<AbilityRuntime::IQueryERMSObserver> observer)
    {
        return 0;
    }

    /**
     * Restart atomic service.
     *
     * @param callerToken, The caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t RestartSelfAtomicService(sptr<IRemoteObject> callerToken)
    {
        return 0;
    }

    /**
     * Query atomic service ERMS rule.
     *
     * @param callerToken, The caller ability token.
     * @param appId, The appId of the atomic service.
     * @param startTime, The startTime of the query.
     * @param rule, The returned ERMS rule.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t QueryAtomicServiceStartupRule(sptr<IRemoteObject> callerToken,
        const std::string &appId, const std::string &startTime, AtomicServiceStartupRule &rule)
    {
        return 0;
    }

    /**
     * PrepareTerminateAbilityDone, called when PrepareTerminateAbility call is done.
     *
     * @param token, the token of the ability to terminate.
     * @param isTerminate, indicates whether the ability should be terminated.
     */
    virtual void PrepareTerminateAbilityDone(const sptr<IRemoteObject> &token, bool isTerminate)
    {}

    /**
     * KillProcessWithPrepareTerminateDone, called when KillProcessWithPrepareTerminate call is done.
     *
     * @param moduleName, the module name of the application.
     * @param prepareTermination, the result of prepareTermination call of the module.
     * @param isExist, whether the prepareTerminate functions are implemented.
     */
    virtual void KillProcessWithPrepareTerminateDone(const std::string &moduleName,
        int32_t prepareTermination, bool isExist)
    {}

    /**
     * KillProcessForPermissionUpdate, call KillProcessForPermissionUpdate() through proxy object,
     * force kill the application by accessTokenId, notify exception to SCB.
     *
     * @param  accessTokenId, accessTokenId.
     * @return ERR_OK, return back success, others fail.
     */
    virtual int32_t KillProcessForPermissionUpdate(uint32_t accessTokenId)
    {
        return 0;
    }

    /**
     * Register hidden start observer.
     * @param observer, ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t RegisterHiddenStartObserver(const sptr<IHiddenStartObserver> &observer)
    {
        return 0;
    }

    /**
     * Unregister hidden start observer.
     * @param observer, ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t UnregisterHiddenStartObserver(const sptr<IHiddenStartObserver> &observer)
    {
        return 0;
    }
    /**
     * Query preload uiextension record.
     *
     * @param element, The uiextension ElementName.
     * @param moduleName, The uiextension moduleName.
     * @param hostBundleName, The uiextension caller hostBundleName.
     * @param recordNum, The returned count of uiextension.
     * @param userId, The User Id.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t QueryPreLoadUIExtensionRecord(const AppExecFwk::ElementName &element,
                                                  const std::string &moduleName,
                                                  const int32_t hostPid,
                                                  int32_t &recordNum,
                                                  int32_t userId = DEFAULT_INVAL_VALUE)
    {
        return 0;
    }

    /**
     * Revoke delegator.
     *
     * @param token, ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t RevokeDelegator(sptr<IRemoteObject> token)
    {
        return 0;
    }

    /**
     * Get all insight intent infos.
     * @param flag, the get type.
     * @param infos, the insight intent infos.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t GetAllInsightIntentInfo(
        AbilityRuntime::GetInsightIntentFlag flag,
        std::vector<InsightIntentInfoForQuery> &infos,
        int32_t userId = DEFAULT_INVAL_VALUE)
    {
        return 0;
    }

    /**
     * Get specified bundleName insight intent infos.
     * @param flag, the get type.
     * @param infos, the insight intent infos.
     * @param bundleName, The get insightIntent bundleName.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t GetInsightIntentInfoByBundleName(
        AbilityRuntime::GetInsightIntentFlag flag,
        const std::string &bundleName,
        std::vector<InsightIntentInfoForQuery> &infos,
        int32_t userId = DEFAULT_INVAL_VALUE)
    {
        return 0;
    }

    /**
     * Get specified intentName insight intent infos.
     * @param flag, the get type.
     * @param infos, the insight intent infos.
     * @param bundleName, The get insightIntent bundleName.
     * @param moduleName, The get insightIntent moduleName.
     * @param intentName, The get intent name.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t GetInsightIntentInfoByIntentName(
        AbilityRuntime::GetInsightIntentFlag flag,
        const std::string &bundleName,
        const std::string &moduleName,
        const std::string &intentName,
        InsightIntentInfoForQuery &info,
        int32_t userId = DEFAULT_INVAL_VALUE)
    {
        return 0;
    }

    /**
     * @brief Query entity.
     * @param key The key of intent executing client.
     * @param callerToken Caller ability token.
     * @param param The Intent query param.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode QueryEntityInfo(uint64_t key, sptr<IRemoteObject> callerToken,
        const InsightIntentQueryParam &param)
    {
        return 0;
    };

    /**
     * StartAbilityWithWait, send want and abilityStartWithWaitObserver to abms.
     *
     * @param want Ability want.
     * @param observer ability foreground notify observer for aa tool.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t StartAbilityWithWait(Want &want, sptr<IAbilityStartWithWaitObserver> &observer)
    {
        return 0;
    }

    /**
     * Start UIAbility with callback to receive the request result, the callback is valid only for SA callers.
     *
     * @param want Indicates the ability to start.
     * @param callerToken Indicates the caller ability token.
     * @param callback Indicates the callback used to receive the result of request start ability.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t StartUIAbilityWithCallback(const Want &want, sptr<IRemoteObject> callerToken,
        sptr<IRequestStartAbilityCallback> callback)
    {
        return 0;
    }

    /**
     * Set keep-alive flag for app service extension under u1 user.
     * @param bundleName Bundle name.
     * @param flag Keep-alive flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t SetAppServiceExtensionKeepAlive(const std::string &bundleName, bool flag)
    {
        return 0;
    }

    virtual int32_t UpdateKioskApplicationList(const std::vector<std::string> &appList)
    {
        return 0;
    }

    /**
     * Get keep-alive app service extensions.
     * @param list List of Keep-alive information.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t QueryKeepAliveAppServiceExtensions(std::vector<KeepAliveInfo> &list)
    {
        return 0;
    }

    virtual int32_t EnterKioskMode(sptr<IRemoteObject> callerToken)
    {
        return 0;
    }

    virtual int32_t ExitKioskMode(sptr<IRemoteObject> callerToken)
    {
        return 0;
    }

    virtual int32_t GetKioskStatus(AAFwk::KioskStatus &kioskStatus)
    {
        return 0;
    }

    /**
     * Register sa interceptor.
     * @param interceptor, The sa interceptor.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t RegisterSAInterceptor(sptr<AbilityRuntime::ISAInterceptor> interceptor)
    {
        return 0;
    }

    virtual int32_t SetOnNewWantSkipScenarios(sptr<IRemoteObject> callerToken, int32_t scenarios)
    {
        return 0;
    }

    /**
     * SCB notifies AbilityManagerService that UIAbility startup was intercepted.
     *
     * @param requestId The request id.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t NotifyStartupExceptionBySCB(int32_t requestId)
    {
        return 0;
    }

    /**
     * Preload application.
     * @param bundleName Name of the application.
     * @param userId user id.
     * @param appIndex app clone index. Reserved field, only appIndex=0 is supported.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t PreloadApplication(const std::string &bundleName, int32_t userId, int32_t appIndex)
    {
        return 0;
    }

    /**
     * Start self UIAbility in current process.
     * @param want Ability want.
     * @param specifiedFlag specified flag.
     * @param startOptions Indicates the options used to start.
     * @param hasOptions Is have start options.
     * @param callerToken The caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode StartSelfUIAbilityInCurrentProcess(const Want &want, const std::string &specifiedFlag,
        const AAFwk::StartOptions &startOptions, bool hasOptions, sptr<IRemoteObject> callerToken)
    {
        return ERR_OK;
    }

    /**
     * @brief Notify cancel game prelaunch and kill the process.
     * @param callerToken Indicates the caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t NotifyCancelGamePreLaunch(const sptr<IRemoteObject> callerToken)
    {
        return ERR_OK;
    }

    /**
     * @brief Notify complete game prelaunch and clear the flag.
     * @param callerToken Indicates the caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t NotifyCompleteGamePreLaunch(const sptr<IRemoteObject> callerToken)
    {
        return ERR_OK;
    }

    /**
     * Check if the app is restart-limited.
     * @return Returns true on being limited.
     */
    virtual bool IsRestartAppLimit()
    {
        return false;
    }

    /**
     * UnPreload UIExtension with want, send want to ability manager service.
     *
     * @param extensionAbilityId The extension ability Id.
     * @param userId The User Id.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t ClearPreloadedUIExtensionAbility(
    int32_t extensionAbilityId, int32_t userId = DEFAULT_INVAL_VALUE)
    {
        return 0;
    }

    /**
     * clear all Preload UIExtension with want, send want to ability manager service.
     *
     * @param userId The User Id.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t ClearPreloadedUIExtensionAbilities(int32_t userId = DEFAULT_INVAL_VALUE)
    {
        return 0;
    }

    /**
     * @brief Register preload ui extension host client.
     * @param callerToken Caller ability token.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t RegisterPreloadUIExtensionHostClient(
    const sptr<IRemoteObject> &callerToken)
    {
        return 0;
    }

    /**
     * @brief UnRegister preload ui extension host client.
     * @param hostBundleName, the caller application bundle name.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t UnRegisterPreloadUIExtensionHostClient(int32_t callerPid = DEFAULT_INVAL_VALUE)
    {
        return 0;
    }

    /**
 	 * @brief Queries self modular object extension information.
     * @param extensionInfos get the queried extensionInfos.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t QuerySelfModularObjectExtensionInfos(std::vector<ModularObjectExtensionInfo> &extensionInfos)
    {
        return 0;
    }

    /**
     * @brief Get list of applications launched before the first unlock.
     * @param userId The User Id.
     * @param userLockedBundleList List of applications launched before the first unlock.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetUserLockedBundleList(int32_t userId, std::unordered_set<std::string> &userLockedBundleList)
    {
        return ERR_OK;
    }

    /**
     * @brief Set app recovery galg.
     * @param token Caller ability token.
     * @param flag App recovery flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t SetAppRecoveryFlag(const sptr<IRemoteObject>& token, int flag)
    {
        return 0;
    }

    /**
     * @brief Start skill by HDC, launch target ability.
     * @param bundleName The target bundle name.
     * @param moduleName The target module name.
     * @param skillName The skill name to execute.
     * @param arkTSPath The target ArkTS file path.
     * @param funcName The target function name.
     * @param argv The arguments for skill execution.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t ExecuteInAppSkill(const std::string &bundleName, const std::string &moduleName,
        const std::string &skillName, const std::string &arkTSPath = "",
        const std::string &funcName = "",
        const std::shared_ptr<AAFwk::WantParams> &skillArgs = nullptr,
        const sptr<ISkillExecuteCallback> &callback = nullptr)
    {
        return ERR_OK;
    }

    /**
     * @brief Execute in-app skill with explicit caller tokenId (for SA-to-SA calls).
     * @param request The skill execute request parameters.
     * @param callback The callback for skill execution result.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t ExecuteInAppSkillWithTokenId(const AppExecFwk::SkillExecuteRequest &request,
        const sptr<ISkillExecuteCallback> &callback)
    {
        return ERR_OK;
    }

    /**
     * @brief Query the type of a skill (independent or in-app).
     * @param bundleName The bundle name of the target application.
     * @param moduleName The module name of the target application.
     * @param skillName The skill name identifier.
     * @param skillType Output the skill type.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t QuerySkillType(const std::string &bundleName, const std::string &moduleName,
        const std::string &skillName, int32_t &skillType)
    {
        return ERR_OK;
    }

    virtual int32_t ExecuteSkillDone(const sptr<IRemoteObject> &token, const std::string &requestCode,
        int32_t resultCode, const AppExecFwk::SkillExecuteResult &result)
    {
        return ERR_OK;
    }
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_ABILITY_MANAGER_INTERFACE_H
