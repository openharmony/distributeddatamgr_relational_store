
    /**
     * Starts a new ability with specific start options.
     *
     * @param want, the want of the ability to start.
     * @param startOptions Indicates the options used to start.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t StartShortcut(const Want &want, const StartOptions &startOptions);

    /**
     * Get ability state by persistent id.
     *
     * @param persistentId, the persistentId of the session.
     * @param state Indicates the ability state.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t GetAbilityStateByPersistentId(int32_t persistentId, bool &state);

    /**
     * Transfer resultCode & want to abms.
     *
     * @param callerToken caller ability token.
     * @param requestCode the resultCode of the ability to start.
     * @param want Indicates the ability to start.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t TransferAbilityResultForExtension(const sptr<IRemoteObject> &callerToken, int32_t resultCode,
        const Want &want);

    /**
     * Notify ability manager service frozen process.
     *
     * @param pidList, the pid list of the frozen process.
     * @param uid, the uid of the frozen process.
     */
    void NotifyFrozenProcessByRSS(const std::vector<int32_t> &pidList, int32_t uid);

    /**
     * Open atomic service window prior to finishing free install.
     *
     * @param bundleName, the bundle name of the atomic service.
     * @param moduleName, the module name of the atomic service.
     * @param abilityName, the ability name of the atomic service.
     * @param startTime, the starting time of the free install task.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t PreStartMission(const std::string& bundleName, const std::string& moduleName,
        const std::string& abilityName, const std::string& startTime);

    /**
     *  Request to clean UIAbility from user.
     *
     * @param sessionInfo the session info of the ability to clean.
     * @param isUserRequestedExit determine whether it is a user request to exit.
     * @param sceneFlag the reason info of the ability to terminate.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode CleanUIAbilityBySCB(sptr<SessionInfo> sessionInfo,
        bool isUserRequestedExit = false, uint32_t sceneFlag = 0);

    /**
     * Open link of ability and atomic service.
     *
     * @param want Ability want.
     * @param callerToken Caller ability token.
     * @param userId User ID.
     * @param requestCode Ability request code.
     * @return Returns ERR_OK on success, others on failure.
    */
    int32_t OpenLink(const Want &want, sptr<IRemoteObject> callerToken, int32_t userId, int requestCode,
        bool hideFailureTipDialog = false);

    /**
     * Terminate process by bundleName.
     *
     * @param missionId, The mission id of the UIAbility need to be terminated.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode TerminateMission(int32_t missionId);

    /**
     * Notify ability manager to set the flag to block all apps from starting.
     * Needs to apply for ohos.permission.BLOCK_ALL_APP_START.
     * @param flag, The flag to block all apps from starting
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode BlockAllAppStart(bool flag);

    /**
     * update associate config list by rss.
     *
     * @param configs The rss config info.
     * @param exportConfigs The rss export config info.
     * @param flag UPDATE_CONFIG_FLAG_COVER is cover config, UPDATE_CONFIG_FLAG_APPEND is append config.
     */
    ErrCode UpdateAssociateConfigList(const std::map<std::string, std::list<std::string>>& configs,
        const std::list<std::string>& exportConfigs, int32_t flag);

    ErrCode GetAllIntentExemptionInfo(std::vector<AppExecFwk::IntentExemptionInfo>& info);

    /**
     * Add query ERMS observer.
     *
     * @param callerToken, The caller ability token.
     * @param observer, The observer of the ability to query ERMS.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode AddQueryERMSObserver(sptr<IRemoteObject> callerToken,
        sptr<AbilityRuntime::IQueryERMSObserver> observer);

    /**
     * Query atomic service ERMS rule.
     *
     * @param callerToken, The caller ability token.
     * @param appId, The appId of the atomic service.
     * @param startTime, The startTime of the query.
     * @param rule, The returned ERMS rule.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode QueryAtomicServiceStartupRule(sptr<IRemoteObject> callerToken,
        const std::string &appId, const std::string &startTime, AtomicServiceStartupRule &rule);

    /**
     * Restart atomic service.
     *
     * @param callerToken, The caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
     ErrCode RestartSelfAtomicService(sptr<IRemoteObject> callerToken);

    /**
     * PrepareTerminateAbilityDone, called when PrepareTerminateAbility call is done.
     *
     * @param token, the token of the ability to terminate.
     * @param callback callback.
     */
    void PrepareTerminateAbilityDone(sptr<IRemoteObject> token, bool isTerminate);

    /**
     * KillProcessWithPrepareTerminateDone, called when KillProcessWithPrepareTerminate call is done.
     *
     * @param moduleName, the module name of the application.
     * @param prepareTermination, the result of prepareTermination call of the module.
     * @param isExist, whether the prepareTerminate functions are implemented.
     */
    void KillProcessWithPrepareTerminateDone(const std::string &moduleName, int32_t prepareTermination, bool isExist);

    /**
     * KillProcessForPermissionUpdate
     * force kill the application by accessTokenId, notify exception to SCB.
     *
     * @param  accessTokenId, accessTokenId.
     * @return ERR_OK, return back success, others fail.
     */
    ErrCode KillProcessForPermissionUpdate(uint32_t accessTokenId);

    /**
     * Register hidden start observer.
     * @param observer, ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RegisterHiddenStartObserver(const sptr<IHiddenStartObserver> &observer);

    /**
     * Unregister hidden start observer.
     * @param observer, ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UnregisterHiddenStartObserver(const sptr<IHiddenStartObserver> &observer);

    /**
     * Query preload uiextension record.
     *
     * @param element, The uiextension ElementName.
     * @param moduleName, The uiextension moduleName.
     * @param hostPid, The uiextension caller pid.
     * @param recordNum, The returned count of uiextension.
     * @param userId, The User Id.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode QueryPreLoadUIExtensionRecord(const AppExecFwk::ElementName &element,
                                          const std::string &moduleName,
                                          const int32_t hostPid,
                                          int32_t &recordNum,
                                          int32_t userId = DEFAULT_INVAL_VALUE);

    /**
     * Revoke delegator.
     *
     * @param token, ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RevokeDelegator(sptr<IRemoteObject> token);

    /**
     * Get all insight intent infos.
     * @param flag, the get type.
     * @param infos, the insight intent infos.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetAllInsightIntentInfo(
        AbilityRuntime::GetInsightIntentFlag flag,
        std::vector<InsightIntentInfoForQuery> &infos,
        int32_t userId = DEFAULT_INVAL_VALUE);

    /**
     * Get specified bundleName insight intent infos.
     * @param flag, the get type.
     * @param infos, the insight intent infos.
     * @param bundleName, The get insightIntent bundleName.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetInsightIntentInfoByBundleName(
        AbilityRuntime::GetInsightIntentFlag flag,
        const std::string &bundleName,
        std::vector<InsightIntentInfoForQuery> &infos,
        int32_t userId = DEFAULT_INVAL_VALUE);

    /**
     * Get specified intentName insight intent infos.
     * @param flag, the get type.
     * @param infos, the insight intent infos.
     * @param bundleName, The get insightIntent bundleName.
     * @param moduleName, The get insightIntent moduleName.
     * @param intentName, The get intent name.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetInsightIntentInfoByIntentName(
        AbilityRuntime::GetInsightIntentFlag flag,
        const std::string &bundleName,
        const std::string &moduleName,
        const std::string &intentName,
        InsightIntentInfoForQuery &info,
        int32_t userId = DEFAULT_INVAL_VALUE);

    ErrCode UpdateKioskApplicationList(const std::vector<std::string> &appList);

    ErrCode EnterKioskMode(sptr<IRemoteObject> callerToken);

    ErrCode ExitKioskMode(sptr<IRemoteObject> callerToken);

    ErrCode GetKioskStatus(AAFwk::KioskStatus &kioskStatus);

    /**
     * Register sa interceptor.
     * @param interceptor, The sa interceptor.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RegisterSAInterceptor(sptr<AbilityRuntime::ISAInterceptor> interceptor);

    /**
     * SuspendExtensionAbility, suspend session with service ability.
     *
     * @param connect, Callback used to notify caller the result of connecting or disconnecting.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode SuspendExtensionAbility(sptr<IAbilityConnection> connect);

    /**
     * ResumeExtensionAbility, resume session with service ability.
     *
     * @param connect, Callback used to notify caller the result of connecting or disconnecting.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode ResumeExtensionAbility(sptr<IAbilityConnection> connect);

    ErrCode SetOnNewWantSkipScenarios(sptr<IRemoteObject> callerToken, int32_t scenarios);

    ErrCode NotifyStartupExceptionBySCB(int32_t requestId);

    /**
     * Preload application.
     * @param bundleName Name of the application.
     * @param userId user id.
     * @param appIndex app clone index. Reserved field, only appIndex=0 is supported.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode PreloadApplication(const std::string &bundleName, int32_t userId, int32_t appIndex);

    /**
     * Start self UIAbility in current process.
     * @param want Ability want.
     * @param specifiedFlag specified flag.
     * @param startOptions Indicates the options used to start.
     * @param hasOptions Is have start options.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode StartSelfUIAbilityInCurrentProcess(const Want &want, const std::string &specifiedFlag,
        const AAFwk::StartOptions &startOptions, bool hasOptions, sptr<IRemoteObject> callerToken);

    /**
     * @brief Notify cancel game prelaunch and kill the process.
     * @param callerToken Indicates the caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode NotifyCancelGamePreLaunch(const sptr<IRemoteObject> callerToken);

    /**
     * @brief Notify complete game prelaunch and clear the flag.
     * @param callerToken Indicates the caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode NotifyCompleteGamePreLaunch(const sptr<IRemoteObject> callerToken);

    /**
     * Check if the app is restart-limited.
     * @return Returns true on being limited.
     */
    bool IsRestartAppLimit();

    /**
     * UnPreload UIExtension with want, send want to ability manager service.
     *
     * @param extensionAbilityId The extension ability Id.
     * @param userId The User Id.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode ClearPreloadedUIExtensionAbility(int32_t extensionAbilityId, int32_t userId = DEFAULT_INVAL_VALUE);

    /**
     * clear all Preload UIExtension with want, send want to ability manager service.
     *
     * @param userId The User Id.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode ClearPreloadedUIExtensionAbilities(int32_t userId = DEFAULT_INVAL_VALUE);

    /**
     * @brief Register preload ui extension host client.
     * @param callerToken Caller ability token.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RegisterPreloadUIExtensionHostClient(const sptr<IRemoteObject> &callerToken);

    /**
     * @brief UnRegister preload ui extension host client.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UnRegisterPreloadUIExtensionHostClient(int32_t callerPid = DEFAULT_INVAL_VALUE);

    /**
 	 * @brief Queries self modular object extension information.
     * @param extensionInfos get the queried extensionInfos.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode QuerySelfModularObjectExtensionInfos(std::vector<ModularObjectExtensionInfo> &extensionInfos);

    /**
     * @brief Get list of applications launched before the first unlock.
     * @param userId The User Id.
     * @param userLockedBundleList List of applications launched before the first unlock.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetUserLockedBundleList(int32_t userId, std::unordered_set<std::string> &userLockedBundleList);

    /**
     * @brief UnRegister preload ui extension host client.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t SetAppRecoveryFlag(const sptr<IRemoteObject>& token, int flag);

    ErrCode ExecuteInAppSkill(const std::string &bundleName, const std::string &moduleName,
        const std::string &skillName, const std::string &arkTSPath = "",
        const std::string &funcName = "",
        const std::shared_ptr<AAFwk::WantParams> &skillArgs = nullptr,
        const sptr<ISkillExecuteCallback> &callback = nullptr);

    ErrCode ExecuteInAppSkillWithTokenId(const AppExecFwk::SkillExecuteRequest &request,
        const sptr<ISkillExecuteCallback> &callback);

    ErrCode ExecuteSkillDone(sptr<IRemoteObject> token, const std::string &requestCode,
        int32_t resultCode, const AppExecFwk::SkillExecuteResult &result);

    ErrCode QuerySkillType(const std::string &bundleName, const std::string &moduleName,
        const std::string &skillName, int32_t &skillType);

public:
    AbilityManagerClient();
private:
    DISALLOW_COPY_AND_MOVE(AbilityManagerClient);

    class AbilityMgrDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        AbilityMgrDeathRecipient() = default;
        ~AbilityMgrDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;
    private:
        DISALLOW_COPY_AND_MOVE(AbilityMgrDeathRecipient);
    };

    sptr<IAbilityManager> GetAbilityManager();
    void ResetProxy(wptr<IRemoteObject> remote);
    void HandleDlpApp(Want &want);

    static std::once_flag singletonFlag_;
    static std::shared_ptr<AbilityManagerClient> instance_;
    sptr<IAbilityManager> proxy_;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_;
    std::recursive_mutex mutex_;
    std::mutex topAbilityMutex_;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_ABILITY_MANAGER_CLIENT_H
