/* Copyright (c) 2013 KrossX <krossx@live.com>
* License: http://www.opensource.org/licenses/mit-license.html  MIT License
*/

#pragma once

char *Advapi_Function[] =
{
	"ADVAPI32_1000",
	"I_ScGetCurrentGroupStateW",
	"A_SHAFinal",
	"A_SHAInit",
	"A_SHAUpdate",
	"AbortSystemShutdownA",
	"AbortSystemShutdownW",
	"AccessCheck",
	"AccessCheckAndAuditAlarmA",
	"AccessCheckAndAuditAlarmW",
	"AccessCheckByType",
	"AccessCheckByTypeAndAuditAlarmA",
	"AccessCheckByTypeAndAuditAlarmW",
	"AccessCheckByTypeResultList",
	"AccessCheckByTypeResultListAndAuditAlarmA",
	"AccessCheckByTypeResultListAndAuditAlarmByHandleA",
	"AccessCheckByTypeResultListAndAuditAlarmByHandleW",
	"AccessCheckByTypeResultListAndAuditAlarmW",
	"AddAccessAllowedAce",
	"AddAccessAllowedAceEx",
	"AddAccessAllowedObjectAce",
	"AddAccessDeniedAce",
	"AddAccessDeniedAceEx",
	"AddAccessDeniedObjectAce",
	"AddAce",
	"AddAuditAccessAce",
	"AddAuditAccessAceEx",
	"AddAuditAccessObjectAce",
	"AddConditionalAce",
	"AddMandatoryAce",
	"AddUsersToEncryptedFile",
	"AddUsersToEncryptedFileEx",
	"AdjustTokenGroups",
	"AdjustTokenPrivileges",
	"AllocateAndInitializeSid",
	"AllocateLocallyUniqueId",
	"AreAllAccessesGranted",
	"AreAnyAccessesGranted",
	"AuditComputeEffectivePolicyBySid",
	"AuditComputeEffectivePolicyByToken",
	"AuditEnumerateCategories",
	"AuditEnumeratePerUserPolicy",
	"AuditEnumerateSubCategories",
	"AuditFree",
	"AuditLookupCategoryGuidFromCategoryId",
	"AuditLookupCategoryIdFromCategoryGuid",
	"AuditLookupCategoryNameA",
	"AuditLookupCategoryNameW",
	"AuditLookupSubCategoryNameA",
	"AuditLookupSubCategoryNameW",
	"AuditQueryGlobalSaclA",
	"AuditQueryGlobalSaclW",
	"AuditQueryPerUserPolicy",
	"AuditQuerySecurity",
	"AuditQuerySystemPolicy",
	"AuditSetGlobalSaclA",
	"AuditSetGlobalSaclW",
	"AuditSetPerUserPolicy",
	"AuditSetSecurity",
	"AuditSetSystemPolicy",
	"BackupEventLogA",
	"BackupEventLogW",
	"BuildExplicitAccessWithNameA",
	"BuildExplicitAccessWithNameW",
	"BuildImpersonateExplicitAccessWithNameA",
	"BuildImpersonateExplicitAccessWithNameW",
	"BuildImpersonateTrusteeA",
	"BuildImpersonateTrusteeW",
	"BuildSecurityDescriptorA",
	"BuildSecurityDescriptorW",
	"BuildTrusteeWithNameA",
	"BuildTrusteeWithNameW",
	"BuildTrusteeWithObjectsAndNameA",
	"BuildTrusteeWithObjectsAndNameW",
	"BuildTrusteeWithObjectsAndSidA",
	"BuildTrusteeWithObjectsAndSidW",
	"BuildTrusteeWithSidA",
	"BuildTrusteeWithSidW",
	"CancelOverlappedAccess",
	"ChangeServiceConfig2A",
	"ChangeServiceConfig2W",
	"ChangeServiceConfigA",
	"ChangeServiceConfigW",
	"CheckTokenMembership",
	"ClearEventLogA",
	"ClearEventLogW",
	"CloseCodeAuthzLevel",
	"CloseEncryptedFileRaw",
	"CloseEventLog",
	"CloseServiceHandle",
	"CloseThreadWaitChainSession",
	"CloseTrace",
	"CommandLineFromMsiDescriptor",
	"ComputeAccessTokenFromCodeAuthzLevel",
	"ControlService",
	"ControlServiceExA",
	"ControlServiceExW",
	"ControlTraceA",
	"ControlTraceW",
	"ConvertAccessToSecurityDescriptorA",
	"ConvertAccessToSecurityDescriptorW",
	"ConvertSDToStringSDRootDomainA",
	"ConvertSDToStringSDRootDomainW",
	"ConvertSecurityDescriptorToAccessA",
	"ConvertSecurityDescriptorToAccessNamedA",
	"ConvertSecurityDescriptorToAccessNamedW",
	"ConvertSecurityDescriptorToAccessW",
	"ConvertSecurityDescriptorToStringSecurityDescriptorA",
	"ConvertSecurityDescriptorToStringSecurityDescriptorW",
	"ConvertSidToStringSidA",
	"ConvertSidToStringSidW",
	"ConvertStringSDToSDDomainA",
	"ConvertStringSDToSDDomainW",
	"ConvertStringSDToSDRootDomainA",
	"ConvertStringSDToSDRootDomainW",
	"ConvertStringSecurityDescriptorToSecurityDescriptorA",
	"ConvertStringSecurityDescriptorToSecurityDescriptorW",
	"ConvertStringSidToSidA",
	"ConvertStringSidToSidW",
	"ConvertToAutoInheritPrivateObjectSecurity",
	"CopySid",
	"CreateCodeAuthzLevel",
	"CreatePrivateObjectSecurity",
	"CreatePrivateObjectSecurityEx",
	"CreatePrivateObjectSecurityWithMultipleInheritance",
	"CreateProcessAsUserA",
	"CreateProcessAsUserW",
	"CreateProcessWithLogonW",
	"CreateProcessWithTokenW",
	"CreateRestrictedToken",
	"CreateServiceA",
	"CreateServiceW",
	"CreateTraceInstanceId",
	"CreateWellKnownSid",
	"CredBackupCredentials",
	"CredDeleteA",
	"CredDeleteW",
	"CredEncryptAndMarshalBinaryBlob",
	"CredEnumerateA",
	"CredEnumerateW",
	"CredFindBestCredentialA",
	"CredFindBestCredentialW",
	"CredFree",
	"CredGetSessionTypes",
	"CredGetTargetInfoA",
	"CredGetTargetInfoW",
	"CredIsMarshaledCredentialA",
	"CredIsMarshaledCredentialW",
	"CredIsProtectedA",
	"CredIsProtectedW",
	"CredMarshalCredentialA",
	"CredMarshalCredentialW",
	"CredProfileLoaded",
	"CredProfileUnloaded",
	"CredProtectA",
	"CredProtectW",
	"CredReadA",
	"CredReadByTokenHandle",
	"CredReadDomainCredentialsA",
	"CredReadDomainCredentialsW",
	"CredReadW",
	"CredRenameA",
	"CredRenameW",
	"CredRestoreCredentials",
	"CredUnmarshalCredentialA",
	"CredUnmarshalCredentialW",
	"CredUnprotectA",
	"CredUnprotectW",
	"CredWriteA",
	"CredWriteDomainCredentialsA",
	"CredWriteDomainCredentialsW",
	"CredWriteW",
	"CredpConvertCredential",
	"CredpConvertOneCredentialSize",
	"CredpConvertTargetInfo",
	"CredpDecodeCredential",
	"CredpEncodeCredential",
	"CredpEncodeSecret",
	"CryptAcquireContextA",
	"CryptAcquireContextW",
	"CryptContextAddRef",
	"CryptCreateHash",
	"CryptDecrypt",
	"CryptDeriveKey",
	"CryptDestroyHash",
	"CryptDestroyKey",
	"CryptDuplicateHash",
	"CryptDuplicateKey",
	"CryptEncrypt",
	"CryptEnumProviderTypesA",
	"CryptEnumProviderTypesW",
	"CryptEnumProvidersA",
	"CryptEnumProvidersW",
	"CryptExportKey",
	"CryptGenKey",
	"CryptGenRandom",
	"CryptGetDefaultProviderA",
	"CryptGetDefaultProviderW",
	"CryptGetHashParam",
	"CryptGetKeyParam",
	"CryptGetProvParam",
	"CryptGetUserKey",
	"CryptHashData",
	"CryptHashSessionKey",
	"CryptImportKey",
	"CryptReleaseContext",
	"CryptSetHashParam",
	"CryptSetKeyParam",
	"CryptSetProvParam",
	"CryptSetProviderA",
	"CryptSetProviderExA",
	"CryptSetProviderExW",
	"CryptSetProviderW",
	"CryptSignHashA",
	"CryptSignHashW",
	"CryptVerifySignatureA",
	"CryptVerifySignatureW",
	"DecryptFileA",
	"DecryptFileW",
	"DeleteAce",
	"DeleteService",
	"DeregisterEventSource",
	"DestroyPrivateObjectSecurity",
	"DuplicateEncryptionInfoFile",
	"DuplicateToken",
	"DuplicateTokenEx",
	"ElfBackupEventLogFileA",
	"ElfBackupEventLogFileW",
	"ElfChangeNotify",
	"ElfClearEventLogFileA",
	"ElfClearEventLogFileW",
	"ElfCloseEventLog",
	"ElfDeregisterEventSource",
	"ElfFlushEventLog",
	"ElfNumberOfRecords",
	"ElfOldestRecord",
	"ElfOpenBackupEventLogA",
	"ElfOpenBackupEventLogW",
	"ElfOpenEventLogA",
	"ElfOpenEventLogW",
	"ElfReadEventLogA",
	"ElfReadEventLogW",
	"ElfRegisterEventSourceA",
	"ElfRegisterEventSourceW",
	"ElfReportEventA",
	"ElfReportEventAndSourceW",
	"ElfReportEventW",
	"EnableTrace",
	"EnableTraceEx2",
	"EnableTraceEx",
	"EncryptFileA",
	"EncryptFileW",
	"EncryptedFileKeyInfo",
	"EncryptionDisable",
	"EnumDependentServicesA",
	"EnumDependentServicesW",
	"EnumServiceGroupW",
	"EnumServicesStatusA",
	"EnumServicesStatusExA",
	"EnumServicesStatusExW",
	"EnumServicesStatusW",
	"EnumerateTraceGuids",
	"EnumerateTraceGuidsEx",
	"EqualDomainSid",
	"EqualPrefixSid",
	"EqualSid",
	"EventAccessControl",
	"EventAccessQuery",
	"EventAccessRemove",
	"EventActivityIdControl",
	"EventEnabled",
	"EventProviderEnabled",
	"EventRegister",
	"EventUnregister",
	"EventWrite",
	"EventWriteEndScenario",
	"EventWriteEx",
	"EventWriteStartScenario",
	"EventWriteString",
	"EventWriteTransfer",
	"FileEncryptionStatusA",
	"FileEncryptionStatusW",
	"FindFirstFreeAce",
	"FlushEfsCache",
	"FlushTraceA",
	"FlushTraceW",
	"FreeEncryptedFileKeyInfo",
	"FreeEncryptedFileMetadata",
	"FreeEncryptionCertificateHashList",
	"FreeInheritedFromArray",
	"FreeSid",
	"GetAccessPermissionsForObjectA",
	"GetAccessPermissionsForObjectW",
	"GetAce",
	"GetAclInformation",
	"GetAuditedPermissionsFromAclA",
	"GetAuditedPermissionsFromAclW",
	"GetCurrentHwProfileA",
	"GetCurrentHwProfileW",
	"GetEffectiveRightsFromAclA",
	"GetEffectiveRightsFromAclW",
	"GetEncryptedFileMetadata",
	"GetEventLogInformation",
	"GetExplicitEntriesFromAclA",
	"GetExplicitEntriesFromAclW",
	"GetFileSecurityA",
	"GetFileSecurityW",
	"GetInformationCodeAuthzLevelW",
	"GetInformationCodeAuthzPolicyW",
	"GetInheritanceSourceA",
	"GetInheritanceSourceW",
	"GetKernelObjectSecurity",
	"GetLengthSid",
	"GetLocalManagedApplicationData",
	"GetLocalManagedApplications",
	"GetManagedApplicationCategories",
	"GetManagedApplications",
	"GetMultipleTrusteeA",
	"GetMultipleTrusteeOperationA",
	"GetMultipleTrusteeOperationW",
	"GetMultipleTrusteeW",
	"GetNamedSecurityInfoA",
	"GetNamedSecurityInfoExA",
	"GetNamedSecurityInfoExW",
	"GetNamedSecurityInfoW",
	"GetNumberOfEventLogRecords",
	"GetOldestEventLogRecord",
	"GetOverlappedAccessResults",
	"GetPrivateObjectSecurity",
	"GetSecurityDescriptorControl",
	"GetSecurityDescriptorDacl",
	"GetSecurityDescriptorGroup",
	"GetSecurityDescriptorLength",
	"GetSecurityDescriptorOwner",
	"GetSecurityDescriptorRMControl",
	"GetSecurityDescriptorSacl",
	"GetSecurityInfo",
	"GetSecurityInfoExA",
	"GetSecurityInfoExW",
	"GetServiceDisplayNameA",
	"GetServiceDisplayNameW",
	"GetServiceKeyNameA",
	"GetServiceKeyNameW",
	"GetSidIdentifierAuthority",
	"GetSidLengthRequired",
	"GetSidSubAuthority",
	"GetSidSubAuthorityCount",
	"GetThreadWaitChain",
	"GetTokenInformation",
	"GetTraceEnableFlags",
	"GetTraceEnableLevel",
	"GetTraceLoggerHandle",
	"GetTrusteeFormA",
	"GetTrusteeFormW",
	"GetTrusteeNameA",
	"GetTrusteeNameW",
	"GetTrusteeTypeA",
	"GetTrusteeTypeW",
	"GetUserNameA",
	"GetUserNameW",
	"GetWindowsAccountDomainSid",
	"I_QueryTagInformation",
	"I_ScIsSecurityProcess",
	"I_ScPnPGetServiceName",
	"I_ScQueryServiceConfig",
	"I_ScSendPnPMessage",
	"I_ScSendTSMessage",
	"I_ScSetServiceBitsA",
	"I_ScSetServiceBitsW",
	"I_ScValidatePnPService",
	"IdentifyCodeAuthzLevelW",
	"ImpersonateAnonymousToken",
	"ImpersonateLoggedOnUser",
	"ImpersonateNamedPipeClient",
	"ImpersonateSelf",
	"InitializeAcl",
	"InitializeSecurityDescriptor",
	"InitializeSid",
	"InitiateShutdownA",
	"InitiateShutdownW",
	"InitiateSystemShutdownA",
	"InitiateSystemShutdownExA",
	"InitiateSystemShutdownExW",
	"InitiateSystemShutdownW",
	"InstallApplication",
	"IsTextUnicode",
	"IsTokenRestricted",
	"IsTokenUntrusted",
	"IsValidAcl",
	"IsValidRelativeSecurityDescriptor",
	"IsValidSecurityDescriptor",
	"IsValidSid",
	"IsWellKnownSid",
	"LockServiceDatabase",
	"LogonUserA",
	"LogonUserExA",
	"LogonUserExExW",
	"LogonUserExW",
	"LogonUserW",
	"LookupAccountNameA",
	"LookupAccountNameW",
	"LookupAccountSidA",
	"LookupAccountSidW",
	"LookupPrivilegeDisplayNameA",
	"LookupPrivilegeDisplayNameW",
	"LookupPrivilegeNameA",
	"LookupPrivilegeNameW",
	"LookupPrivilegeValueA",
	"LookupPrivilegeValueW",
	"LookupSecurityDescriptorPartsA",
	"LookupSecurityDescriptorPartsW",
	"LsaAddAccountRights",
	"LsaAddPrivilegesToAccount",
	"LsaClearAuditLog",
	"LsaClose",
	"LsaCreateAccount",
	"LsaCreateSecret",
	"LsaCreateTrustedDomain",
	"LsaCreateTrustedDomainEx",
	"LsaDelete",
	"LsaDeleteTrustedDomain",
	"LsaEnumerateAccountRights",
	"LsaEnumerateAccounts",
	"LsaEnumerateAccountsWithUserRight",
	"LsaEnumeratePrivileges",
	"LsaEnumeratePrivilegesOfAccount",
	"LsaEnumerateTrustedDomains",
	"LsaEnumerateTrustedDomainsEx",
	"LsaFreeMemory",
	"LsaGetQuotasForAccount",
	"LsaGetRemoteUserName",
	"LsaGetSystemAccessAccount",
	"LsaGetUserName",
	"LsaICLookupNames",
	"LsaICLookupNamesWithCreds",
	"LsaICLookupSids",
	"LsaICLookupSidsWithCreds",
	"LsaLookupNames2",
	"LsaLookupNames",
	"LsaLookupPrivilegeDisplayName",
	"LsaLookupPrivilegeName",
	"LsaLookupPrivilegeValue",
	"LsaLookupSids",
	"LsaManageSidNameMapping",
	"LsaNtStatusToWinError",
	"LsaOpenAccount",
	"LsaOpenPolicy",
	"LsaOpenPolicySce",
	"LsaOpenSecret",
	"LsaOpenTrustedDomain",
	"LsaOpenTrustedDomainByName",
	"LsaQueryDomainInformationPolicy",
	"LsaQueryForestTrustInformation",
	"LsaQueryInfoTrustedDomain",
	"LsaQueryInformationPolicy",
	"LsaQuerySecret",
	"LsaQuerySecurityObject",
	"LsaQueryTrustedDomainInfo",
	"LsaQueryTrustedDomainInfoByName",
	"LsaRemoveAccountRights",
	"LsaRemovePrivilegesFromAccount",
	"LsaRetrievePrivateData",
	"LsaSetDomainInformationPolicy",
	"LsaSetForestTrustInformation",
	"LsaSetInformationPolicy",
	"LsaSetInformationTrustedDomain",
	"LsaSetQuotasForAccount",
	"LsaSetSecret",
	"LsaSetSecurityObject",
	"LsaSetSystemAccessAccount",
	"LsaSetTrustedDomainInfoByName",
	"LsaSetTrustedDomainInformation",
	"LsaStorePrivateData",
	"MD4Final",
	"MD4Init",
	"MD4Update",
	"MD5Final",
	"MD5Init",
	"MD5Update",
	"MSChapSrvChangePassword2",
	"MSChapSrvChangePassword",
	"MakeAbsoluteSD2",
	"MakeAbsoluteSD",
	"MakeSelfRelativeSD",
	"MapGenericMask",
	"NotifyBootConfigStatus",
	"NotifyChangeEventLog",
	"NotifyServiceStatusChange",
	"NotifyServiceStatusChangeA",
	"NotifyServiceStatusChangeW",
	"ObjectCloseAuditAlarmA",
	"ObjectCloseAuditAlarmW",
	"ObjectDeleteAuditAlarmA",
	"ObjectDeleteAuditAlarmW",
	"ObjectOpenAuditAlarmA",
	"ObjectOpenAuditAlarmW",
	"ObjectPrivilegeAuditAlarmA",
	"ObjectPrivilegeAuditAlarmW",
	"OpenBackupEventLogA",
	"OpenBackupEventLogW",
	"OpenEncryptedFileRawA",
	"OpenEncryptedFileRawW",
	"OpenEventLogA",
	"OpenEventLogW",
	"OpenProcessToken",
	"OpenSCManagerA",
	"OpenSCManagerW",
	"OpenServiceA",
	"OpenServiceW",
	"OpenThreadToken",
	"OpenThreadWaitChainSession",
	"OpenTraceA",
	"OpenTraceW",
	"PerfAddCounters",
	"PerfCloseQueryHandle",
	"PerfCreateInstance",
	"PerfDecrementULongCounterValue",
	"PerfDecrementULongLongCounterValue",
	"PerfDeleteCounters",
	"PerfDeleteInstance",
	"PerfEnumerateCounterSet",
	"PerfEnumerateCounterSetInstances",
	"PerfIncrementULongCounterValue",
	"PerfIncrementULongLongCounterValue",
	"PerfOpenQueryHandle",
	"PerfQueryCounterData",
	"PerfQueryCounterInfo",
	"PerfQueryCounterSetRegistrationInfo",
	"PerfQueryInstance",
	"PerfSetCounterRefValue",
	"PerfSetCounterSetInfo",
	"PerfSetULongCounterValue",
	"PerfSetULongLongCounterValue",
	"PerfStartProvider",
	"PerfStartProviderEx",
	"PerfStopProvider",
	"PrivilegeCheck",
	"PrivilegedServiceAuditAlarmA",
	"PrivilegedServiceAuditAlarmW",
	"ProcessIdleTasks",
	"ProcessIdleTasksW",
	"ProcessTrace",
	"QueryAllTracesA",
	"QueryAllTracesW",
	"QueryRecoveryAgentsOnEncryptedFile",
	"QuerySecurityAccessMask",
	"QueryServiceConfig2A",
	"QueryServiceConfig2W",
	"QueryServiceConfigA",
	"QueryServiceConfigW",
	"QueryServiceLockStatusA",
	"QueryServiceLockStatusW",
	"QueryServiceObjectSecurity",
	"QueryServiceStatus",
	"QueryServiceStatusEx",
	"QueryTraceA",
	"QueryTraceW",
	"QueryUsersOnEncryptedFile",
	"ReadEncryptedFileRaw",
	"ReadEventLogA",
	"ReadEventLogW",
	"RegCloseKey",
	"RegConnectRegistryA",
	"RegConnectRegistryExA",
	"RegConnectRegistryExW",
	"RegConnectRegistryW",
	"RegCopyTreeA",
	"RegCopyTreeW",
	"RegCreateKeyA",
	"RegCreateKeyExA",
	"RegCreateKeyExW",
	"RegCreateKeyTransactedA",
	"RegCreateKeyTransactedW",
	"RegCreateKeyW",
	"RegDeleteKeyA",
	"RegDeleteKeyExA",
	"RegDeleteKeyExW",
	"RegDeleteKeyTransactedA",
	"RegDeleteKeyTransactedW",
	"RegDeleteKeyValueA",
	"RegDeleteKeyValueW",
	"RegDeleteKeyW",
	"RegDeleteTreeA",
	"RegDeleteTreeW",
	"RegDeleteValueA",
	"RegDeleteValueW",
	"RegDisablePredefinedCache",
	"RegDisablePredefinedCacheEx",
	"RegDisableReflectionKey",
	"RegEnableReflectionKey",
	"RegEnumKeyA",
	"RegEnumKeyExA",
	"RegEnumKeyExW",
	"RegEnumKeyW",
	"RegEnumValueA",
	"RegEnumValueW",
	"RegFlushKey",
	"RegGetKeySecurity",
	"RegGetValueA",
	"RegGetValueW",
	"RegLoadAppKeyA",
	"RegLoadAppKeyW",
	"RegLoadKeyA",
	"RegLoadKeyW",
	"RegLoadMUIStringA",
	"RegLoadMUIStringW",
	"RegNotifyChangeKeyValue",
	"RegOpenCurrentUser",
	"RegOpenKeyA",
	"RegOpenKeyExA",
	"RegOpenKeyExW",
	"RegOpenKeyTransactedA",
	"RegOpenKeyTransactedW",
	"RegOpenKeyW",
	"RegOpenUserClassesRoot",
	"RegOverridePredefKey",
	"RegQueryInfoKeyA",
	"RegQueryInfoKeyW",
	"RegQueryMultipleValuesA",
	"RegQueryMultipleValuesW",
	"RegQueryReflectionKey",
	"RegQueryValueA",
	"RegQueryValueExA",
	"RegQueryValueExW",
	"RegQueryValueW",
	"RegRenameKey",
	"RegReplaceKeyA",
	"RegReplaceKeyW",
	"RegRestoreKeyA",
	"RegRestoreKeyW",
	"RegSaveKeyA",
	"RegSaveKeyExA",
	"RegSaveKeyExW",
	"RegSaveKeyW",
	"RegSetKeySecurity",
	"RegSetKeyValueA",
	"RegSetKeyValueW",
	"RegSetValueA",
	"RegSetValueExA",
	"RegSetValueExW",
	"RegSetValueW",
	"RegUnLoadKeyA",
	"RegUnLoadKeyW",
	"RegisterEventSourceA",
	"RegisterEventSourceW",
	"RegisterIdleTask",
	"RegisterServiceCtrlHandlerA",
	"RegisterServiceCtrlHandlerExA",
	"RegisterServiceCtrlHandlerExW",
	"RegisterServiceCtrlHandlerW",
	"RegisterTraceGuidsA",
	"RegisterTraceGuidsW",
	"RegisterWaitChainCOMCallback",
	"RemoveTraceCallback",
	"RemoveUsersFromEncryptedFile",
	"ReportEventA",
	"ReportEventW",
	"RevertToSelf",
	"SaferCloseLevel",
	"SaferComputeTokenFromLevel",
	"SaferCreateLevel",
	"SaferGetLevelInformation",
	"SaferGetPolicyInformation",
	"SaferIdentifyLevel",
	"SaferRecordEventLogEntry",
	"SaferSetLevelInformation",
	"SaferSetPolicyInformation",
	"SaferiChangeRegistryScope",
	"SaferiCompareTokenLevels",
	"SaferiIsDllAllowed",
	"SaferiIsExecutableFileType",
	"SaferiPopulateDefaultsInRegistry",
	"SaferiRecordEventLogEntry",
	"SaferiSearchMatchingHashRules",
	"SetAclInformation",
	"SetEncryptedFileMetadata",
	"SetEntriesInAccessListA",
	"SetEntriesInAccessListW",
	"SetEntriesInAclA",
	"SetEntriesInAclW",
	"SetEntriesInAuditListA",
	"SetEntriesInAuditListW",
	"SetFileSecurityA",
	"SetFileSecurityW",
	"SetInformationCodeAuthzLevelW",
	"SetInformationCodeAuthzPolicyW",
	"SetKernelObjectSecurity",
	"SetNamedSecurityInfoA",
	"SetNamedSecurityInfoExA",
	"SetNamedSecurityInfoExW",
	"SetNamedSecurityInfoW",
	"SetPrivateObjectSecurity",
	"SetPrivateObjectSecurityEx",
	"SetSecurityAccessMask",
	"SetSecurityDescriptorControl",
	"SetSecurityDescriptorDacl",
	"SetSecurityDescriptorGroup",
	"SetSecurityDescriptorOwner",
	"SetSecurityDescriptorRMControl",
	"SetSecurityDescriptorSacl",
	"SetSecurityInfo",
	"SetSecurityInfoExA",
	"SetSecurityInfoExW",
	"SetServiceBits",
	"SetServiceObjectSecurity",
	"SetServiceStatus",
	"SetThreadToken",
	"SetTokenInformation",
	"SetTraceCallback",
	"SetUserFileEncryptionKey",
	"SetUserFileEncryptionKeyEx",
	"StartServiceA",
	"StartServiceCtrlDispatcherA",
	"StartServiceCtrlDispatcherW",
	"StartServiceW",
	"StartTraceA",
	"StartTraceW",
	"StopTraceA",
	"StopTraceW",
	"SystemFunction001",
	"SystemFunction002",
	"SystemFunction003",
	"SystemFunction004",
	"SystemFunction005",
	"SystemFunction006",
	"SystemFunction007",
	"SystemFunction008",
	"SystemFunction009",
	"SystemFunction010",
	"SystemFunction011",
	"SystemFunction012",
	"SystemFunction013",
	"SystemFunction014",
	"SystemFunction015",
	"SystemFunction016",
	"SystemFunction017",
	"SystemFunction018",
	"SystemFunction019",
	"SystemFunction020",
	"SystemFunction021",
	"SystemFunction022",
	"SystemFunction023",
	"SystemFunction024",
	"SystemFunction025",
	"SystemFunction026",
	"SystemFunction027",
	"SystemFunction028",
	"SystemFunction029",
	"SystemFunction030",
	"SystemFunction031",
	"SystemFunction032",
	"SystemFunction033",
	"SystemFunction034",
	"SystemFunction035",
	"SystemFunction036",
	"SystemFunction040",
	"SystemFunction041",
	"TraceEvent",
	"TraceEventInstance",
	"TraceMessage",
	"TraceMessageVa",
	"TraceSetInformation",
	"TreeResetNamedSecurityInfoA",
	"TreeResetNamedSecurityInfoW",
	"TreeSetNamedSecurityInfoA",
	"TreeSetNamedSecurityInfoW",
	"TrusteeAccessToObjectA",
	"TrusteeAccessToObjectW",
	"UninstallApplication",
	"UnlockServiceDatabase",
	"UnregisterIdleTask",
	"UnregisterTraceGuids",
	"UpdateTraceA",
	"UpdateTraceW",
	"UsePinForEncryptedFilesA",
	"UsePinForEncryptedFilesW",
	"WmiCloseBlock",
	"WmiDevInstToInstanceNameA",
	"WmiDevInstToInstanceNameW",
	"WmiEnumerateGuids",
	"WmiExecuteMethodA",
	"WmiExecuteMethodW",
	"WmiFileHandleToInstanceNameA",
	"WmiFileHandleToInstanceNameW",
	"WmiFreeBuffer",
	"WmiMofEnumerateResourcesA",
	"WmiMofEnumerateResourcesW",
	"WmiNotificationRegistrationA",
	"WmiNotificationRegistrationW",
	"WmiOpenBlock",
	"WmiQueryAllDataA",
	"WmiQueryAllDataMultipleA",
	"WmiQueryAllDataMultipleW",
	"WmiQueryAllDataW",
	"WmiQueryGuidInformation",
	"WmiQuerySingleInstanceA",
	"WmiQuerySingleInstanceMultipleA",
	"WmiQuerySingleInstanceMultipleW",
	"WmiQuerySingleInstanceW",
	"WmiReceiveNotificationsA",
	"WmiReceiveNotificationsW",
	"WmiSetSingleInstanceA",
	"WmiSetSingleInstanceW",
	"WmiSetSingleItemA",
	"WmiSetSingleItemW",
	"WriteEncryptedFileRaw"
};

bool Advapi_Support[] =
{
false,	// ADVAPI32_1000
false,	// I_ScGetCurrentGroupStateW
false,	// A_SHAFinal
false,	// A_SHAInit
false,	// A_SHAUpdate
false,	// AbortSystemShutdownA
false,	// AbortSystemShutdownW
false,	// AccessCheck
false,	// AccessCheckAndAuditAlarmA
false,	// AccessCheckAndAuditAlarmW
false,	// AccessCheckByType
false,	// AccessCheckByTypeAndAuditAlarmA
false,	// AccessCheckByTypeAndAuditAlarmW
false,	// AccessCheckByTypeResultList
false,	// AccessCheckByTypeResultListAndAuditAlarmA
false,	// AccessCheckByTypeResultListAndAuditAlarmByHandleA
false,	// AccessCheckByTypeResultListAndAuditAlarmByHandleW
false,	// AccessCheckByTypeResultListAndAuditAlarmW
false,	// AddAccessAllowedAce
false,	// AddAccessAllowedAceEx
false,	// AddAccessAllowedObjectAce
false,	// AddAccessDeniedAce
false,	// AddAccessDeniedAceEx
false,	// AddAccessDeniedObjectAce
false,	// AddAce
false,	// AddAuditAccessAce
false,	// AddAuditAccessAceEx
false,	// AddAuditAccessObjectAce
false,	// AddConditionalAce
false,	// AddMandatoryAce
false,	// AddUsersToEncryptedFile
false,	// AddUsersToEncryptedFileEx
false,	// AdjustTokenGroups
false,	// AdjustTokenPrivileges
false,	// AllocateAndInitializeSid
false,	// AllocateLocallyUniqueId
false,	// AreAllAccessesGranted
false,	// AreAnyAccessesGranted
false,	// AuditComputeEffectivePolicyBySid
false,	// AuditComputeEffectivePolicyByToken
false,	// AuditEnumerateCategories
false,	// AuditEnumeratePerUserPolicy
false,	// AuditEnumerateSubCategories
false,	// AuditFree
false,	// AuditLookupCategoryGuidFromCategoryId
false,	// AuditLookupCategoryIdFromCategoryGuid
false,	// AuditLookupCategoryNameA
false,	// AuditLookupCategoryNameW
false,	// AuditLookupSubCategoryNameA
false,	// AuditLookupSubCategoryNameW
false,	// AuditQueryGlobalSaclA
false,	// AuditQueryGlobalSaclW
false,	// AuditQueryPerUserPolicy
false,	// AuditQuerySecurity
false,	// AuditQuerySystemPolicy
false,	// AuditSetGlobalSaclA
false,	// AuditSetGlobalSaclW
false,	// AuditSetPerUserPolicy
false,	// AuditSetSecurity
false,	// AuditSetSystemPolicy
false,	// BackupEventLogA
false,	// BackupEventLogW
false,	// BuildExplicitAccessWithNameA
false,	// BuildExplicitAccessWithNameW
false,	// BuildImpersonateExplicitAccessWithNameA
false,	// BuildImpersonateExplicitAccessWithNameW
false,	// BuildImpersonateTrusteeA
false,	// BuildImpersonateTrusteeW
false,	// BuildSecurityDescriptorA
false,	// BuildSecurityDescriptorW
false,	// BuildTrusteeWithNameA
false,	// BuildTrusteeWithNameW
false,	// BuildTrusteeWithObjectsAndNameA
false,	// BuildTrusteeWithObjectsAndNameW
false,	// BuildTrusteeWithObjectsAndSidA
false,	// BuildTrusteeWithObjectsAndSidW
false,	// BuildTrusteeWithSidA
false,	// BuildTrusteeWithSidW
false,	// CancelOverlappedAccess
false,	// ChangeServiceConfig2A
false,	// ChangeServiceConfig2W
false,	// ChangeServiceConfigA
false,	// ChangeServiceConfigW
false,	// CheckTokenMembership
false,	// ClearEventLogA
false,	// ClearEventLogW
false,	// CloseCodeAuthzLevel
false,	// CloseEncryptedFileRaw
false,	// CloseEventLog
false,	// CloseServiceHandle
false,	// CloseThreadWaitChainSession
false,	// CloseTrace
false,	// CommandLineFromMsiDescriptor
false,	// ComputeAccessTokenFromCodeAuthzLevel
false,	// ControlService
false,	// ControlServiceExA
false,	// ControlServiceExW
false,	// ControlTraceA
false,	// ControlTraceW
false,	// ConvertAccessToSecurityDescriptorA
false,	// ConvertAccessToSecurityDescriptorW
false,	// ConvertSDToStringSDRootDomainA
false,	// ConvertSDToStringSDRootDomainW
false,	// ConvertSecurityDescriptorToAccessA
false,	// ConvertSecurityDescriptorToAccessNamedA
false,	// ConvertSecurityDescriptorToAccessNamedW
false,	// ConvertSecurityDescriptorToAccessW
false,	// ConvertSecurityDescriptorToStringSecurityDescriptorA
false,	// ConvertSecurityDescriptorToStringSecurityDescriptorW
false,	// ConvertSidToStringSidA
false,	// ConvertSidToStringSidW
false,	// ConvertStringSDToSDDomainA
false,	// ConvertStringSDToSDDomainW
false,	// ConvertStringSDToSDRootDomainA
false,	// ConvertStringSDToSDRootDomainW
false,	// ConvertStringSecurityDescriptorToSecurityDescriptorA
false,	// ConvertStringSecurityDescriptorToSecurityDescriptorW
false,	// ConvertStringSidToSidA
false,	// ConvertStringSidToSidW
false,	// ConvertToAutoInheritPrivateObjectSecurity
false,	// CopySid
false,	// CreateCodeAuthzLevel
false,	// CreatePrivateObjectSecurity
false,	// CreatePrivateObjectSecurityEx
false,	// CreatePrivateObjectSecurityWithMultipleInheritance
false,	// CreateProcessAsUserA
false,	// CreateProcessAsUserW
false,	// CreateProcessWithLogonW
false,	// CreateProcessWithTokenW
false,	// CreateRestrictedToken
false,	// CreateServiceA
false,	// CreateServiceW
false,	// CreateTraceInstanceId
false,	// CreateWellKnownSid
false,	// CredBackupCredentials
false,	// CredDeleteA
false,	// CredDeleteW
false,	// CredEncryptAndMarshalBinaryBlob
false,	// CredEnumerateA
false,	// CredEnumerateW
false,	// CredFindBestCredentialA
false,	// CredFindBestCredentialW
false,	// CredFree
false,	// CredGetSessionTypes
false,	// CredGetTargetInfoA
false,	// CredGetTargetInfoW
false,	// CredIsMarshaledCredentialA
false,	// CredIsMarshaledCredentialW
false,	// CredIsProtectedA
false,	// CredIsProtectedW
false,	// CredMarshalCredentialA
false,	// CredMarshalCredentialW
false,	// CredProfileLoaded
false,	// CredProfileUnloaded
false,	// CredProtectA
false,	// CredProtectW
false,	// CredReadA
false,	// CredReadByTokenHandle
false,	// CredReadDomainCredentialsA
false,	// CredReadDomainCredentialsW
false,	// CredReadW
false,	// CredRenameA
false,	// CredRenameW
false,	// CredRestoreCredentials
false,	// CredUnmarshalCredentialA
false,	// CredUnmarshalCredentialW
false,	// CredUnprotectA
false,	// CredUnprotectW
false,	// CredWriteA
false,	// CredWriteDomainCredentialsA
false,	// CredWriteDomainCredentialsW
false,	// CredWriteW
false,	// CredpConvertCredential
false,	// CredpConvertOneCredentialSize
false,	// CredpConvertTargetInfo
false,	// CredpDecodeCredential
false,	// CredpEncodeCredential
false,	// CredpEncodeSecret
false,	// CryptAcquireContextA
false,	// CryptAcquireContextW
false,	// CryptContextAddRef
false,	// CryptCreateHash
false,	// CryptDecrypt
false,	// CryptDeriveKey
false,	// CryptDestroyHash
false,	// CryptDestroyKey
false,	// CryptDuplicateHash
false,	// CryptDuplicateKey
false,	// CryptEncrypt
false,	// CryptEnumProviderTypesA
false,	// CryptEnumProviderTypesW
false,	// CryptEnumProvidersA
false,	// CryptEnumProvidersW
false,	// CryptExportKey
false,	// CryptGenKey
false,	// CryptGenRandom
false,	// CryptGetDefaultProviderA
false,	// CryptGetDefaultProviderW
false,	// CryptGetHashParam
false,	// CryptGetKeyParam
false,	// CryptGetProvParam
false,	// CryptGetUserKey
false,	// CryptHashData
false,	// CryptHashSessionKey
false,	// CryptImportKey
false,	// CryptReleaseContext
false,	// CryptSetHashParam
false,	// CryptSetKeyParam
false,	// CryptSetProvParam
false,	// CryptSetProviderA
false,	// CryptSetProviderExA
false,	// CryptSetProviderExW
false,	// CryptSetProviderW
false,	// CryptSignHashA
false,	// CryptSignHashW
false,	// CryptVerifySignatureA
false,	// CryptVerifySignatureW
false,	// DecryptFileA
false,	// DecryptFileW
false,	// DeleteAce
false,	// DeleteService
false,	// DeregisterEventSource
false,	// DestroyPrivateObjectSecurity
false,	// DuplicateEncryptionInfoFile
false,	// DuplicateToken
false,	// DuplicateTokenEx
false,	// ElfBackupEventLogFileA
false,	// ElfBackupEventLogFileW
false,	// ElfChangeNotify
false,	// ElfClearEventLogFileA
false,	// ElfClearEventLogFileW
false,	// ElfCloseEventLog
false,	// ElfDeregisterEventSource
false,	// ElfFlushEventLog
false,	// ElfNumberOfRecords
false,	// ElfOldestRecord
false,	// ElfOpenBackupEventLogA
false,	// ElfOpenBackupEventLogW
false,	// ElfOpenEventLogA
false,	// ElfOpenEventLogW
false,	// ElfReadEventLogA
false,	// ElfReadEventLogW
false,	// ElfRegisterEventSourceA
false,	// ElfRegisterEventSourceW
false,	// ElfReportEventA
false,	// ElfReportEventAndSourceW
false,	// ElfReportEventW
false,	// EnableTrace
false,	// EnableTraceEx2
false,	// EnableTraceEx
false,	// EncryptFileA
false,	// EncryptFileW
false,	// EncryptedFileKeyInfo
false,	// EncryptionDisable
false,	// EnumDependentServicesA
false,	// EnumDependentServicesW
false,	// EnumServiceGroupW
false,	// EnumServicesStatusA
false,	// EnumServicesStatusExA
false,	// EnumServicesStatusExW
false,	// EnumServicesStatusW
false,	// EnumerateTraceGuids
false,	// EnumerateTraceGuidsEx
false,	// EqualDomainSid
false,	// EqualPrefixSid
false,	// EqualSid
false,	// EventAccessControl
false,	// EventAccessQuery
false,	// EventAccessRemove
false,	// EventActivityIdControl
false,	// EventEnabled
false,	// EventProviderEnabled
false,	// EventRegister
false,	// EventUnregister
false,	// EventWrite
false,	// EventWriteEndScenario
false,	// EventWriteEx
false,	// EventWriteStartScenario
false,	// EventWriteString
false,	// EventWriteTransfer
false,	// FileEncryptionStatusA
false,	// FileEncryptionStatusW
false,	// FindFirstFreeAce
false,	// FlushEfsCache
false,	// FlushTraceA
false,	// FlushTraceW
false,	// FreeEncryptedFileKeyInfo
false,	// FreeEncryptedFileMetadata
false,	// FreeEncryptionCertificateHashList
false,	// FreeInheritedFromArray
false,	// FreeSid
false,	// GetAccessPermissionsForObjectA
false,	// GetAccessPermissionsForObjectW
false,	// GetAce
false,	// GetAclInformation
false,	// GetAuditedPermissionsFromAclA
false,	// GetAuditedPermissionsFromAclW
false,	// GetCurrentHwProfileA
false,	// GetCurrentHwProfileW
false,	// GetEffectiveRightsFromAclA
false,	// GetEffectiveRightsFromAclW
false,	// GetEncryptedFileMetadata
false,	// GetEventLogInformation
false,	// GetExplicitEntriesFromAclA
false,	// GetExplicitEntriesFromAclW
false,	// GetFileSecurityA
false,	// GetFileSecurityW
false,	// GetInformationCodeAuthzLevelW
false,	// GetInformationCodeAuthzPolicyW
false,	// GetInheritanceSourceA
false,	// GetInheritanceSourceW
false,	// GetKernelObjectSecurity
false,	// GetLengthSid
false,	// GetLocalManagedApplicationData
false,	// GetLocalManagedApplications
false,	// GetManagedApplicationCategories
false,	// GetManagedApplications
false,	// GetMultipleTrusteeA
false,	// GetMultipleTrusteeOperationA
false,	// GetMultipleTrusteeOperationW
false,	// GetMultipleTrusteeW
false,	// GetNamedSecurityInfoA
false,	// GetNamedSecurityInfoExA
false,	// GetNamedSecurityInfoExW
false,	// GetNamedSecurityInfoW
false,	// GetNumberOfEventLogRecords
false,	// GetOldestEventLogRecord
false,	// GetOverlappedAccessResults
false,	// GetPrivateObjectSecurity
false,	// GetSecurityDescriptorControl
false,	// GetSecurityDescriptorDacl
false,	// GetSecurityDescriptorGroup
false,	// GetSecurityDescriptorLength
false,	// GetSecurityDescriptorOwner
false,	// GetSecurityDescriptorRMControl
false,	// GetSecurityDescriptorSacl
false,	// GetSecurityInfo
false,	// GetSecurityInfoExA
false,	// GetSecurityInfoExW
false,	// GetServiceDisplayNameA
false,	// GetServiceDisplayNameW
false,	// GetServiceKeyNameA
false,	// GetServiceKeyNameW
false,	// GetSidIdentifierAuthority
false,	// GetSidLengthRequired
false,	// GetSidSubAuthority
false,	// GetSidSubAuthorityCount
false,	// GetThreadWaitChain
false,	// GetTokenInformation
false,	// GetTraceEnableFlags
false,	// GetTraceEnableLevel
false,	// GetTraceLoggerHandle
false,	// GetTrusteeFormA
false,	// GetTrusteeFormW
false,	// GetTrusteeNameA
false,	// GetTrusteeNameW
false,	// GetTrusteeTypeA
false,	// GetTrusteeTypeW
false,	// GetUserNameA
false,	// GetUserNameW
false,	// GetWindowsAccountDomainSid
false,	// I_QueryTagInformation
false,	// I_ScIsSecurityProcess
false,	// I_ScPnPGetServiceName
false,	// I_ScQueryServiceConfig
false,	// I_ScSendPnPMessage
false,	// I_ScSendTSMessage
false,	// I_ScSetServiceBitsA
false,	// I_ScSetServiceBitsW
false,	// I_ScValidatePnPService
false,	// IdentifyCodeAuthzLevelW
false,	// ImpersonateAnonymousToken
false,	// ImpersonateLoggedOnUser
false,	// ImpersonateNamedPipeClient
false,	// ImpersonateSelf
false,	// InitializeAcl
false,	// InitializeSecurityDescriptor
false,	// InitializeSid
false,	// InitiateShutdownA
false,	// InitiateShutdownW
false,	// InitiateSystemShutdownA
false,	// InitiateSystemShutdownExA
false,	// InitiateSystemShutdownExW
false,	// InitiateSystemShutdownW
false,	// InstallApplication
false,	// IsTextUnicode
false,	// IsTokenRestricted
false,	// IsTokenUntrusted
false,	// IsValidAcl
false,	// IsValidRelativeSecurityDescriptor
false,	// IsValidSecurityDescriptor
false,	// IsValidSid
false,	// IsWellKnownSid
false,	// LockServiceDatabase
false,	// LogonUserA
false,	// LogonUserExA
false,	// LogonUserExExW
false,	// LogonUserExW
false,	// LogonUserW
false,	// LookupAccountNameA
false,	// LookupAccountNameW
false,	// LookupAccountSidA
false,	// LookupAccountSidW
false,	// LookupPrivilegeDisplayNameA
false,	// LookupPrivilegeDisplayNameW
false,	// LookupPrivilegeNameA
false,	// LookupPrivilegeNameW
false,	// LookupPrivilegeValueA
false,	// LookupPrivilegeValueW
false,	// LookupSecurityDescriptorPartsA
false,	// LookupSecurityDescriptorPartsW
false,	// LsaAddAccountRights
false,	// LsaAddPrivilegesToAccount
false,	// LsaClearAuditLog
false,	// LsaClose
false,	// LsaCreateAccount
false,	// LsaCreateSecret
false,	// LsaCreateTrustedDomain
false,	// LsaCreateTrustedDomainEx
false,	// LsaDelete
false,	// LsaDeleteTrustedDomain
false,	// LsaEnumerateAccountRights
false,	// LsaEnumerateAccounts
false,	// LsaEnumerateAccountsWithUserRight
false,	// LsaEnumeratePrivileges
false,	// LsaEnumeratePrivilegesOfAccount
false,	// LsaEnumerateTrustedDomains
false,	// LsaEnumerateTrustedDomainsEx
false,	// LsaFreeMemory
false,	// LsaGetQuotasForAccount
false,	// LsaGetRemoteUserName
false,	// LsaGetSystemAccessAccount
false,	// LsaGetUserName
false,	// LsaICLookupNames
false,	// LsaICLookupNamesWithCreds
false,	// LsaICLookupSids
false,	// LsaICLookupSidsWithCreds
false,	// LsaLookupNames2
false,	// LsaLookupNames
false,	// LsaLookupPrivilegeDisplayName
false,	// LsaLookupPrivilegeName
false,	// LsaLookupPrivilegeValue
false,	// LsaLookupSids
false,	// LsaManageSidNameMapping
false,	// LsaNtStatusToWinError
false,	// LsaOpenAccount
false,	// LsaOpenPolicy
false,	// LsaOpenPolicySce
false,	// LsaOpenSecret
false,	// LsaOpenTrustedDomain
false,	// LsaOpenTrustedDomainByName
false,	// LsaQueryDomainInformationPolicy
false,	// LsaQueryForestTrustInformation
false,	// LsaQueryInfoTrustedDomain
false,	// LsaQueryInformationPolicy
false,	// LsaQuerySecret
false,	// LsaQuerySecurityObject
false,	// LsaQueryTrustedDomainInfo
false,	// LsaQueryTrustedDomainInfoByName
false,	// LsaRemoveAccountRights
false,	// LsaRemovePrivilegesFromAccount
false,	// LsaRetrievePrivateData
false,	// LsaSetDomainInformationPolicy
false,	// LsaSetForestTrustInformation
false,	// LsaSetInformationPolicy
false,	// LsaSetInformationTrustedDomain
false,	// LsaSetQuotasForAccount
false,	// LsaSetSecret
false,	// LsaSetSecurityObject
false,	// LsaSetSystemAccessAccount
false,	// LsaSetTrustedDomainInfoByName
false,	// LsaSetTrustedDomainInformation
false,	// LsaStorePrivateData
false,	// MD4Final
false,	// MD4Init
false,	// MD4Update
false,	// MD5Final
false,	// MD5Init
false,	// MD5Update
false,	// MSChapSrvChangePassword2
false,	// MSChapSrvChangePassword
false,	// MakeAbsoluteSD2
false,	// MakeAbsoluteSD
false,	// MakeSelfRelativeSD
false,	// MapGenericMask
false,	// NotifyBootConfigStatus
false,	// NotifyChangeEventLog
false,	// NotifyServiceStatusChange
false,	// NotifyServiceStatusChangeA
false,	// NotifyServiceStatusChangeW
false,	// ObjectCloseAuditAlarmA
false,	// ObjectCloseAuditAlarmW
false,	// ObjectDeleteAuditAlarmA
false,	// ObjectDeleteAuditAlarmW
false,	// ObjectOpenAuditAlarmA
false,	// ObjectOpenAuditAlarmW
false,	// ObjectPrivilegeAuditAlarmA
false,	// ObjectPrivilegeAuditAlarmW
false,	// OpenBackupEventLogA
false,	// OpenBackupEventLogW
false,	// OpenEncryptedFileRawA
false,	// OpenEncryptedFileRawW
false,	// OpenEventLogA
false,	// OpenEventLogW
false,	// OpenProcessToken
false,	// OpenSCManagerA
false,	// OpenSCManagerW
false,	// OpenServiceA
false,	// OpenServiceW
false,	// OpenThreadToken
false,	// OpenThreadWaitChainSession
false,	// OpenTraceA
false,	// OpenTraceW
false,	// PerfAddCounters
false,	// PerfCloseQueryHandle
false,	// PerfCreateInstance
false,	// PerfDecrementULongCounterValue
false,	// PerfDecrementULongLongCounterValue
false,	// PerfDeleteCounters
false,	// PerfDeleteInstance
false,	// PerfEnumerateCounterSet
false,	// PerfEnumerateCounterSetInstances
false,	// PerfIncrementULongCounterValue
false,	// PerfIncrementULongLongCounterValue
false,	// PerfOpenQueryHandle
false,	// PerfQueryCounterData
false,	// PerfQueryCounterInfo
false,	// PerfQueryCounterSetRegistrationInfo
false,	// PerfQueryInstance
false,	// PerfSetCounterRefValue
false,	// PerfSetCounterSetInfo
false,	// PerfSetULongCounterValue
false,	// PerfSetULongLongCounterValue
false,	// PerfStartProvider
false,	// PerfStartProviderEx
false,	// PerfStopProvider
false,	// PrivilegeCheck
false,	// PrivilegedServiceAuditAlarmA
false,	// PrivilegedServiceAuditAlarmW
false,	// ProcessIdleTasks
false,	// ProcessIdleTasksW
false,	// ProcessTrace
false,	// QueryAllTracesA
false,	// QueryAllTracesW
false,	// QueryRecoveryAgentsOnEncryptedFile
false,	// QuerySecurityAccessMask
false,	// QueryServiceConfig2A
false,	// QueryServiceConfig2W
false,	// QueryServiceConfigA
false,	// QueryServiceConfigW
false,	// QueryServiceLockStatusA
false,	// QueryServiceLockStatusW
false,	// QueryServiceObjectSecurity
false,	// QueryServiceStatus
false,	// QueryServiceStatusEx
false,	// QueryTraceA
false,	// QueryTraceW
false,	// QueryUsersOnEncryptedFile
false,	// ReadEncryptedFileRaw
false,	// ReadEventLogA
false,	// ReadEventLogW

//-----------------------------------------------------------------------------

true,	// RegCloseKey
true,	// RegConnectRegistryA
false,	// RegConnectRegistryExA
false,	// RegConnectRegistryExW
false,	// RegConnectRegistryW
false,	// RegCopyTreeA
false,	// RegCopyTreeW
true,	// RegCreateKeyA
true,	// RegCreateKeyExA
true,	// RegCreateKeyExW
false,	// RegCreateKeyTransactedA
false,	// RegCreateKeyTransactedW
false,	// RegCreateKeyW
false,	// RegDeleteKeyA
false,	// RegDeleteKeyExA
false,	// RegDeleteKeyExW
false,	// RegDeleteKeyTransactedA
false,	// RegDeleteKeyTransactedW
false,	// RegDeleteKeyValueA
false,	// RegDeleteKeyValueW
false,	// RegDeleteKeyW
false,	// RegDeleteTreeA
false,	// RegDeleteTreeW
false,	// RegDeleteValueA
false,	// RegDeleteValueW
false,	// RegDisablePredefinedCache
false,	// RegDisablePredefinedCacheEx
false,	// RegDisableReflectionKey
false,	// RegEnableReflectionKey
false,	// RegEnumKeyA
false,	// RegEnumKeyExA
false,	// RegEnumKeyExW
false,	// RegEnumKeyW
false,	// RegEnumValueA
false,	// RegEnumValueW
true,	// RegFlushKey
false,	// RegGetKeySecurity
false,	// RegGetValueA
false,	// RegGetValueW
false,	// RegLoadAppKeyA
false,	// RegLoadAppKeyW
false,	// RegLoadKeyA
false,	// RegLoadKeyW
false,	// RegLoadMUIStringA
false,	// RegLoadMUIStringW
false,	// RegNotifyChangeKeyValue
false,	// RegOpenCurrentUser
true,	// RegOpenKeyA
true,	// RegOpenKeyExA
false,	// RegOpenKeyExW
false,	// RegOpenKeyTransactedA
false,	// RegOpenKeyTransactedW
false,	// RegOpenKeyW
false,	// RegOpenUserClassesRoot
false,	// RegOverridePredefKey
false,	// RegQueryInfoKeyA
false,	// RegQueryInfoKeyW
false,	// RegQueryMultipleValuesA
false,	// RegQueryMultipleValuesW
false,	// RegQueryReflectionKey
false,	// RegQueryValueA
true,	// RegQueryValueExA
false,	// RegQueryValueExW
false,	// RegQueryValueW
false,	// RegRenameKey
false,	// RegReplaceKeyA
false,	// RegReplaceKeyW
false,	// RegRestoreKeyA
false,	// RegRestoreKeyW
false,	// RegSaveKeyA
false,	// RegSaveKeyExA
false,	// RegSaveKeyExW
false,	// RegSaveKeyW
false,	// RegSetKeySecurity
false,	// RegSetKeyValueA
false,	// RegSetKeyValueW
false,	// RegSetValueA
true,	// RegSetValueExA
true,	// RegSetValueExW
false,	// RegSetValueW
false,	// RegUnLoadKeyA
false,	// RegUnLoadKeyW

//---------------------------------------------------------------------------

false,	// RegisterEventSourceA
false,	// RegisterEventSourceW
false,	// RegisterIdleTask
false,	// RegisterServiceCtrlHandlerA
false,	// RegisterServiceCtrlHandlerExA
false,	// RegisterServiceCtrlHandlerExW
false,	// RegisterServiceCtrlHandlerW
false,	// RegisterTraceGuidsA
false,	// RegisterTraceGuidsW
false,	// RegisterWaitChainCOMCallback
false,	// RemoveTraceCallback
false,	// RemoveUsersFromEncryptedFile
false,	// ReportEventA
false,	// ReportEventW
false,	// RevertToSelf
false,	// SaferCloseLevel
false,	// SaferComputeTokenFromLevel
false,	// SaferCreateLevel
false,	// SaferGetLevelInformation
false,	// SaferGetPolicyInformation
false,	// SaferIdentifyLevel
false,	// SaferRecordEventLogEntry
false,	// SaferSetLevelInformation
false,	// SaferSetPolicyInformation
false,	// SaferiChangeRegistryScope
false,	// SaferiCompareTokenLevels
false,	// SaferiIsDllAllowed
false,	// SaferiIsExecutableFileType
false,	// SaferiPopulateDefaultsInRegistry
false,	// SaferiRecordEventLogEntry
false,	// SaferiSearchMatchingHashRules
false,	// SetAclInformation
false,	// SetEncryptedFileMetadata
false,	// SetEntriesInAccessListA
false,	// SetEntriesInAccessListW
false,	// SetEntriesInAclA
false,	// SetEntriesInAclW
false,	// SetEntriesInAuditListA
false,	// SetEntriesInAuditListW
false,	// SetFileSecurityA
false,	// SetFileSecurityW
false,	// SetInformationCodeAuthzLevelW
false,	// SetInformationCodeAuthzPolicyW
false,	// SetKernelObjectSecurity
false,	// SetNamedSecurityInfoA
false,	// SetNamedSecurityInfoExA
false,	// SetNamedSecurityInfoExW
false,	// SetNamedSecurityInfoW
false,	// SetPrivateObjectSecurity
false,	// SetPrivateObjectSecurityEx
false,	// SetSecurityAccessMask
false,	// SetSecurityDescriptorControl
false,	// SetSecurityDescriptorDacl
false,	// SetSecurityDescriptorGroup
false,	// SetSecurityDescriptorOwner
false,	// SetSecurityDescriptorRMControl
false,	// SetSecurityDescriptorSacl
false,	// SetSecurityInfo
false,	// SetSecurityInfoExA
false,	// SetSecurityInfoExW
false,	// SetServiceBits
false,	// SetServiceObjectSecurity
false,	// SetServiceStatus
false,	// SetThreadToken
false,	// SetTokenInformation
false,	// SetTraceCallback
false,	// SetUserFileEncryptionKey
false,	// SetUserFileEncryptionKeyEx
false,	// StartServiceA
false,	// StartServiceCtrlDispatcherA
false,	// StartServiceCtrlDispatcherW
false,	// StartServiceW
false,	// StartTraceA
false,	// StartTraceW
false,	// StopTraceA
false,	// StopTraceW
false,	// SystemFunction001
false,	// SystemFunction002
false,	// SystemFunction003
false,	// SystemFunction004
false,	// SystemFunction005
false,	// SystemFunction006
false,	// SystemFunction007
false,	// SystemFunction008
false,	// SystemFunction009
false,	// SystemFunction010
false,	// SystemFunction011
false,	// SystemFunction012
false,	// SystemFunction013
false,	// SystemFunction014
false,	// SystemFunction015
false,	// SystemFunction016
false,	// SystemFunction017
false,	// SystemFunction018
false,	// SystemFunction019
false,	// SystemFunction020
false,	// SystemFunction021
false,	// SystemFunction022
false,	// SystemFunction023
false,	// SystemFunction024
false,	// SystemFunction025
false,	// SystemFunction026
false,	// SystemFunction027
false,	// SystemFunction028
false,	// SystemFunction029
false,	// SystemFunction030
false,	// SystemFunction031
false,	// SystemFunction032
false,	// SystemFunction033
false,	// SystemFunction034
false,	// SystemFunction035
false,	// SystemFunction036
false,	// SystemFunction040
false,	// SystemFunction041
false,	// TraceEvent
false,	// TraceEventInstance
false,	// TraceMessage
false,	// TraceMessageVa
false,	// TraceSetInformation
false,	// TreeResetNamedSecurityInfoA
false,	// TreeResetNamedSecurityInfoW
false,	// TreeSetNamedSecurityInfoA
false,	// TreeSetNamedSecurityInfoW
false,	// TrusteeAccessToObjectA
false,	// TrusteeAccessToObjectW
false,	// UninstallApplication
false,	// UnlockServiceDatabase
false,	// UnregisterIdleTask
false,	// UnregisterTraceGuids
false,	// UpdateTraceA
false,	// UpdateTraceW
false,	// UsePinForEncryptedFilesA
false,	// UsePinForEncryptedFilesW
false,	// WmiCloseBlock
false,	// WmiDevInstToInstanceNameA
false,	// WmiDevInstToInstanceNameW
false,	// WmiEnumerateGuids
false,	// WmiExecuteMethodA
false,	// WmiExecuteMethodW
false,	// WmiFileHandleToInstanceNameA
false,	// WmiFileHandleToInstanceNameW
false,	// WmiFreeBuffer
false,	// WmiMofEnumerateResourcesA
false,	// WmiMofEnumerateResourcesW
false,	// WmiNotificationRegistrationA
false,	// WmiNotificationRegistrationW
false,	// WmiOpenBlock
false,	// WmiQueryAllDataA
false,	// WmiQueryAllDataMultipleA
false,	// WmiQueryAllDataMultipleW
false,	// WmiQueryAllDataW
false,	// WmiQueryGuidInformation
false,	// WmiQuerySingleInstanceA
false,	// WmiQuerySingleInstanceMultipleA
false,	// WmiQuerySingleInstanceMultipleW
false,	// WmiQuerySingleInstanceW
false,	// WmiReceiveNotificationsA
false,	// WmiReceiveNotificationsW
false,	// WmiSetSingleInstanceA
false,	// WmiSetSingleInstanceW
false,	// WmiSetSingleItemA
false,	// WmiSetSingleItemW
false	// WriteEncryptedFileRaw
};