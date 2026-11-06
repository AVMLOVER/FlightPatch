/* Independent Windows licensing API replacement inspired by slshim's design.
   It reports local shim licensing status; it does not issue a Microsoft license
   or implement online activation, genuine tickets, or Office licensing. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <wchar.h>
#include <string.h>
#include <sddl.h>
#include <aclapi.h>
#include "slshim_policy.h"

#define SL_KEY L"SYSTEM\\NTTimebombSLShim"
#define SL_SERVICE L"NTTimebombSLShim"
#define SL_MISSING ((HRESULT)0xc004f012u)
#define SL_UNSUPPORTED ((HRESULT)0xc004f016u)
typedef struct { DWORD magic; GUID sku; } SlContext;
typedef struct { GUID sku; DWORD status,grace,total; HRESULT reason; ULONGLONG expires; } SlStatus;
_Static_assert(sizeof(SlStatus)==40,"licensing status ABI");
static INIT_ONCE sl_once=INIT_ONCE_STATIC_INIT;
static BYTE *sl_cache;
static DWORD sl_cache_size;
static wchar_t sl_edition[80];
static BOOL CALLBACK sl_load(PINIT_ONCE once,void *parameter,void **context)
{
    (void)once;(void)parameter;(void)context;
    HKEY key;
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,SL_KEY,0,KEY_QUERY_VALUE,&key)!=ERROR_SUCCESS) return TRUE;
    DWORD type=0,size=0;
    DWORD version=0,version_size=4;
    if(RegQueryValueExW(key,L"Version",NULL,&type,(BYTE *)&version,&version_size)!=ERROR_SUCCESS ||
       type!=REG_DWORD || version_size!=4 || version!=1){RegCloseKey(key);return TRUE;}
    if(RegQueryValueExW(key,L"Policy",NULL,&type,NULL,&size)==ERROR_SUCCESS && type==REG_BINARY && size<=SL_POLICY_MAX) {
        BYTE *data=HeapAlloc(GetProcessHeap(),0,size);
        if(data && RegQueryValueExW(key,L"Policy",NULL,&type,data,&size)==ERROR_SUCCESS && sl_policy_valid(data,size)) {
            sl_cache=data;sl_cache_size=size;
        } else if(data) HeapFree(GetProcessHeap(),0,data);
    }
    size=sizeof sl_edition;
    if(RegQueryValueExW(key,L"EditionID",NULL,&type,(BYTE *)sl_edition,&size)!=ERROR_SUCCESS ||
       type!=REG_SZ || size>sizeof sl_edition || size<2 || size%2 || sl_edition[(size/2)-1])
        sl_edition[0]=0;
    RegCloseKey(key);
    return TRUE;
}
static HRESULT sl_reply(DWORD type,const void *value,DWORD size,DWORD *out_type,UINT *out_size,BYTE **out_data)
{
    if(out_data) {
        *out_data=NULL;
        BYTE *copy=LocalAlloc(LMEM_FIXED,size?size:1);
        if(!copy) return E_OUTOFMEMORY;
        if(size) memcpy(copy,value,size);
        *out_data=copy;
    }
    if(out_type) *out_type=type;
    if(out_size) *out_size=size;
    return S_OK;
}
static HRESULT sl_query(const wchar_t *name,DWORD *type,UINT *size,BYTE **value)
{
    if(!name) return E_INVALIDARG;
    if(value) *value=NULL;
    if(size) *size=0;
    InitOnceExecuteOnce(&sl_once,sl_load,NULL,NULL);
    DWORD actual_type=0,actual_size=0; const BYTE *actual=NULL;
    if(sl_cache && sl_policy_get(sl_cache,sl_cache_size,name,&actual_type,&actual,&actual_size)==ERROR_SUCCESS)
        return sl_reply(actual_type,actual,actual_size,type,size,value);
    if(!_wcsicmp(name,L"EditionID") && sl_edition[0])
        return sl_reply(REG_SZ,sl_edition,(DWORD)((wcslen(sl_edition)+1)*2),type,size,value);
    DWORD number;
    if(!_wcsicmp(name,L"LicenseStatus")) number=1;
    else if(!_wcsicmp(name,L"GraceTime") || !_wcsicmp(name,L"GenuineState")) number=0;
    else return SL_MISSING;
    return sl_reply(REG_DWORD,&number,sizeof number,type,size,value);
}
HRESULT WINAPI SLOpen(void **out)
{
    if(!out) return E_INVALIDARG;
    *out=NULL;
    InitOnceExecuteOnce(&sl_once,sl_load,NULL,NULL);
    if(!sl_cache)return SL_MISSING;
    SlContext *context=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof *context);
    if(!context) return E_OUTOFMEMORY;
    context->magic=0x5054544e;*out=context;return S_OK;
}
HRESULT WINAPI SLClose(void *handle)
{
    if(!handle || ((SlContext *)handle)->magic!=0x5054544e) return E_INVALIDARG;
    ((SlContext *)handle)->magic=0;
    HeapFree(GetProcessHeap(),0,handle);return S_OK;
}
HRESULT WINAPI SLConsumeRight(void *handle,const GUID *app,const GUID *sku,const wchar_t *right,void *reserved)
{
    (void)app;(void)right;(void)reserved;
    if(!handle || ((SlContext *)handle)->magic!=0x5054544e) return E_INVALIDARG;
    if(sku) ((SlContext *)handle)->sku=*sku;
    return S_OK;
}
HRESULT WINAPI SLGetLicensingStatusInformation(void *handle,const GUID *app,const GUID *sku,
                                               const wchar_t *right,UINT *count,SlStatus **out)
{
    (void)app;(void)right;
    if(!count || !out || !handle || ((SlContext *)handle)->magic!=0x5054544e) return E_INVALIDARG;
    *count=0;*out=NULL;
    SlStatus *entry=LocalAlloc(LMEM_FIXED|LMEM_ZEROINIT,sizeof *entry);
    if(!entry) return E_OUTOFMEMORY;
    entry->sku=sku?*sku:((SlContext *)handle)->sku;entry->status=1;
    *count=1;*out=entry;return S_OK;
}
HRESULT WINAPI SLGetSLIDList(void *handle,DWORD query_type,const GUID *query,DWORD result_type,UINT *count,GUID **out)
{
    (void)query_type;(void)query;(void)result_type;
    if(!count || !out || !handle || ((SlContext *)handle)->magic!=0x5054544e) return E_INVALIDARG;
    *count=0;*out=LocalAlloc(LMEM_FIXED,sizeof(GUID));
    if(!*out) return E_OUTOFMEMORY;
    **out=((SlContext *)handle)->sku;*count=1;return S_OK;
}
HRESULT WINAPI SLGetPolicyInformation(void *handle,const wchar_t *name,DWORD *type,UINT *size,BYTE **data)
{ (void)handle;return sl_query(name,type,size,data); }
HRESULT WINAPI SLLoadApplicationPolicies(const GUID *app,const GUID *sku,DWORD flags,void **out)
{
    (void)app;(void)flags;
    HRESULT result=SLOpen(out);
    if(SUCCEEDED(result) && sku)((SlContext *)*out)->sku=*sku;
    return result;
}
HRESULT WINAPI SLUnloadApplicationPolicies(void *context,DWORD flags)
{ (void)flags;return SLClose(context); }
HRESULT WINAPI SLGetApplicationInformation(void *handle,const GUID *app,const wchar_t *name,DWORD *type,UINT *size,BYTE **data)
{ (void)handle;(void)app;return sl_query(name,type,size,data); }
HRESULT WINAPI SLGetPKeyInformation(void *handle,const GUID *key,const wchar_t *name,DWORD *type,UINT *size,BYTE **data)
{ return SLGetApplicationInformation(handle,key,name,type,size,data); }
HRESULT WINAPI SLGetGenuineInformation(const GUID *app,const wchar_t *name,DWORD *type,UINT *size,BYTE **data)
{ (void)app;return sl_query(name,type,size,data); }
HRESULT WINAPI SLGetWindowsInformation(const wchar_t *name,DWORD *type,UINT *size,BYTE **data)
{ return sl_query(name,type,size,data); }
HRESULT WINAPI SLGetWindowsInformationDWORD(const wchar_t *name,DWORD *out)
{
    if(!out) return E_INVALIDARG;
    *out=0;DWORD type=0;UINT size=0;BYTE *data=NULL;
    HRESULT result=sl_query(name,&type,&size,&data);
    if(SUCCEEDED(result)) {
        if(type!=REG_DWORD || size!=4) result=SL_MISSING;
        else memcpy(out,data,4);
    }
    if(data) LocalFree(data);
    return result;
}
HRESULT WINAPI SLGetPolicyInformationDWORD(void *handle,const wchar_t *name,DWORD *out)
{ (void)handle;return SLGetWindowsInformationDWORD(name,out); }
HRESULT WINAPI SLIsGenuineLocal(const GUID *app,DWORD *state,void *options)
{
    (void)app;(void)options;if(!state)return E_INVALIDARG;
    InitOnceExecuteOnce(&sl_once,sl_load,NULL,NULL);
    if(!sl_cache)return SL_MISSING;
    *state=0;return S_OK;
}
HRESULT WINAPI SLIsGenuineLocalEx(const GUID *app,void *a,DWORD *state)
{ (void)a;return SLIsGenuineLocal(app,state,NULL); }
HRESULT WINAPI SLIsWindowsGenuineLocal(DWORD *state)
{ return SLIsGenuineLocal(NULL,state,NULL); }
HRESULT WINAPI SLInstallLicense(void *handle,UINT size,const BYTE *license,GUID *out)
{ (void)handle;(void)size;(void)license;if(!out)return E_INVALIDARG;memset(out,0,sizeof *out);return S_OK; }

/* A dedicated svchost service maintains the SKU's cached kernel policy. */
static SERVICE_STATUS_HANDLE sl_service_handle;
static SERVICE_STATUS sl_service_status;
static HANDLE sl_stop_event;
static BOOL sl_privilege(const wchar_t *name)
{
    HANDLE token;TOKEN_PRIVILEGES p={.PrivilegeCount=1};
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&token))return FALSE;
    BOOL ok=LookupPrivilegeValueW(NULL,name,&p.Privileges[0].Luid);
    p.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    ok=ok && AdjustTokenPrivileges(token,FALSE,&p,0,NULL,NULL) && GetLastError()==ERROR_SUCCESS;
    CloseHandle(token);return ok;
}
static DWORD WINAPI sl_control(DWORD code,DWORD type,void *data,void *context)
{
    (void)type;(void)data;(void)context;
    if(code==SERVICE_CONTROL_STOP || code==SERVICE_CONTROL_SHUTDOWN) SetEvent(sl_stop_event);
    return NO_ERROR;
}
static BOOL sl_private_directory(const wchar_t *path)
{
    HANDLE directory=CreateFileW(path,READ_CONTROL|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,
        NULL,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,NULL);
    if(directory==INVALID_HANDLE_VALUE)return FALSE;
    BY_HANDLE_FILE_INFORMATION info;PSECURITY_DESCRIPTOR sd=NULL;PSID owner=NULL;PACL acl=NULL;
    BOOL ok=GetFileInformationByHandle(directory,&info) && !(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) &&
        GetSecurityInfo(directory,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
                        &owner,NULL,&acl,NULL,&sd)==ERROR_SUCCESS &&
        (IsWellKnownSid(owner,WinLocalSystemSid) || IsWellKnownSid(owner,WinBuiltinAdministratorsSid)) && acl;
    for(DWORD i=0;ok && i<acl->AceCount;++i) {
        void *value=NULL;
        ok=GetAce(acl,i,&value);
        if(!ok)break;
        ACCESS_ALLOWED_ACE *ace=value;
        ok=ace->Header.AceType==ACCESS_ALLOWED_ACE_TYPE &&
            (IsWellKnownSid(&ace->SidStart,WinLocalSystemSid) || IsWellKnownSid(&ace->SidStart,WinBuiltinAdministratorsSid));
    }
    LocalFree(sd);CloseHandle(directory);return ok;
}
static LONG sl_refresh(HKEY options)
{
    DWORD type=0,size=0;
    LONG error=RegQueryValueExW(options,L"ProductPolicy",NULL,&type,NULL,&size);
    if(error || type!=REG_BINARY || size>SL_POLICY_MAX)return ERROR_INVALID_DATA;
    BYTE *current=HeapAlloc(GetProcessHeap(),0,size);
    if(!current)return ERROR_NOT_ENOUGH_MEMORY;
    error=RegQueryValueExW(options,L"ProductPolicy",NULL,&type,current,&size);
    BOOL equal=!error && size==sl_cache_size && !memcmp(current,sl_cache,size);
    HeapFree(GetProcessHeap(),0,current);
    if(error || equal)return error;
    wchar_t windows[MAX_PATH],folder[MAX_PATH],file[MAX_PATH];
    if(!GetWindowsDirectoryW(windows,MAX_PATH) ||
       swprintf(folder,MAX_PATH,L"%ls\\Temp\\NTTimebombSLShim",windows)<0 ||
       swprintf(file,MAX_PATH,L"%ls\\policy-%lu-%llu.hiv",folder,GetCurrentProcessId(),GetTickCount64())<0)
        return ERROR_FILENAME_EXCED_RANGE;
    PSECURITY_DESCRIPTOR sd=NULL;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",SDDL_REVISION_1,&sd,NULL))return GetLastError();
    SECURITY_ATTRIBUTES attributes={sizeof attributes,sd,FALSE};
    BOOL made=CreateDirectoryW(folder,&attributes);
    DWORD dir_error=GetLastError();LocalFree(sd);
    if(!made && dir_error!=ERROR_ALREADY_EXISTS)return dir_error;
    /* Refuse junctions and pre-created permissive directories before saving. */
    DWORD attrs=GetFileAttributesW(folder);
    if(attrs==INVALID_FILE_ATTRIBUTES || (attrs&FILE_ATTRIBUTE_REPARSE_POINT) || !sl_private_directory(folder))return ERROR_INVALID_DATA;
    error=RegSaveKeyExW(options,file,NULL,REG_LATEST_FORMAT);
    if(error)return error;
    HKEY saved=NULL;
    error=RegLoadAppKeyW(file,&saved,KEY_ALL_ACCESS,REG_PROCESS_APPKEY,0);
    if(!error)error=RegSetValueExW(saved,L"ProductPolicy",0,REG_BINARY,sl_cache,sl_cache_size);
    if(saved)RegCloseKey(saved);
    if(!error) {
        for(unsigned attempt=0;attempt<20;++attempt) {
            error=RegRestoreKeyW(options,file,REG_FORCE_RESTORE);
            if(error!=ERROR_SHARING_VIOLATION)break;
            Sleep(50);
        }
    }
    DeleteFileW(file);return error;
}
void WINAPI ServiceMain(DWORD argc,wchar_t **argv)
{
    (void)argc;(void)argv;
    sl_stop_event=CreateEventW(NULL,TRUE,FALSE,NULL);
    sl_service_handle=RegisterServiceCtrlHandlerExW(SL_SERVICE,sl_control,NULL);
    if(!sl_service_handle || !sl_stop_event)return;
    sl_service_status.dwServiceType=SERVICE_WIN32_SHARE_PROCESS;
    sl_service_status.dwCurrentState=SERVICE_START_PENDING;
    sl_service_status.dwWaitHint=5000;
    SetServiceStatus(sl_service_handle,&sl_service_status);
    InitOnceExecuteOnce(&sl_once,sl_load,NULL,NULL);
    HKEY options=NULL;
    LONG error=ERROR_INVALID_DATA;
    if(sl_cache && sl_privilege(L"SeBackupPrivilege") && sl_privilege(L"SeRestorePrivilege"))
        error=RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\ProductOptions",0,KEY_ALL_ACCESS,&options);
    HANDLE changed=CreateEventW(NULL,FALSE,FALSE,NULL);
    if(!error && !changed)error=GetLastError();
    if(!error) {
        sl_service_status.dwCurrentState=SERVICE_RUNNING;
        sl_service_status.dwControlsAccepted=SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN;
        sl_service_status.dwWaitHint=0;
        SetServiceStatus(sl_service_handle,&sl_service_status);
        HANDLE events[]={sl_stop_event,changed};
        while(WaitForSingleObject(sl_stop_event,0)==WAIT_TIMEOUT) {
            error=RegNotifyChangeKeyValue(options,FALSE,REG_NOTIFY_CHANGE_LAST_SET,changed,TRUE);
            if(error || (error=sl_refresh(options))!=ERROR_SUCCESS)break;
            if(WaitForMultipleObjects(2,events,FALSE,30000)==WAIT_OBJECT_0)break;
        }
    }
    if(options)RegCloseKey(options);
    if(changed)CloseHandle(changed);
    sl_service_status.dwCurrentState=SERVICE_STOPPED;
    sl_service_status.dwControlsAccepted=0;
    sl_service_status.dwWin32ExitCode=error;
    SetServiceStatus(sl_service_handle,&sl_service_status);
    CloseHandle(sl_stop_event);
}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved)
{
    (void)reserved;
    if(reason==DLL_PROCESS_ATTACH)DisableThreadLibraryCalls(instance);
    return TRUE;
}

/* Correct stdcall stack widths and export aliases are generated from the
   supplied original x86 interfaces; unsupported activation APIs fail explicitly. */
#include "slshim_stubs.h"
