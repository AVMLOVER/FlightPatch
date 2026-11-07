#include "slshim_policy.h"
#include "slshim_payloads.h"
#include "offline_registry.h"
enum { SL_OLD_FILES=14, SL_FILES=15, SL_BACKUP_VERSION=1 };
typedef struct {
    wchar_t relative[96];
    char original[65],installed[65];
    DWORD existed,attributes;
} SlBackupFile;
typedef struct {
    char magic[8];
    DWORD version,state,count,control_count,controls[3];
    wchar_t edition[80],build[40];
    SlBackupFile files[SL_FILES];
} SlBackup;
static const wchar_t *const sl_modules[]={L"slc.dll",L"slcext.dll",L"sppc.dll",L"sppcext.dll",L"slwga.dll"};
static const wchar_t *const sl_platform_services[]={L"sppsvc",L"sppuinotify",L"slsvc",L"SLUINotify"};
#include "slshim_controls.h"

static BOOL sl_stream_sha(BCRYPT_ALG_HANDLE algorithm,const wchar_t *path,char hex[65])
{
    HANDLE file=spp_open(path,GENERIC_READ,OPEN_EXISTING);
    if(file==INVALID_HANDLE_VALUE)return FALSE;
    BCRYPT_HASH_HANDLE hash=NULL;BYTE bytes[65536],result[32];DWORD read=0;
    BOOL ok=BCryptCreateHash(algorithm,&hash,NULL,0,NULL,0,0)>=0;
    while(ok) {
        ok=ReadFile(file,bytes,sizeof bytes,&read,NULL);
        if(!ok || !read)break;
        ok=BCryptHashData(hash,bytes,read,0)>=0;
    }
    ok=ok && BCryptFinishHash(hash,result,sizeof result,0)>=0;
    if(hash)BCryptDestroyHash(hash);
    CloseHandle(file);
    if(ok)for(unsigned i=0;i<32;++i)sprintf(hex+i*2,"%02x",result[i]);
    return ok;
}
static BOOL sl_tool_file(wchar_t path[PATH_SIZE],const wchar_t *relative)
{
    wchar_t home[PATH_SIZE];DWORD length=GetModuleFileNameW(NULL,home,PATH_SIZE);
    wchar_t *slash=wcsrchr(home,L'\\');
    if(!length || length>=PATH_SIZE || !slash)return FALSE;
    *slash=0;
    if(!build_path(path,home,relative))return FALSE;
    for(wchar_t *p=path;*p;++p)if(*p==L'/')*p=L'\\';
    return spp_path_chain(path,FALSE) && spp_path_type(path,FALSE,FALSE);
}
static BOOL sl_payload_file(BCRYPT_ALG_HANDLE algorithm,const SlPayload *payload,wchar_t path[PATH_SIZE])
{
    char sha[65];
    BOOL ok=sl_tool_file(path,payload->relative) && sl_stream_sha(algorithm,path,sha) && !strcmp(sha,payload->sha);
    if(!ok){fwprintf(stderr,L"Missing, modified or wrong-version SLShim payload: %ls. Extract the complete matching package.\n",payload->relative);SetLastError(ERROR_CRC);}
    return ok;
}
static BOOL sl_registry_load(BCRYPT_ALG_HANDLE algorithm,SlRegistry *api)
{
    wchar_t path[PATH_SIZE];
#if defined(__aarch64__)
    unsigned host=2;
#else
    unsigned host=sizeof(void *)==8;
#endif
    if(!sl_payload_file(algorithm,&sl_offreg_payloads[host],path))return FALSE;
    api->module=LoadLibraryExW(path,NULL,LOAD_WITH_ALTERED_SEARCH_PATH);
    if(!api->module){fwprintf(stderr,L"Cannot load Offline Registry Library (Win32 %lu).\n",GetLastError());return FALSE;}
#define SL_IMPORT(field,name) do { FARPROC p=GetProcAddress(api->module,name); memcpy(&api->field,&p,sizeof p); if(!p)return FALSE; } while(0)
    SL_IMPORT(OpenHive,"OROpenHive");SL_IMPORT(CloseHive,"ORCloseHive");SL_IMPORT(SaveHive,"ORSaveHive");
    SL_IMPORT(OpenKey,"OROpenKey");SL_IMPORT(CloseKey,"ORCloseKey");SL_IMPORT(CreateKey,"ORCreateKey");
    SL_IMPORT(GetValue,"ORGetValue");SL_IMPORT(SetValue,"ORSetValue");SL_IMPORT(DeleteValue,"ORDeleteValue");
    SL_IMPORT(DeleteKey,"ORDeleteKey");SL_IMPORT(EnumKey,"OREnumKey");
#undef SL_IMPORT
    return TRUE;
}
static BOOL sl_export_match(const Image *image,const SlLibrary *library)
{
    if(image->machine!=library->machine)return FALSE;
    DWORD directory=image->pe+24+(image->x64?0x70:0x60);
    if(directory+8>image->section_table)return FALSE;
    DWORD raw=translate(image,u32(image->bytes+directory),FALSE,FALSE);
    if(raw==NONE || raw>image->size-40)return FALSE;
    BYTE *e=image->bytes+raw;
    DWORD base=u32(e+16),count=u32(e+20),names=u32(e+24);
    DWORD ft=translate(image,u32(e+28),FALSE,FALSE),nt=translate(image,u32(e+32),FALSE,FALSE),ot=translate(image,u32(e+36),FALSE,FALSE);
    if(count>65536 || names>count || ft==NONE || nt==NONE || ot==NONE ||
       count>(image->size-ft)/4 || names>(image->size-nt)/4 || names>(image->size-ot)/2)return FALSE;
    unsigned populated=0;
    for(DWORD i=0;i<count;++i)if(u32(image->bytes+ft+i*4))++populated;
    if(populated!=library->count)return FALSE;
    unsigned named=0;
    for(unsigned i=0;i<library->count;++i) {
        const SlExport *expected=&library->exports[i];
        if(expected->ordinal<base || expected->ordinal-base>=count || !u32(image->bytes+ft+(expected->ordinal-base)*4))return FALSE;
        if(!expected->name)continue;
        ++named;BOOL found=FALSE;
        for(DWORD n=0;n<names;++n) {
            DWORD string=translate(image,u32(image->bytes+nt+n*4),FALSE,FALSE);
            size_t length=strlen(expected->name)+1;
            if(string!=NONE && length<=image->size-string && !memcmp(image->bytes+string,expected->name,length) &&
               u16(image->bytes+ot+n*2)==expected->ordinal-base){found=TRUE;break;}
        }
        if(!found)return FALSE;
    }
    return named==names;
}
static const SlLibrary *sl_library(BCRYPT_ALG_HANDLE algorithm,const wchar_t *path,const wchar_t *module)
{
    HANDLE file=spp_open(path,GENERIC_READ,OPEN_EXISTING);Output data={0};Image image;
    BOOL ok=file!=INVALID_HANDLE_VALUE && offline_read(file,&data,algorithm) && image_open_arch(&image,data.data,data.size,TRUE);
    if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);
    const SlLibrary *match=NULL;
    for(unsigned i=0;ok && i<sizeof sl_libraries/sizeof *sl_libraries;++i)
        if(!_wcsicmp(module,sl_libraries[i].module) && sl_export_match(&image,&sl_libraries[i])) {match=&sl_libraries[i];break;}
    free(data.data);
    if(!match){fwprintf(stderr,L"Unverified licensing ABI in %ls. No replacement is allowed.\n",path);SetLastError(ERROR_NOT_SUPPORTED);}
    return match;
}
static BOOL sl_metadata_copy(const wchar_t *source,const wchar_t *target)
{
    HANDLE input=spp_open(source,READ_CONTROL|FILE_READ_ATTRIBUTES,OPEN_EXISTING);
    HANDLE output=spp_open(target,WRITE_OWNER|WRITE_DAC|FILE_WRITE_ATTRIBUTES,OPEN_EXISTING);
    BOOL ok=input!=INVALID_HANDLE_VALUE && output!=INVALID_HANDLE_VALUE && spp_restore_metadata(input,output)==ERROR_SUCCESS;
    if(input!=INVALID_HANDLE_VALUE)CloseHandle(input);
    if(output!=INVALID_HANDLE_VALUE)CloseHandle(output);
    return ok;
}
static BOOL sl_copy(const wchar_t *source,const wchar_t *target)
{
    HANDLE input=spp_open(source,GENERIC_READ|READ_CONTROL,OPEN_EXISTING);
    HANDLE output=spp_open(target,GENERIC_READ|GENERIC_WRITE|WRITE_OWNER|WRITE_DAC,CREATE_NEW);
    BOOL ok=input!=INVALID_HANDLE_VALUE && output!=INVALID_HANDLE_VALUE &&
            spp_copy_verified(input,output) && spp_restore_metadata(input,output)==ERROR_SUCCESS;
    if(input!=INVALID_HANDLE_VALUE)CloseHandle(input);
    if(output!=INVALID_HANDLE_VALUE)CloseHandle(output);
    return ok;
}
static BOOL sl_new_metadata(const wchar_t *file)
{
    PSECURITY_DESCRIPTOR descriptor=NULL;
    if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:SYD:"
        L"(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)"
        L"(A;;GRGX;;;AC)(A;;GRGX;;;S-1-15-2-2)",SDDL_REVISION_1,&descriptor,NULL))return FALSE;
    HANDLE handle=spp_open(file,WRITE_OWNER|WRITE_DAC,OPEN_EXISTING);
    BOOL ok=handle!=INVALID_HANDLE_VALUE && SetKernelObjectSecurity(handle,
        OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,descriptor);
    if(handle!=INVALID_HANDLE_VALUE)CloseHandle(handle);
    LocalFree(descriptor);return ok;
}
static BOOL sl_manifest_io(const wchar_t *path,SlBackup *backup,BOOL write)
{
    wchar_t pending[PATH_SIZE];
    if(write && swprintf(pending,PATH_SIZE,L"%ls.pending-%lu",path,GetCurrentProcessId())<0)return FALSE;
    HANDLE file=spp_open(write?pending:path,write?GENERIC_WRITE:GENERIC_READ,write?CREATE_NEW:OPEN_EXISTING);
    if(file==INVALID_HANDLE_VALUE)return FALSE;
    DWORD size=0;
    BOOL ok=write?WriteFile(file,backup,sizeof *backup,&size,NULL):ReadFile(file,backup,sizeof *backup,&size,NULL);
    const DWORD legacy_size=sizeof *backup-(SL_FILES-SL_OLD_FILES)*sizeof backup->files[0];
    ok=ok && (size==sizeof *backup || (!write && size==legacy_size && backup->count<=SL_OLD_FILES));
    if(write)ok=ok && FlushFileBuffers(file);
    CloseHandle(file);
    if(write) {
        if(ok)ok=MoveFileExW(pending,path,MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH);
        if(!ok)DeleteFileW(pending);
    }
    if(!write)ok=ok && !memcmp(backup->magic,"NTTPSL01",8) && backup->version==SL_BACKUP_VERSION &&
                        backup->count<=SL_FILES && backup->count>=6 && backup->control_count && backup->control_count<=3;
    return ok;
}
static BOOL sl_original_name(wchar_t result[PATH_SIZE],const wchar_t *directory,unsigned index)
{
    wchar_t name[24];swprintf(name,24,L"original-%02u.bin",index);
    return build_path(result,directory,name);
}
static BOOL sl_root(const wchar_t *root)
{
    wchar_t windows[PATH_SIZE],live[PATH_SIZE],a[OFFLINE_NT_PATH],b[OFFLINE_NT_PATH];
    UINT length=GetSystemWindowsDirectoryW(live,PATH_SIZE);
    return length && length<PATH_SIZE && offline_root(root,TRUE) && build_path(windows,root,L"Windows") &&
           spp_path_chain(windows,TRUE) && offline_directory(windows,a) && offline_directory(live,b) &&
           _wcsicmp(a,b) && !offline_under(a,b);
}

static DWORD sl_hive_io_error(const wchar_t *operation,const wchar_t *path,DWORD error)
{
    if(error) {
        fwprintf(stderr,L"Cannot %ls SLShim registry hive %ls (Win32 %lu).\n",operation,path,error);
        if(error==ERROR_SHARING_VIOLATION)
            fwprintf(stderr,L"Close any servicing tool that loaded the offline hives, or unload the offline hives you loaded manually, then retry. SYSTEM privileges do not clear a sharing violation.\n");
    }
    return error;
}

static BOOL sl_policy_add_zero_default(BYTE **data,DWORD *size,const wchar_t *name)
{
    DWORD type=0,length=0;const BYTE *value=NULL;
    DWORD error=sl_policy_get(*data,*size,name,&type,&value,&length);
    if(error==ERROR_SUCCESS)return type==REG_DWORD && length==sizeof(DWORD);
    if(error!=ERROR_FILE_NOT_FOUND)return FALSE;
    const WORD name_bytes=(WORD)(wcslen(name)*sizeof(wchar_t));
    const WORD entry_bytes=(16+name_bytes+sizeof(DWORD)+3)&~3;
    if(*size>SL_POLICY_MAX-entry_bytes)return FALSE;
    BYTE *grown=realloc(*data,*size+entry_bytes);
    if(!grown)return FALSE;
    *data=grown;
    BYTE *entry=grown+*size-4;
    memcpy(entry+entry_bytes,entry,4);
    memset(entry,0,entry_bytes);
    const WORD header[]={entry_bytes,name_bytes,REG_DWORD,sizeof(DWORD)};
    memcpy(entry,header,sizeof header);
    memcpy(entry+16,name,name_bytes);
    *size+=entry_bytes;
    DWORD payload=*size-24;
    memcpy(grown,size,4);
    memcpy(grown+4,&payload,4);
    return TRUE;
}
static char *sl_stock_ppd(const wchar_t *root,const wchar_t *edition,BOOL defaults)
{
    for(const wchar_t *p=edition;*p;++p)
        if(!((*p>=L'A' && *p<=L'Z') || (*p>=L'a' && *p<=L'z') || (*p>=L'0' && *p<=L'9')))return NULL;
    wchar_t path[PATH_SIZE],relative[280];
    if(!*edition || swprintf(relative,ARRAYSIZE(relative),
        L"Windows\\System32\\spp\\tokens\\skus\\%ls\\%ls%ls-ppdlic.xrm-ms",edition,defaults?L"DefaultPpd-":L"",edition)<0 ||
        !build_path(path,root,relative) || !spp_path_chain(path,FALSE) ||
        !spp_path_type(path,FALSE,FALSE))return NULL;
    HANDLE file=spp_open(path,GENERIC_READ,OPEN_EXISTING);
    if(file==INVALID_HANDLE_VALUE)return NULL;
    LARGE_INTEGER bytes;
    BOOL sized=GetFileSizeEx(file,&bytes) && bytes.QuadPart>0 && bytes.QuadPart<=SL_POLICY_MAX;
    char *xml=sized?malloc((size_t)bytes.QuadPart+1):NULL;
    DWORD read=0;
    BOOL ok=xml && ReadFile(file,xml,(DWORD)bytes.QuadPart,&read,NULL) && read==(DWORD)bytes.QuadPart;
    CloseHandle(file);
    if(ok){xml[read]=0;return xml;}
    free(xml);
    return NULL;
}

static BOOL sl_ppd_identity_number(const char *xml,const char *name,DWORD *number)
{
    char marker[80];
    snprintf(marker,sizeof marker,"<sl:policyInt name=\"%s\"",name);
    const char *item=strstr(xml,marker);
    if(!item || strstr(item+1,marker))return FALSE;
    item+=strlen(marker);
    static const char override[]=" attributes=\"override-only\"";
    if(!strncmp(item,override,sizeof override-1))item+=sizeof override-1;
    if(*item++!='>' || *item<'0' || *item>'9')return FALSE;
    ULONGLONG value=0;
    do {
        value=value*10+(*item++-'0');
        if(value>MAXDWORD)return FALSE;
    } while(*item>='0' && *item<='9');
    if(!value || strncmp(item,"</sl:policyInt>",15))return FALSE;
    *number=(DWORD)value;
    return TRUE;
}

static BOOL sl_composition_cached(const BYTE *data,DWORD size,const wchar_t *edition,const wchar_t *composition)
{
    DWORD type=0,length=0;const BYTE *value=NULL;
    size_t bytes=wcslen(composition)*sizeof(wchar_t);
    return bytes && _wcsicmp(edition,composition) &&
        sl_policy_get(data,size,L"Kernel-EditionName",&type,&value,&length)==ERROR_SUCCESS && type==REG_SZ &&
        (length==bytes || (length==bytes+sizeof(wchar_t) && !sl_word16(value+bytes))) &&
        !_wcsnicmp((const wchar_t *)value,composition,bytes/sizeof(wchar_t));
}

static BOOL sl_apply_sku_identity(const wchar_t *root,const wchar_t *edition,BYTE **data,DWORD *size)
{
    char *xml=sl_stock_ppd(root,edition,FALSE);
    char marker[168];
    snprintf(marker,sizeof marker,"<sl:policyStr name=\"Kernel-EditionName\">%ls</sl:policyStr>",edition);
    DWORD branding=0,product=0;
    BOOL ok=xml && strstr(xml,marker) && sl_ppd_identity_number(xml,"Kernel-BrandingInfo",&branding) &&
        sl_ppd_identity_number(xml,"Kernel-ProductInfo",&product);
    free(xml);
    if(!ok)return FALSE;

    const BYTE *old_name=NULL,*old_brand=NULL,*old_product=NULL;
    DWORD type=0,length=0;
    if(sl_policy_get(*data,*size,L"Kernel-BrandingInfo",&type,&old_brand,&length)!=ERROR_SUCCESS ||
       type!=REG_DWORD || length!=sizeof(DWORD) ||
       sl_policy_get(*data,*size,L"Kernel-ProductInfo",&type,&old_product,&length)!=ERROR_SUCCESS ||
       type!=REG_DWORD || length!=sizeof(DWORD) ||
       sl_policy_get(*data,*size,L"Kernel-EditionName",&type,&old_name,&length)!=ERROR_SUCCESS || type!=REG_SZ)
        return FALSE;
    WORD name_bytes=(WORD)(wcslen(edition)*sizeof(wchar_t));
    if(length>=sizeof(wchar_t) && !sl_word16(old_name+length-sizeof(wchar_t)))name_bytes+=sizeof(wchar_t);
    DWORD entry_offset=(DWORD)(old_name-*data)-16-(sizeof L"Kernel-EditionName"-sizeof(wchar_t));
    WORD old_entry=sl_word16(*data+entry_offset);
    WORD entry_bytes=(16+sl_word16(*data+entry_offset+2)+name_bytes+3)&~3;
    DWORD updated_size=*size-old_entry+entry_bytes;
    if(updated_size>SL_POLICY_MAX)return FALSE;

    memcpy((BYTE *)old_brand,&branding,sizeof branding);
    memcpy((BYTE *)old_product,&product,sizeof product);
    if(updated_size>*size) {
        BYTE *grown=realloc(*data,updated_size);
        if(!grown)return FALSE;
        *data=grown;
    }
    BYTE *entry=*data+entry_offset;
    memmove(entry+entry_bytes,entry+old_entry,*size-entry_offset-old_entry);
    BYTE *value=entry+16+sl_word16(entry+2);
    memset(value,0,entry_bytes-(value-entry));
    memcpy(value,edition,name_bytes);
    memcpy(entry,&entry_bytes,sizeof entry_bytes);
    memcpy(entry+6,&name_bytes,sizeof name_bytes);
    *size=updated_size;
    DWORD payload=*size-24;
    memcpy(*data,size,4);
    memcpy(*data+4,&payload,4);
    return sl_policy_valid(*data,*size);
}

static DWORD sl_config_hives(SlRegistry *api,const wchar_t *root,const wchar_t *system,const wchar_t *software,
                             const wchar_t *new_system,const wchar_t *new_software,SlBackup *backup,
                             const wchar_t *old_system,const wchar_t *old_software)
{
    SlKey sys=NULL,soft=NULL,original_sys=NULL,original_soft=NULL;
    DWORD error=sl_hive_io_error(L"open",system,api->OpenHive(system,&sys));
    if(!error)error=sl_hive_io_error(L"open",software,api->OpenHive(software,&soft));
    wchar_t edition[80],build[40],composition[80]={0};
    if(!error && (!sl_string(api,soft,L"Microsoft\\Windows NT\\CurrentVersion",L"EditionID",edition,80) ||
                  !sl_string(api,soft,L"Microsoft\\Windows NT\\CurrentVersion",L"CurrentBuild",build,40)))error=ERROR_INVALID_DATA;
    BOOL restore=old_system!=NULL;
    char *defaults=!error && !restore?sl_stock_ppd(root,edition,TRUE):NULL;
    /* feclient and shell32 distinguish a missing value from an explicit zero. */
    BOOL dpl_default=defaults && strstr(defaults,
        "<sl:policyInt name=\"DataProtectionUnderLock-WindowsCore-Enabled\">0</sl:policyInt>");
    BOOL watermark_default=defaults && strstr(defaults,
        "<sl:policyInt name=\"shell32-license-ShowProductNameOnDesktop\">0</sl:policyInt>");
    free(defaults);
    if(!error && !restore &&
       !sl_string(api,soft,L"Microsoft\\Windows NT\\CurrentVersion",L"CompositionEditionID",composition,80))
        composition[0]=0;
    if(!error && restore && (wcscmp(edition,backup->edition) || wcscmp(build,backup->build)))error=ERROR_REVISION_MISMATCH;
    if(!error && restore)error=sl_hive_io_error(L"open",old_system,api->OpenHive(old_system,&original_sys));
    if(!error && restore)error=sl_hive_io_error(L"open",old_software,api->OpenHive(old_software,&original_soft));
    SlControlMap controls[SL_CONTROL_LIMIT];DWORD control_count=0;
    if(!error && !restore) {
        wcscpy(backup->edition,edition);wcscpy(backup->build,build);
        const wchar_t *names[]={L"Current",L"Default",L"LastKnownGood"};
        for(unsigned i=0;i<3;++i) {
            DWORD control=0;
            if(!sl_get(api,sys,L"Select",names[i],REG_DWORD,&control,4) || !control)continue;
            if(control>999){error=ERROR_INVALID_DATA;break;}
            BOOL duplicate=FALSE;
            for(unsigned j=0;j<backup->control_count;++j)duplicate|=backup->controls[j]==control;
            if(!duplicate)backup->controls[backup->control_count++]=control;
        }
        if(!backup->control_count)error=ERROR_INVALID_DATA;
        SlKey collision=NULL;
        if(!error && api->OpenKey(sys,L"NTTimebombSLShim",&collision)!=ERROR_FILE_NOT_FOUND) {
            if(collision)api->CloseKey(collision);
            error=ERROR_ALREADY_EXISTS;
        }
        DWORD n=0,type=0;
        if(!error && api->GetValue(soft,L"Microsoft\\Windows NT\\CurrentVersion\\Svchost",L"NTTimebombSLShim",&type,NULL,&n)!=ERROR_FILE_NOT_FOUND)
            error=ERROR_ALREADY_EXISTS;
    }
    if(!error && restore)error=sl_restore_controls(api,sys,original_sys,backup,controls,&control_count);
    if(!error && !restore)for(unsigned i=0;i<backup->control_count;++i)
        controls[control_count++]=(SlControlMap){backup->controls[i],backup->controls[i]};
    BYTE *policy=NULL;DWORD policy_size=0;
    for(unsigned i=0;!error && i<control_count;++i) {
        wchar_t options[100],source_options[100],service[120],parameters[140],spp[100],source_spp[100];
        swprintf(options,100,L"ControlSet%03lu\\Control\\ProductOptions",controls[i].target);
        swprintf(source_options,100,L"ControlSet%03lu\\Control\\ProductOptions",controls[i].source);
        swprintf(service,120,L"ControlSet%03lu\\Services\\NTTimebombSLShim",controls[i].target);
        swprintf(parameters,140,L"%ls\\Parameters",service);
        SlKey source_sys=restore?original_sys:sys;
        DWORD type=0,size=0;
        error=api->GetValue(source_sys,source_options,L"ProductPolicy",&type,NULL,&size);
        BYTE *data=!error && size<=SL_POLICY_MAX?malloc(size):NULL;
        if(!data){error=ERROR_INVALID_DATA;break;}
        if(!error)error=api->GetValue(source_sys,source_options,L"ProductPolicy",&type,data,&size);
        if(!error && (type!=REG_BINARY || !sl_policy_valid(data,size)))error=ERROR_INVALID_DATA;
        if(!error && restore)error=sl_set(api,sys,options,L"ProductPolicy",REG_BINARY,data,size);
        if(!error && !restore) {
            if(!sl_policy_profile(data,&size))error=ERROR_INVALID_DATA;
            if(!error && sl_composition_cached(data,size,edition,composition)) {
                if(sl_apply_sku_identity(root,edition,&data,&size))
                    wprintf(L"Using the original %ls SKU identity in place of the %ls composition cache.\n",edition,composition);
                else {
                    fwprintf(stderr,L"Could not verify %ls SKU identity in its original PPD license.\n",edition);
                    error=ERROR_INVALID_DATA;
                }
            }
            if(!error && dpl_default && !sl_policy_add_zero_default(&data,&size,L"DataProtectionUnderLock-WindowsCore-Enabled"))
                error=ERROR_INVALID_DATA;
            if(!error && watermark_default && !sl_policy_add_zero_default(&data,&size,L"shell32-license-ShowProductNameOnDesktop"))
                error=ERROR_INVALID_DATA;
            /* Older kernels consume the policy before the service can start. */
            if(!error)error=sl_set(api,sys,options,L"ProductPolicy",REG_BINARY,data,size);
            if(!policy){policy=data;policy_size=size;data=NULL;}
            else if(size!=policy_size || memcmp(policy,data,size))error=ERROR_INVALID_DATA;
        }
        free(data);
        BOOL core_service=FALSE;
        for(unsigned s=0;!error && s<4;++s) {
            swprintf(spp,100,L"ControlSet%03lu\\Services\\%ls",controls[i].target,sl_platform_services[s]);
            swprintf(source_spp,100,L"ControlSet%03lu\\Services\\%ls",controls[i].source,sl_platform_services[s]);
            DWORD start=0;
            SlKey existing=NULL;
            error=api->OpenKey(source_sys,source_spp,&existing);
            if(error==ERROR_FILE_NOT_FOUND){error=ERROR_SUCCESS;continue;}
            if(existing)api->CloseKey(existing);
            if(error)break;
            if(!sl_get(api,source_sys,source_spp,L"Start",REG_DWORD,&start,4)){error=ERROR_INVALID_DATA;break;}
            if(s==0 || s==2)core_service=TRUE;
            error=sl_set_number(api,sys,spp,L"Start",restore?start:4);
        }
        if(!error && !core_service)error=ERROR_FILE_NOT_FOUND;
        if(error)break;
        if(restore) { error=sl_delete_tree(api,sys,service,0);continue; }
        SlKey collision=NULL;
        if(api->OpenKey(sys,service,&collision)!=ERROR_FILE_NOT_FOUND) {
            if(collision)api->CloseKey(collision);
            error=ERROR_ALREADY_EXISTS;break;
        }
        error=sl_set_number(api,sys,service,L"Start",2);
        if(!error)error=sl_set_number(api,sys,service,L"Type",SERVICE_WIN32_SHARE_PROCESS);
        if(!error)error=sl_set_number(api,sys,service,L"ErrorControl",1);
        if(!error)error=sl_set_number(api,sys,service,L"ServiceSidType",1);
        if(!error)error=sl_set_number(api,sys,service,L"SvcHostSplitDisable",1);
        if(!error)error=sl_set_string(api,sys,service,L"ImagePath",REG_EXPAND_SZ,L"\"%SystemRoot%\\System32\\svchost.exe\" -k NTTimebombSLShim");
        if(!error)error=sl_set_string(api,sys,service,L"ObjectName",REG_SZ,L"LocalSystem");
        if(!error)error=sl_set_string(api,sys,service,L"DisplayName",REG_SZ,L"NT Timebomb Licensing Shim (experimental)");
        if(!error)error=sl_set_string(api,sys,parameters,L"ServiceDll",REG_EXPAND_SZ,L"%SystemRoot%\\System32\\nttp-slshim.dll");
        if(!error)error=sl_set_string(api,sys,parameters,L"ServiceMain",REG_SZ,L"ServiceMain");
    }
    if(!error && restore) {
        error=sl_delete_tree(api,sys,L"NTTimebombSLShim",0);
        SlKey key=NULL;
        if(!error)error=api->OpenKey(soft,L"Microsoft\\Windows NT\\CurrentVersion\\Svchost",&key);
        if(!error) { error=api->DeleteValue(key,L"NTTimebombSLShim");if(error==ERROR_FILE_NOT_FOUND)error=0; }
        if(key)api->CloseKey(key);
    } else if(!error) {
        SlKey key=NULL;PSECURITY_DESCRIPTOR sd=NULL;
        if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"O:SYG:SYD:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)"
            L"(A;CI;KR;;;AC)(A;CI;KR;;;S-1-15-2-2)",SDDL_REVISION_1,&sd,NULL))error=GetLastError();
        if(!error)error=api->CreateKey(sys,L"NTTimebombSLShim",NULL,0,sd,&key,NULL);
        if(sd)LocalFree(sd);
        if(!error)error=api->SetValue(key,L"Policy",REG_BINARY,policy,policy_size);
        if(!error)error=api->SetValue(key,L"EditionID",REG_SZ,(const BYTE *)edition,(DWORD)((wcslen(edition)+1)*2));
        DWORD one=1;
        if(!error)error=api->SetValue(key,L"Version",REG_DWORD,(BYTE *)&one,4);
        if(key)api->CloseKey(key);
        static const wchar_t group[]=L"NTTimebombSLShim\0";
        if(!error)error=sl_set(api,soft,L"Microsoft\\Windows NT\\CurrentVersion\\Svchost",L"NTTimebombSLShim",REG_MULTI_SZ,group,sizeof group);
    }
    if(!error)error=sl_hive_io_error(L"save",new_system,api->SaveHive(sys,new_system,6,1));
    if(!error)error=sl_hive_io_error(L"save",new_software,api->SaveHive(soft,new_software,6,1));
    free(policy);
    if(original_sys)api->CloseHive(original_sys);
    if(original_soft)api->CloseHive(original_soft);
    if(sys)api->CloseHive(sys);
    if(soft)api->CloseHive(soft);
    if(error){fwprintf(stderr,L"SLShim registry preflight failed (Win32 %lu). No target changes have been applied.\n",error);SetLastError(error);}
    return error;
}

static BOOL sl_backup_directory(const wchar_t *root,wchar_t backup[PATH_SIZE],BOOL create)
{
    wchar_t parent[PATH_SIZE];
    if(!build_path(parent,root,L"NTTimebombBackup") || !build_path(backup,parent,L"SLShim") ||
       !spp_path_chain(parent,FALSE))return FALSE;
    if(create) {
        PSECURITY_DESCRIPTOR sd=NULL;
        if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",SDDL_REVISION_1,&sd,NULL))return FALSE;
        SECURITY_ATTRIBUTES attributes={sizeof attributes,sd,FALSE};
        BOOL ok=(CreateDirectoryW(parent,&attributes) || GetLastError()==ERROR_ALREADY_EXISTS) &&
                spp_path_chain(parent,TRUE) &&
                (CreateDirectoryW(backup,&attributes) || GetLastError()==ERROR_ALREADY_EXISTS);
        LocalFree(sd);
        if(!ok)return FALSE;
    }
    if(GetFileAttributesW(backup)==INVALID_FILE_ATTRIBUTES)return FALSE;
    if(!spp_path_chain(backup,TRUE)){SetLastError(ERROR_INVALID_DATA);return FALSE;}
    DWORD attrs=GetFileAttributesW(parent);
    DWORD visibility=FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN;
    return attrs!=INVALID_FILE_ATTRIBUTES && ((attrs&visibility)==visibility ||
        SetFileAttributesW(parent,(attrs&~FILE_ATTRIBUTE_NORMAL)|visibility));
}
static BOOL sl_backup_paths_valid(const SlBackup *backup)
{
    if(backup->state>2 || !wmemchr(backup->edition,0,80) || !wmemchr(backup->build,0,40))return FALSE;
    for(unsigned i=0;i<backup->control_count;++i)if(!backup->controls[i] || backup->controls[i]>999)return FALSE;
    BOOL system=FALSE,software=FALSE;
    for(unsigned i=0;i<backup->count;++i) {
        const SlBackupFile *entry=&backup->files[i];
        if(!wmemchr(entry->relative,0,96) || entry->existed>1 || entry->original[64] || entry->installed[64])return FALSE;
        BOOL allowed=FALSE;
        for(unsigned arch=0;arch<2;++arch)for(unsigned file=0;file<6;++file) {
            wchar_t relative[96];
            swprintf(relative,96,L"Windows\\%ls\\%ls",arch?L"SysWOW64":L"System32",file<5?sl_modules[file]:L"nttp-slshim.dll");
            allowed|=!_wcsicmp(entry->relative,relative);
        }
        if(!_wcsicmp(entry->relative,L"Windows\\System32\\Config\\SYSTEM")){system=TRUE;allowed=TRUE;}
        if(!_wcsicmp(entry->relative,L"Windows\\System32\\Config\\SOFTWARE")){software=TRUE;allowed=TRUE;}
        if(!_wcsicmp(entry->relative,L"Windows\\System32\\nttp-slshim-x64.dll") && !entry->existed)allowed=TRUE;
        if(!allowed)return FALSE;
        for(unsigned j=0;j<i;++j)if(!_wcsicmp(entry->relative,backup->files[j].relative))return FALSE;
    }
    return system && software;
}

/* State 2 is published only after the restore and attribute writes commit.
   Keep its manifest until all known originals are removed so cleanup can retry. */
static BOOL sl_cleanup_restored(BCRYPT_ALG_HANDLE algorithm,const wchar_t *directory,
                                const wchar_t *manifest,const SlBackup *backup)
{
    for(unsigned i=0;i<backup->count;++i) {
        if(!backup->files[i].existed)continue;
        wchar_t original[PATH_SIZE];char sha[65];
        if(!sl_original_name(original,directory,i))return FALSE;
        DWORD attrs=GetFileAttributesW(original);
        if(attrs==INVALID_FILE_ATTRIBUTES && spp_missing(GetLastError()))continue;
        if(attrs==INVALID_FILE_ATTRIBUTES || (attrs&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)) ||
           !sl_stream_sha(algorithm,original,sha) || strcmp(sha,backup->files[i].original)) {
            fwprintf(stderr,L"Retained an unexpected file at %ls.\n",original);
            SetLastError(ERROR_INVALID_DATA);
            return FALSE;
        }
        if(!spp_remove(original))return FALSE;
    }
    return spp_remove(manifest);
}

static BOOL sl_target_file(const wchar_t *root,const wchar_t *relative,wchar_t target[PATH_SIZE])
{
    wchar_t scope[OFFLINE_NT_PATH],final[OFFLINE_NT_PATH],live[PATH_SIZE];
    if(!build_path(target,root,relative) || !spp_path_chain(target,FALSE) || !spp_path_type(target,FALSE,TRUE))return FALSE;
    if(!spp_path_type(target,FALSE,FALSE))return TRUE;
    if(!offline_directory(root,scope))return FALSE;
    HANDLE file=spp_open(target,FILE_READ_ATTRIBUTES,OPEN_EXISTING);
    BOOL ok=file!=INVALID_HANDLE_VALUE && offline_path_name(file,final) && offline_under(final,scope);
    BY_HANDLE_FILE_INFORMATION target_id;
    ok=ok && GetFileInformationByHandle(file,&target_id);
    if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);
    UINT length=GetSystemWindowsDirectoryW(live,PATH_SIZE);
    if(ok && length && length<PATH_SIZE && !_wcsnicmp(relative,L"Windows\\",8)) {
        wchar_t current[PATH_SIZE],native[96];
        wcscpy(native,relative+8);
        BOOL wow=FALSE;
        if(sizeof(void *)==4 && IsWow64Process(GetCurrentProcess(),&wow) && wow && !_wcsnicmp(native,L"System32\\",9)) {
            wchar_t tail[96];wcscpy(tail,native+9);swprintf(native,96,L"Sysnative\\%ls",tail);
        }
        if(!build_path(current,live,native))return FALSE;
        HANDLE active=spp_open(current,FILE_READ_ATTRIBUTES,OPEN_EXISTING);
        if(active!=INVALID_HANDLE_VALUE) {
            BY_HANDLE_FILE_INFORMATION id;
            ok=GetFileInformationByHandle(active,&id) && !offline_file_id(&id,&target_id);
            CloseHandle(active);
        }
    }
    return ok;
}
static BOOL sl_stage_metadata(const wchar_t *target,const wchar_t *stage,BOOL existed)
{ return existed?sl_metadata_copy(target,stage):sl_new_metadata(stage); }

static BOOL sl_stage_entry(BCRYPT_ALG_HANDLE algorithm,const wchar_t *root,const wchar_t *stage,
                           const wchar_t *relative,const wchar_t *source,SlBackup *backup,SppPlan *plan,WORD machine)
{
    if(backup->count>=SL_FILES)return FALSE;
    SlBackupFile *entry=&backup->files[backup->count];
    wchar_t target[PATH_SIZE],name[32],prepared[PATH_SIZE];
    if(!sl_target_file(root,relative,target))return FALSE;
    wcscpy(entry->relative,relative);
    DWORD attributes=GetFileAttributesW(target);
    entry->existed=attributes!=INVALID_FILE_ATTRIBUTES;
    entry->attributes=entry->existed?attributes:FILE_ATTRIBUTE_ARCHIVE;
    if(entry->existed && !sl_stream_sha(algorithm,target,entry->original))return FALSE;
    swprintf(name,32,L"payload-%02lu.bin",backup->count);
    if(!build_path(prepared,stage,name) || !sl_copy(source,prepared) ||
       !sl_stage_metadata(target,prepared,entry->existed) || !sl_stream_sha(algorithm,prepared,entry->installed) ||
       !spp_add_file(plan,prepared,target,FALSE,FALSE,machine))return FALSE;
    ++backup->count;return TRUE;
}
static BOOL sl_attribute(const wchar_t *path,DWORD attributes)
{
    HANDLE file=spp_open(path,FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES,OPEN_EXISTING);
    FILE_BASIC_INFO info={0};info.FileAttributes=attributes & ~FILE_ATTRIBUTE_REPARSE_POINT;
    if(!info.FileAttributes)info.FileAttributes=FILE_ATTRIBUTE_NORMAL;
    BOOL ok=file!=INVALID_HANDLE_VALUE && SetFileInformationByHandle(file,FileBasicInfo,&info,sizeof info);
    if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);
    return ok;
}
static BOOL sl_installed_hives(SlRegistry *api,const wchar_t *root,const SlBackup *backup)
{
    wchar_t path[PATH_SIZE],edition[80],build[40],cache_edition[80];SlKey sys=NULL,soft=NULL;DWORD one=0;
    BYTE *policy=NULL,*current=NULL;DWORD type=0,size=0;
    BOOL ok=sl_target_file(root,L"Windows\\System32\\Config\\SYSTEM",path) && !api->OpenHive(path,&sys) &&
        sl_target_file(root,L"Windows\\System32\\Config\\SOFTWARE",path) && !api->OpenHive(path,&soft) &&
        sl_get(api,sys,L"NTTimebombSLShim",L"Version",REG_DWORD,&one,4) && one==1 &&
        sl_string(api,soft,L"Microsoft\\Windows NT\\CurrentVersion",L"EditionID",edition,80) &&
        sl_string(api,soft,L"Microsoft\\Windows NT\\CurrentVersion",L"CurrentBuild",build,40) &&
        !wcscmp(edition,backup->edition) && !wcscmp(build,backup->build) &&
        sl_string(api,sys,L"NTTimebombSLShim",L"EditionID",cache_edition,80) && !wcscmp(edition,cache_edition);
    if(ok)ok=!api->GetValue(sys,L"NTTimebombSLShim",L"Policy",&type,NULL,&size) && type==REG_BINARY && size>=24 && size<=SL_POLICY_MAX;
    if(ok) {
        policy=malloc(size);current=malloc(size);
        ok=policy && current && sl_get(api,sys,L"NTTimebombSLShim",L"Policy",REG_BINARY,policy,size) && sl_policy_valid(policy,size);
    }
    if(ok) {
        DWORD profiled=size;memcpy(current,policy,size);
        ok=sl_policy_profile(current,&profiled) && profiled==size && !memcmp(current,policy,size);
    }
    static const wchar_t group[]=L"NTTimebombSLShim\0";
    wchar_t group_value[sizeof group/sizeof *group];
    if(ok)ok=sl_get(api,soft,L"Microsoft\\Windows NT\\CurrentVersion\\Svchost",L"NTTimebombSLShim",REG_MULTI_SZ,group_value,sizeof group) && !memcmp(group_value,group,sizeof group);
    DWORD controls[SL_CONTROL_LIMIT],control_count=0;
    if(ok)ok=!sl_control_list(api,sys,backup,TRUE,controls,&control_count);
    for(unsigned i=0;ok && i<control_count;++i) {
        wchar_t key[100];DWORD start=0;
        BOOL core_service=FALSE;
        for(unsigned s=0;ok && s<4;++s) {
            swprintf(key,100,L"ControlSet%03lu\\Services\\%ls",controls[i],sl_platform_services[s]);
            SlKey existing=NULL;DWORD error=api->OpenKey(sys,key,&existing);
            if(error==ERROR_FILE_NOT_FOUND)continue;
            if(existing)api->CloseKey(existing);
            ok=!error && sl_get(api,sys,key,L"Start",REG_DWORD,&start,4) && start==4;
            if(ok && (s==0 || s==2))core_service=TRUE;
        }
        ok=ok && core_service;
        swprintf(key,100,L"ControlSet%03lu\\Control\\ProductOptions",controls[i]);
        ok=ok && sl_get(api,sys,key,L"ProductPolicy",REG_BINARY,current,size) && !memcmp(current,policy,size);
        swprintf(key,100,L"ControlSet%03lu\\Services\\NTTimebombSLShim",controls[i]);
        ok=ok && sl_get(api,sys,key,L"Start",REG_DWORD,&start,4) && start==2;
        ok=ok && sl_get(api,sys,key,L"Type",REG_DWORD,&start,4) && start==SERVICE_WIN32_SHARE_PROCESS;
        wchar_t actual[PATH_SIZE];
        static const wchar_t image[]=L"\"%SystemRoot%\\System32\\svchost.exe\" -k NTTimebombSLShim";
        if(ok)ok=sl_get(api,sys,key,L"ImagePath",REG_EXPAND_SZ,actual,sizeof image) && !wcscmp(actual,image) &&
            sl_string(api,sys,key,L"ObjectName",actual,PATH_SIZE) && !wcscmp(actual,L"LocalSystem");
        swprintf(key,100,L"ControlSet%03lu\\Services\\NTTimebombSLShim\\Parameters",controls[i]);
        static const wchar_t dll[]=L"%SystemRoot%\\System32\\nttp-slshim.dll";
        if(ok)ok=sl_get(api,sys,key,L"ServiceDll",REG_EXPAND_SZ,actual,sizeof dll) && !wcscmp(actual,dll) &&
            sl_string(api,sys,key,L"ServiceMain",actual,PATH_SIZE) && !wcscmp(actual,L"ServiceMain");
    }
    free(policy);free(current);
    if(sys)api->CloseHive(sys);
    if(soft)api->CloseHive(soft);
    return ok;
}
static BOOL sl_install(BCRYPT_ALG_HANDLE algorithm,const wchar_t *root,BOOL restore)
{
    SlBackup backup={.version=SL_BACKUP_VERSION};memcpy(backup.magic,"NTTPSL01",8);
    SlRegistry api={0};SppPlan plan={.mode=SPP_RESTORE};
    wchar_t directory[PATH_SIZE],manifest[PATH_SIZE],lock_path[PATH_SIZE],stage[PATH_SIZE],stage_name[64];
    wchar_t system[PATH_SIZE],software[PATH_SIZE],new_system[PATH_SIZE],new_software[PATH_SIZE];
    HANDLE lock=INVALID_HANDLE_VALUE;
    BOOL owns_stage=FALSE,ok=FALSE,committed=FALSE,remove_empty_backup=FALSE;
    DWORD failure=ERROR_SUCCESS;
    wchar_t removed[3][PATH_SIZE]={{0}},removed_target[3][PATH_SIZE]={{0}};
    if(!sl_root(root)) {fwprintf(stderr,L"Specify a separate offline Windows root containing SYSTEM and SOFTWARE hives.\n");return FALSE;}
    if(!sl_backup_directory(root,directory,!restore)) {
        if(restore && spp_missing(GetLastError())){
            wprintf(L"No SLShim backup exists in this target.\n");
            return TRUE;
        }
        goto finish;
    }
    if(!build_path(manifest,directory,L"state.bin") || !build_path(lock_path,directory,L"operation.lock"))goto finish;
    lock=CreateFileW(lock_path,GENERIC_READ|GENERIC_WRITE|(restore?DELETE:0),0,NULL,OPEN_ALWAYS,
                     FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,NULL);
    if(lock==INVALID_HANDLE_VALUE){fwprintf(stderr,L"Another SLShim operation is active, or the backup is inaccessible.\n");goto finish;}
    BY_HANDLE_FILE_INFORMATION lock_info;
    if(!GetFileInformationByHandle(lock,&lock_info))goto finish;
    if((lock_info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) || lock_info.nFileSizeHigh || lock_info.nFileSizeLow) {
        SetLastError(ERROR_INVALID_DATA);goto finish;
    }
    DWORD manifest_attrs=GetFileAttributesW(manifest);
    BOOL has_manifest=manifest_attrs!=INVALID_FILE_ATTRIBUTES;
    if(!has_manifest && !spp_missing(GetLastError()))goto finish;
    if(has_manifest) {
        if(manifest_attrs&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)) {
            SetLastError(ERROR_INVALID_DATA);goto finish;
        }
        if(!sl_manifest_io(manifest,&backup,FALSE) || !sl_backup_paths_valid(&backup))goto finish;
        if(backup.state==2) {
            if(!sl_cleanup_restored(algorithm,directory,manifest,&backup))goto finish;
            if(restore) {
                wprintf(L"SLShim was already restored. Removed its completed backup.\n");
                remove_empty_backup=ok=TRUE;
                goto finish;
            }
            memset(&backup,0,sizeof backup);
            backup.version=SL_BACKUP_VERSION;
            memcpy(backup.magic,"NTTPSL01",8);
            has_manifest=FALSE;
        }
    }
    if(has_manifest) {
        for(unsigned i=0;i<backup.count;++i) {
            wchar_t target[PATH_SIZE],original[PATH_SIZE];char sha[65];
            SlBackupFile *entry=&backup.files[i];
            if(!sl_target_file(root,entry->relative,target))goto finish;
            if(entry->existed && (!sl_original_name(original,directory,i) || !sl_stream_sha(algorithm,original,sha) || strcmp(sha,entry->original))) {
                fwprintf(stderr,L"Original SLShim backup is missing or changed.\n");goto finish;
            }
            BOOL hive=wcsstr(entry->relative,L"\\Config\\")!=NULL;
            if(!hive && spp_path_type(target,FALSE,FALSE)) {
                if(!sl_stream_sha(algorithm,target,sha) || (strcmp(sha,entry->installed) && (!entry->existed || strcmp(sha,entry->original)))) {
                    fwprintf(stderr,L"Target licensing file changed since installation: %ls. Preserve backups and use matching original installation media.\n",target);SetLastError(ERROR_REVISION_MISMATCH);goto finish;
                }
                if(!restore && backup.state==1 && strcmp(sha,entry->installed)) {
                    fwprintf(stderr,L"An installed licensing DLL was restored or changed. Run /slshim-restore before reinstalling.\n");goto finish;
                }
            } else if(!hive && (!restore || entry->existed))goto finish;
        }
        if(!restore && backup.state==1){
            if(!sl_registry_load(algorithm,&api) || !sl_installed_hives(&api,root,&backup)) {
                fwprintf(stderr,L"SLShim registry configuration is incomplete or the OS edition/build changed. Preserve the backup and restore before reinstalling.\n");goto finish;
            }
            wprintf(L"SLShim is already installed in %ls. No files changed.\n",root);ok=TRUE;goto finish;
        }
        if(!restore){fwprintf(stderr,L"A previous SLShim backup already exists. Run /slshim-restore before reinstalling.\n");goto finish;}
    } else if(restore) {
        wprintf(L"No SLShim restore manifest exists in this target. Any other backup files are retained.\n");
        remove_empty_backup=ok=TRUE;
        goto finish;
    }
    if(!sl_registry_load(algorithm,&api))goto finish;
    swprintf(stage_name,64,L".nttp-slshim-stage-%lu",GetCurrentProcessId());
    if(!build_path(stage,root,stage_name) || !CreateDirectoryW(stage,NULL))goto finish;
    owns_stage=TRUE;
    if(!sl_target_file(root,L"Windows\\System32\\Config\\SYSTEM",system) ||
       !sl_target_file(root,L"Windows\\System32\\Config\\SOFTWARE",software) ||
       !build_path(new_system,stage,L"SYSTEM") || !build_path(new_software,stage,L"SOFTWARE"))goto finish;
    if(restore) {
        wchar_t original_system[PATH_SIZE]={0},original_software[PATH_SIZE]={0};
        for(unsigned i=0;i<backup.count;++i) {
            if(!_wcsicmp(backup.files[i].relative,L"Windows\\System32\\Config\\SYSTEM"))sl_original_name(original_system,directory,i);
            if(!_wcsicmp(backup.files[i].relative,L"Windows\\System32\\Config\\SOFTWARE"))sl_original_name(original_software,directory,i);
        }
        if(!original_system[0] || !original_software[0] ||
           sl_config_hives(&api,root,system,software,new_system,new_software,&backup,original_system,original_software))goto finish;
        for(unsigned i=0;i<backup.count;++i) {
            SlBackupFile *entry=&backup.files[i];wchar_t target[PATH_SIZE],original[PATH_SIZE];
            if(!sl_target_file(root,entry->relative,target))goto finish;
            BOOL hive=wcsstr(entry->relative,L"\\Config\\")!=NULL;
            const wchar_t *source=NULL;
            if(hive)source=!_wcsicmp(entry->relative,L"Windows\\System32\\Config\\SYSTEM")?new_system:new_software;
            else if(entry->existed) {if(!sl_original_name(original,directory,i))goto finish;source=original;}
            if(source) {
                if(hive && !sl_metadata_copy(target,source))goto finish;
                if(!spp_add_file(&plan,source,target,FALSE,FALSE,0))goto finish;
            } else if(spp_path_type(target,FALSE,FALSE)) {
                unsigned slot=wcsstr(entry->relative,L"nttp-slshim-x64.dll")?2:(wcsstr(entry->relative,L"SysWOW64")!=NULL);
                wchar_t name[32];swprintf(name,32,L"removed-%u.dll",slot);
                if(!build_path(removed[slot],stage,name))goto finish;
                wcscpy(removed_target[slot],target);
                HANDLE file=spp_open(target,DELETE,OPEN_EXISTING);
                BOOL moved=file!=INVALID_HANDLE_VALUE && spp_rename(file,removed[slot]);
                if(file!=INVALID_HANDLE_VALUE)CloseHandle(file);
                if(!moved){removed[slot][0]=0;goto finish;}
            }
        }
    } else {
        if(sl_config_hives(&api,root,system,software,new_system,new_software,&backup,NULL,NULL))goto finish;
        WORD native_machine=0;
        for(unsigned arch=0;arch<2;++arch) {
            wchar_t folder[PATH_SIZE],base[PATH_SIZE];
            if(!build_path(base,root,arch?L"Windows\\SysWOW64":L"Windows\\System32"))goto finish;
            if(arch && native_machine==IMAGE_FILE_MACHINE_I386)break;
            if(arch && !spp_path_type(base,TRUE,FALSE))continue;
            if(!spp_path_chain(base,TRUE))goto finish;
            unsigned files_added=0;
            for(unsigned module=0;module<5;++module) {
                wchar_t target[PATH_SIZE],relative[96],payload[PATH_SIZE];
                swprintf(relative,96,L"Windows\\%ls\\%ls",arch?L"SysWOW64":L"System32",sl_modules[module]);
                if(!sl_target_file(root,relative,target))goto finish;
                if(!spp_path_type(target,FALSE,FALSE))continue;
                const SlLibrary *library=sl_library(algorithm,target,sl_modules[module]);
                if(!library || !sl_payload_file(algorithm,&library->payload,payload))goto finish;
                if(!native_machine)native_machine=library->machine;
                if(library->machine!=(arch?IMAGE_FILE_MACHINE_I386:native_machine))goto finish;
                if(!sl_stage_entry(algorithm,root,stage,relative,payload,&backup,&plan,library->machine))goto finish;
                ++files_added;
            }
            if(!arch && files_added<3){fwprintf(stderr,L"Provide an intact Windows licensing DLL set.\n");goto finish;}
            if(files_added) {
                wchar_t relative[96],target[PATH_SIZE],payload[PATH_SIZE];
                WORD machine=arch?IMAGE_FILE_MACHINE_I386:native_machine;
                swprintf(relative,96,L"Windows\\%ls\\nttp-slshim.dll",arch?L"SysWOW64":L"System32");
                if(!sl_target_file(root,relative,target) || GetFileAttributesW(target)!=INVALID_FILE_ATTRIBUTES ||
                   !sl_payload_file(algorithm,&sl_runtime_payloads[machine==IMAGE_FILE_MACHINE_ARM64?2:
                                      machine==IMAGE_FILE_MACHINE_AMD64],payload) ||
                   !sl_stage_entry(algorithm,root,stage,relative,payload,&backup,&plan,machine))goto finish;
            }
        }
        if(native_machine==IMAGE_FILE_MACHINE_ARM64) {
            static const wchar_t relative[]=L"Windows\\System32\\nttp-slshim-x64.dll";
            wchar_t target[PATH_SIZE],payload[PATH_SIZE];
            if(!sl_target_file(root,relative,target) || GetFileAttributesW(target)!=INVALID_FILE_ATTRIBUTES ||
               !sl_payload_file(algorithm,&sl_woa_emulated,payload) ||
               !sl_stage_entry(algorithm,root,stage,relative,payload,&backup,&plan,IMAGE_FILE_MACHINE_AMD64))goto finish;
        }
        if(!sl_stage_entry(algorithm,root,stage,L"Windows\\System32\\Config\\SYSTEM",new_system,&backup,&plan,0) ||
           !sl_stage_entry(algorithm,root,stage,L"Windows\\System32\\Config\\SOFTWARE",new_software,&backup,&plan,0))goto finish;
        for(unsigned i=0;i<backup.count;++i)if(backup.files[i].existed) {
            wchar_t target[PATH_SIZE],original[PATH_SIZE];char sha[65];
            if(!sl_target_file(root,backup.files[i].relative,target) || !sl_original_name(original,directory,i))goto finish;
            if(!spp_path_type(original,FALSE,FALSE)) {
                if(!sl_copy(target,original))goto finish;
            }
            if(!sl_stream_sha(algorithm,original,sha) || strcmp(sha,backup.files[i].original))goto finish;
        }
        if(!sl_manifest_io(manifest,&backup,TRUE))goto finish;
    }
    if(!spp_apply(&plan))goto finish;
    committed=TRUE;
    for(unsigned i=0;i<backup.count;++i) {
        wchar_t target[PATH_SIZE];
        if(!sl_target_file(root,backup.files[i].relative,target))goto finish;
        if((!restore || backup.files[i].existed) && !sl_attribute(target,backup.files[i].attributes))goto finish;
    }
    backup.state=restore?2:1;
    if(!sl_manifest_io(manifest,&backup,TRUE))goto finish;
    if(restore && !sl_cleanup_restored(algorithm,directory,manifest,&backup))goto finish;
    remove_empty_backup=restore;
    ok=TRUE;
    wprintf(restore?L"SLShim removed. Original DLLs, service settings and kernel policy restored; unrelated registry settings retained.\n":
                    L"SLShim installed for %ls (build %ls). Original licensing services disabled; the dedicated shim service starts in the target after reboot.\n",backup.edition,backup.build);
    if(!restore)wprintf(L"Backups retained at %ls. /cishim remains a separate operation.\n",directory);
finish:
    if(!ok) {
        failure=GetLastError();if(!failure)failure=ERROR_INVALID_DATA;
        fwprintf(stderr,L"SLShim %ls failed (Win32 %lu). %ls\n",restore?L"restore":L"installation",failure,
                 committed?L"Files were committed; use /slshim-restore with the retained backup.":L"No successful deployment was committed. Preserve any reported backups.");
    }
    for(unsigned i=0;i<ARRAYSIZE(removed);++i)if(removed[i][0]) {
        if(!ok && !committed)spp_restore(removed[i],removed_target[i]);
        else if(!spp_remove(removed[i]))fwprintf(stderr,L"Inert runtime file remains at %ls.\n",removed[i]);
    }
    if(owns_stage) {
        for(unsigned i=0;i<SL_FILES;++i) {
            wchar_t name[32],file[PATH_SIZE];swprintf(name,32,L"payload-%02u.bin",i);
            if(build_path(file,stage,name))spp_remove(file);
        }
        wchar_t file[PATH_SIZE];
        if(build_path(file,stage,L"SYSTEM"))spp_remove(file);
        if(build_path(file,stage,L"SOFTWARE"))spp_remove(file);
        if(!RemoveDirectoryW(stage))fwprintf(stderr,L"Inspect remaining SLShim staging files at %ls.\n",stage);
    }
    if(lock!=INVALID_HANDLE_VALUE) {
        if(remove_empty_backup) {
            FILE_DISPOSITION_INFO disposition={.DeleteFile=TRUE};
            if(!SetFileInformationByHandle(lock,FileDispositionInfo,&disposition,sizeof disposition))
                fwprintf(stderr,L"Could not remove the completed lock at %ls.\n",lock_path);
        }
        CloseHandle(lock);
    }
    if(remove_empty_backup && RemoveDirectoryW(directory)) {
        wchar_t parent[PATH_SIZE];
        if(build_path(parent,root,L"NTTimebombBackup"))RemoveDirectoryW(parent);
    }
    if(api.module)FreeLibrary(api.module);
    free(plan.files);free(plan.directories);
    if(!ok)SetLastError(failure);
    return ok;
}

static int run_slshim(int argc,wchar_t **argv)
{
    wchar_t root[PATH_SIZE];
    BOOL restore=argc>=2 && !_wcsicmp(argv[1],L"/slshim-restore");
    if(argc!=3 || !normalize(root,argv[2]) || !sl_root(root)) {
        fwprintf(stderr,L"Usage: nttimebomb /slshim OFFLINE_ROOT\n       nttimebomb /slshim-restore OFFLINE_ROOT\n");return 2;
    }
    if((in_winpe() && !is_system()) || !enable_privilege(L"SeBackupPrivilege") || !enable_privilege(L"SeRestorePrivilege")) {
        privilege_hint();return 3;
    }
    BCRYPT_ALG_HANDLE algorithm;
    if(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,NULL,0)<0)return 1;
    BOOL ok=sl_install(algorithm,root,restore);
    DWORD failure=GetLastError();
    BCryptCloseAlgorithmProvider(algorithm,0);
    if(!ok && (failure==ERROR_ACCESS_DENIED || failure==ERROR_PRIVILEGE_NOT_HELD))privilege_hint();
    return ok?0:1;
}
