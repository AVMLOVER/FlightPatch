#ifndef NTTP_SLSHIM_CONTROLS_H
#define NTTP_SLSHIM_CONTROLS_H

/* A boot may create another LastKnownGood set after installation. Read-only
   discovery and source mapping keep restore from leaving that clone active. */
enum { SL_CONTROL_LIMIT=64, SL_CONTROL_ENUM_LIMIT=4096 };
typedef struct { DWORD target,source; } SlControlMap;

static DWORD sl_control_add(DWORD ids[SL_CONTROL_LIMIT],DWORD *count,DWORD id)
{
    if(!id || id>999)return ERROR_INVALID_DATA;
    for(DWORD i=0;i<*count;++i)if(ids[i]==id)return ERROR_SUCCESS;
    if(*count>=SL_CONTROL_LIMIT)return ERROR_BUFFER_OVERFLOW;
    ids[(*count)++]=id;return ERROR_SUCCESS;
}
static BOOL sl_control_parse(const wchar_t *name,DWORD *id)
{
    if(wcslen(name)!=13 || _wcsnicmp(name,L"ControlSet",10))return FALSE;
    DWORD number=0;
    for(unsigned i=10;i<13;++i) {
        if(name[i]<L'0' || name[i]>L'9')return FALSE;
        number=number*10+(DWORD)(name[i]-L'0');
    }
    *id=number;return number!=0;
}
static DWORD sl_control_text(SlRegistry *api,SlKey hive,const wchar_t *key,
                             const wchar_t *name,DWORD expected_type,const wchar_t *expected)
{
    wchar_t text[260];DWORD type=0,size=sizeof text;
    DWORD error=api->GetValue(hive,key,name,&type,text,&size);
    if(error)return error;
    if(type!=expected_type || size<2 || size%2 || size>sizeof text || text[size/2-1] ||
       wcslen(text)+1!=size/2)return ERROR_INVALID_DATA;
    int different=!wcscmp(name,L"ServiceMain")?wcscmp(text,expected):_wcsicmp(text,expected);
    return different?ERROR_REVISION_MISMATCH:ERROR_SUCCESS;
}
static DWORD sl_control_owned(SlRegistry *api,SlKey hive,DWORD id,BOOL *owned)
{
    wchar_t service[100],parameters[120];SlKey key=NULL;
    *owned=FALSE;
    swprintf(service,100,L"ControlSet%03lu\\Services\\NTTimebombSLShim",id);
    DWORD error=api->OpenKey(hive,service,&key);
    if(error==ERROR_FILE_NOT_FOUND)return ERROR_SUCCESS;
    if(key)api->CloseKey(key);
    if(error)return error;
    /* A same-name foreign service is never sufficient evidence of ownership. */
    error=sl_control_text(api,hive,service,L"ImagePath",REG_EXPAND_SZ,
                          L"\"%SystemRoot%\\System32\\svchost.exe\" -k NTTimebombSLShim");
    swprintf(parameters,120,L"%ls\\Parameters",service);
    if(!error)error=sl_control_text(api,hive,parameters,L"ServiceDll",REG_EXPAND_SZ,
                                   L"%SystemRoot%\\System32\\nttp-slshim.dll");
    if(!error)error=sl_control_text(api,hive,parameters,L"ServiceMain",REG_SZ,L"ServiceMain");
    if(!error)*owned=TRUE;
    return error;
}
static DWORD sl_control_list(SlRegistry *api,SlKey current,const SlBackup *backup,
                             BOOL include_selected,DWORD ids[SL_CONTROL_LIMIT],DWORD *count)
{
    *count=0;
    if(!backup->control_count || backup->control_count>3)return ERROR_INVALID_DATA;
    DWORD error=ERROR_SUCCESS;
    for(unsigned i=0;!error && i<backup->control_count;++i)
        error=sl_control_add(ids,count,backup->controls[i]);
    if(error)return error;
    if(include_selected) {
        const wchar_t *names[]={L"Current",L"Default",L"LastKnownGood"};
        for(unsigned i=0;i<3;++i) {
            DWORD id=0,type=0,size=sizeof id;
            error=api->GetValue(current,L"Select",names[i],&type,&id,&size);
            if(error==ERROR_FILE_NOT_FOUND && i)continue;
            if(error)return error;
            if(type!=REG_DWORD || size!=sizeof id || (!i && !id))return ERROR_INVALID_DATA;
            if(!id)continue;
            if(id>999)return ERROR_INVALID_DATA;
            wchar_t control[20];SlKey key=NULL;
            swprintf(control,20,L"ControlSet%03lu",id);
            error=api->OpenKey(current,control,&key);
            if(key)api->CloseKey(key);
            if(error)return error;
            if((error=sl_control_add(ids,count,id))!=ERROR_SUCCESS)return error;
        }
    }
    for(DWORD index=0;index<SL_CONTROL_ENUM_LIMIT;++index) {
        wchar_t name[256];DWORD length=256,id=0;
        error=api->EnumKey(current,index,name,&length,NULL,NULL,NULL);
        if(error==ERROR_NO_MORE_ITEMS)return ERROR_SUCCESS;
        if(error)return error;
        if(length>=256)return ERROR_INVALID_DATA;
        name[length]=0;
        if(!sl_control_parse(name,&id))continue;
        BOOL owned=FALSE;
        error=sl_control_owned(api,current,id,&owned);
        if(error)return error;
        if(owned && (error=sl_control_add(ids,count,id))!=ERROR_SUCCESS)return error;
    }
    return ERROR_BUFFER_OVERFLOW;
}

typedef struct {
    BYTE *policy;DWORD size;
    BOOL exists[4];DWORD start[4];
} SlControlSignature;
static DWORD sl_control_signature(SlRegistry *api,SlKey original,DWORD id,SlControlSignature *signature)
{
    memset(signature,0,sizeof *signature);
    wchar_t options[100];DWORD type=0,size=0;
    swprintf(options,100,L"ControlSet%03lu\\Control\\ProductOptions",id);
    DWORD error=api->GetValue(original,options,L"ProductPolicy",&type,NULL,&size);
    if(error)return error;
    if(type!=REG_BINARY || size<24 || size>SL_POLICY_MAX)return ERROR_INVALID_DATA;
    signature->policy=malloc(size);
    if(!signature->policy)return ERROR_NOT_ENOUGH_MEMORY;
    signature->size=size;
    error=api->GetValue(original,options,L"ProductPolicy",&type,signature->policy,&size);
    if(!error && (type!=REG_BINARY || size!=signature->size ||
                   !sl_policy_valid(signature->policy,size)))error=ERROR_INVALID_DATA;
    BOOL core=FALSE;
    for(unsigned s=0;!error && s<4;++s) {
        wchar_t service[100];SlKey key=NULL;
        swprintf(service,100,L"ControlSet%03lu\\Services\\%ls",id,sl_platform_services[s]);
        error=api->OpenKey(original,service,&key);
        if(error==ERROR_FILE_NOT_FOUND){error=ERROR_SUCCESS;continue;}
        if(key)api->CloseKey(key);
        if(error)break;
        signature->exists[s]=TRUE;
        if(!sl_get(api,original,service,L"Start",REG_DWORD,&signature->start[s],4) ||
           signature->start[s]>4){error=ERROR_INVALID_DATA;break;}
        if(s==0 || s==2)core=TRUE;
    }
    if(!error && !core)error=ERROR_INVALID_DATA;
    if(error){free(signature->policy);signature->policy=NULL;}
    return error;
}
static BOOL sl_control_same(const SlControlSignature *a,const SlControlSignature *b)
{
    if(a->size!=b->size || memcmp(a->policy,b->policy,a->size))return FALSE;
    for(unsigned s=0;s<4;++s)
        if(a->exists[s]!=b->exists[s] || (a->exists[s] && a->start[s]!=b->start[s]))return FALSE;
    return TRUE;
}
static DWORD sl_restore_controls(SlRegistry *api,SlKey current,SlKey original,const SlBackup *backup,
                                 SlControlMap maps[SL_CONTROL_LIMIT],DWORD *count)
{
    DWORD ids[SL_CONTROL_LIMIT],length=0;*count=0;
    DWORD error=sl_control_list(api,current,backup,FALSE,ids,&length);
    if(error)return error;
    SlControlSignature first={0};BOOL identical=TRUE;
    /* Validate every original source even when its current set was pruned. */
    for(unsigned i=0;!error && i<backup->control_count;++i) {
        SlControlSignature next={0};
        error=sl_control_signature(api,original,backup->controls[i],&next);
        if(error)break;
        if(!i)first=next;
        else {identical=identical && sl_control_same(&first,&next);free(next.policy);}
    }
    if(!error)for(DWORD i=0;i<length;++i) {
        DWORD source=0;
        wchar_t control[20];swprintf(control,20,L"ControlSet%03lu",ids[i]);
        for(unsigned j=0;j<backup->control_count;++j)
            if(ids[i]==backup->controls[j]){source=ids[i];break;}
        if(!source) {
            /* A set absent from Select at installation may still have an exact
               original in the whole SYSTEM backup. Prefer it to ancestry inference. */
            SlKey same_id=NULL;error=api->OpenKey(original,control,&same_id);
            if(same_id)api->CloseKey(same_id);
            if(!error) {
                SlControlSignature saved={0};
                error=sl_control_signature(api,original,ids[i],&saved);
                free(saved.policy);
                if(error)break;
                source=ids[i];
            } else if(error==ERROR_FILE_NOT_FOUND) {
                error=ERROR_SUCCESS;
                if(!identical){error=ERROR_REVISION_MISMATCH;break;}
                source=backup->controls[0];
            } else break;
        }
        SlKey key=NULL;
        error=api->OpenKey(current,control,&key);
        if(error==ERROR_FILE_NOT_FOUND){error=ERROR_SUCCESS;continue;}
        if(key)api->CloseKey(key);
        if(error)break;
        maps[*count]=(SlControlMap){ids[i],source};++*count;
    }
    free(first.policy);
    return error;
}
#endif
