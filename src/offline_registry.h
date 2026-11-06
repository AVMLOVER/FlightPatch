/* Dynamic Offline Registry Library API. Ordinary commands do not load it. */
typedef void *SlKey;
typedef struct {
    HMODULE module;
    DWORD (WINAPI *OpenHive)(const wchar_t *,SlKey *);
    DWORD (WINAPI *CloseHive)(SlKey);
    DWORD (WINAPI *SaveHive)(SlKey,const wchar_t *,DWORD,DWORD);
    DWORD (WINAPI *OpenKey)(SlKey,const wchar_t *,SlKey *);
    DWORD (WINAPI *CloseKey)(SlKey);
    DWORD (WINAPI *CreateKey)(SlKey,const wchar_t *,wchar_t *,DWORD,PSECURITY_DESCRIPTOR,SlKey *,DWORD *);
    DWORD (WINAPI *GetValue)(SlKey,const wchar_t *,const wchar_t *,DWORD *,void *,DWORD *);
    DWORD (WINAPI *SetValue)(SlKey,const wchar_t *,DWORD,const BYTE *,DWORD);
    DWORD (WINAPI *DeleteValue)(SlKey,const wchar_t *);
    DWORD (WINAPI *DeleteKey)(SlKey,const wchar_t *);
    DWORD (WINAPI *EnumKey)(SlKey,DWORD,wchar_t *,DWORD *,wchar_t *,DWORD *,FILETIME *);
} SlRegistry;

static BOOL sl_get(SlRegistry *api,SlKey hive,const wchar_t *key,const wchar_t *name,
                   DWORD expected,void *value,DWORD size)
{
    DWORD type=0,length=size;
    return api->GetValue(hive,key,name,&type,value,&length)==ERROR_SUCCESS && type==expected && length==size;
}
static BOOL sl_string(SlRegistry *api,SlKey hive,const wchar_t *key,const wchar_t *name,wchar_t *value,DWORD capacity)
{
    DWORD type=0,size=capacity*sizeof(wchar_t);
    return api->GetValue(hive,key,name,&type,value,&size)==ERROR_SUCCESS && type==REG_SZ &&
           size>=2 && size%2==0 && size<=capacity*2 && !value[size/2-1] &&
           wcslen(value)+1==size/2;
}
static DWORD sl_set(SlRegistry *api,SlKey hive,const wchar_t *path,const wchar_t *name,
                    DWORD type,const void *data,DWORD size)
{
    SlKey key=NULL;
    DWORD error=api->CreateKey(hive,path,NULL,0,NULL,&key,NULL);
    if(!error)error=api->SetValue(key,name,type,data,size);
    if(key)api->CloseKey(key);
    return error;
}
static DWORD sl_set_number(SlRegistry *api,SlKey hive,const wchar_t *path,const wchar_t *name,DWORD value)
{ return sl_set(api,hive,path,name,REG_DWORD,&value,sizeof value); }
static DWORD sl_set_string(SlRegistry *api,SlKey hive,const wchar_t *path,const wchar_t *name,DWORD type,const wchar_t *value)
{ return sl_set(api,hive,path,name,type,value,(DWORD)((wcslen(value)+1)*2)); }
static DWORD sl_delete_tree(SlRegistry *api,SlKey hive,const wchar_t *path,unsigned depth)
{
    if(depth>8)return ERROR_INVALID_DATA;
    SlKey key=NULL;
    DWORD error=api->OpenKey(hive,path,&key);
    if(error==ERROR_FILE_NOT_FOUND)return ERROR_SUCCESS;
    if(error)return error;
    for(;;) {
        wchar_t name[256];DWORD count=256;
        error=api->EnumKey(key,0,name,&count,NULL,NULL,NULL);
        if(error==ERROR_NO_MORE_ITEMS){error=ERROR_SUCCESS;break;}
        if(error)break;
        error=sl_delete_tree(api,key,name,depth+1);
        if(error)break;
    }
    api->CloseKey(key);
    return error?error:api->DeleteKey(hive,path);
}
