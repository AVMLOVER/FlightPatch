/* Bounded ProductPolicy reader shared by the offline installer and service.
   Names are length-delimited UTF-16; the trailing marker is four bytes. */
#ifndef NTTP_SLSHIM_POLICY_H
#define NTTP_SLSHIM_POLICY_H
enum { SL_POLICY_MAX = 1024 * 1024 };
static DWORD sl_word32(const BYTE *p) { DWORD v; memcpy(&v,p,4); return v; }
static WORD sl_word16(const BYTE *p) { WORD v; memcpy(&v,p,2); return v; }
static BOOL sl_policy_valid(const BYTE *data, DWORD size)
{
    if (!data || size<24 || size>SL_POLICY_MAX || sl_word32(data)!=size ||
        sl_word32(data+4)!=size-24 || sl_word32(data+8)!=4 || data[size-4]!=0x45)
        return FALSE;
    DWORD position=20;
    while(position<size-4) {
        if(size-4-position<16) return FALSE;
        const BYTE *entry=data+position;
        DWORD length=sl_word16(entry), name=sl_word16(entry+2), value=sl_word16(entry+6);
        if(length<16 || length%4 || length>size-4-position || !name || name%2 || 16+name+value>length)
            return FALSE;
        for(DWORD p=0;p<name;p+=2) if(!sl_word16(entry+16+p)) return FALSE;
        position+=length;
    }
    return position==size-4;
}
static BOOL sl_policy_name(const BYTE *entry, const wchar_t *name)
{
    size_t length=wcslen(name);
    return length==sl_word16(entry+2)/2 && !_wcsnicmp((const wchar_t *)(entry+16),name,length);
}
static DWORD sl_policy_get(const BYTE *data,DWORD size,const wchar_t *name,DWORD *type,const BYTE **value,DWORD *length)
{
    if(!name || !sl_policy_valid(data,size)) return ERROR_INVALID_DATA;
    BOOL found=FALSE;
    for(DWORD p=20;p<size-4;p+=sl_word16(data+p)) {
        const BYTE *entry=data+p;
        if(!sl_policy_name(entry,name)) continue;
        if(found) return ERROR_DUP_NAME;
        found=TRUE; *type=sl_word16(entry+4); *length=sl_word16(entry+6);
        *value=entry+16+sl_word16(entry+2);
    }
    return found?ERROR_SUCCESS:ERROR_FILE_NOT_FOUND;
}
static BOOL sl_policy_profile(BYTE *data,DWORD *size)
{
    if(!sl_policy_valid(data,*size)) return FALSE;
    DWORD output=20;
    for(DWORD p=20;p<*size-4;) {
        DWORD length=sl_word16(data+p);
        if(!sl_policy_name(data+p,L"Kernel-ExpirationDate")) {
            memmove(data+output,data+p,length);
            BYTE *entry=data+output;
            if(sl_policy_name(entry,L"Kernel-NonGenuineNotificationType") &&
               sl_word16(entry+4)==REG_DWORD && sl_word16(entry+6)==4)
                memset(entry+16+sl_word16(entry+2),0,4);
            output+=length;
        }
        p+=length;
    }
    memcpy(data+output,data+*size-4,4);
    *size=output+4;
    DWORD payload=*size-24;
    memcpy(data,size,4); memcpy(data+4,&payload,4);
    return sl_policy_valid(data,*size);
}
#endif
