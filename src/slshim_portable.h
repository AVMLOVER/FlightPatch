/* Small freestanding helpers: the target DLL must not require a newer CRT. */
static void *sl_memcpy(void *target,const void *source,size_t size)
{ BYTE *out=target;const BYTE *in=source;for(size_t i=0;i<size;++i)out[i]=in[i];return target; }
static void *sl_memmove(void *target,const void *source,size_t size)
{
    BYTE *out=target;const BYTE *in=source;
    if((uintptr_t)out<(uintptr_t)in)for(size_t i=0;i<size;++i)out[i]=in[i];
    else for(size_t i=size;i;--i)out[i-1]=in[i-1];
    return target;
}
static void *sl_memset(void *target,int value,size_t size)
{ BYTE *out=target;for(size_t i=0;i<size;++i)out[i]=(BYTE)value;return target; }
static int sl_memcmp(const void *first,const void *second,size_t size)
{ const BYTE *a=first,*b=second;for(size_t i=0;i<size;++i)if(a[i]!=b[i])return a[i]<b[i]?-1:1;return 0; }
static size_t sl_length(const wchar_t *value)
{ size_t length=0;while(value[length])++length;return length; }
static wchar_t sl_fold(wchar_t value)
{ return value>=L'A' && value<=L'Z'?value+(L'a'-L'A'):value; }
static int sl_compare_n(const wchar_t *first,const wchar_t *second,size_t limit)
{
    for(size_t i=0;i<limit;++i) {
        wchar_t a=sl_fold(first[i]),b=sl_fold(second[i]);
        if(a!=b)return a<b?-1:1;
        if(!a)return 0;
    }
    return 0;
}
static int sl_compare(const wchar_t *first,const wchar_t *second)
{ return sl_compare_n(first,second,sl_length(first)+1); }
static BOOL sl_append(wchar_t *target,const wchar_t *part)
{
    size_t a=sl_length(target),b=sl_length(part);
    if(a>=MAX_PATH || b>=MAX_PATH-a)return FALSE;
    for(size_t i=0;i<=b;++i)target[a+i]=part[i];
    return TRUE;
}
static BOOL sl_append_hex(wchar_t *target,ULONGLONG value,unsigned digits)
{
    wchar_t text[17];if(digits>16)return FALSE;
    for(unsigned i=0;i<digits;++i)text[i]=L"0123456789abcdef"[(unsigned)(value>>((digits-i-1)*4))&15];
    text[digits]=0;return sl_append(target,text);
}
#define memcpy sl_memcpy
#define memmove sl_memmove
#define memset sl_memset
#define memcmp sl_memcmp
#define wcslen sl_length
#define _wcsicmp sl_compare
#define _wcsnicmp sl_compare_n
