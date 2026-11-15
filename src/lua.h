/* /enable-lua and /disable-lua - set the LUA switch of the target system.

   The uiAccess programs (osk.exe, Narrator.exe, Magnify.exe) only start while the
   LUA subsystem is off, because the uiAccess token request fails on an expired
   preview build. These two commands write the same value the settings UI writes:

       HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
           EnableLUA   REG_DWORD   0 = LUA off, 1 = LUA on

   A running installation is changed through the live registry, an offline volume
   through its config\SOFTWARE hive, saved back with the same backup and
   chunked-copy path the certificate store uses. A restart is required. */

#define LUA_KEY L"Microsoft\\Windows\\CurrentVersion\\Policies\\System"
#define LUA_VALUE L"EnableLUA"

static BOOL lua_elevated(void)
{
    BOOL admin = FALSE;
    BYTE administrators[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof administrators;
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, administrators, &size) ||
        !CheckTokenMembership(NULL, administrators, &admin) || !admin) {
        fwprintf(stderr, L"Open an elevated command prompt.\n");
        return FALSE;
    }
    HANDLE token = NULL;
    BOOL elevated = FALSE;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION state = {0};
        DWORD length = 0;
        if (GetTokenInformation(token, TokenElevation, &state, sizeof state, &length))
            elevated = state.TokenIsElevated != 0;
        CloseHandle(token);
    }
    if (!elevated)
        fwprintf(stderr, L"Open an elevated command prompt.\n");
    return elevated;
}

static BOOL lua_online(DWORD value)
{
    HKEY key;
    LSTATUS status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\" LUA_KEY, 0, NULL, 0,
                                     KEY_SET_VALUE, NULL, &key, NULL);
    if (status != ERROR_SUCCESS) {
        fwprintf(stderr, L"Cannot open the live policy key (Win32 %ld).\n", (long)status);
        return FALSE;
    }
    status = RegSetValueExW(key, LUA_VALUE, 0, REG_DWORD, (const BYTE *)&value, sizeof value);
    if (!status)
        status = RegFlushKey(key);
    RegCloseKey(key);
    if (status) {
        fwprintf(stderr, L"Cannot write EnableLUA (Win32 %ld).\n", (long)status);
        return FALSE;
    }
    return TRUE;
}

static BOOL lua_offline(const wchar_t *root, DWORD value)
{
    if (!offline_root(root, TRUE)) {
        fwprintf(stderr, L"Specify an offline Windows root with Windows\\System32\\config\\SOFTWARE.\n");
        return FALSE;
    }
    WintrustHive hive;
    if (!wintrust_hive_load(&hive, root)) {
        fwprintf(stderr, L"Cannot open %ls\\Windows\\System32\\config\\SOFTWARE.\n", root);
        return FALSE;
    }
    DWORD error = wintrust_hive_path(&hive, LUA_KEY);
    if (!error)
        error = sl_set(&hive.api, hive.hive, LUA_KEY, LUA_VALUE, REG_DWORD,
                       (const BYTE *)&value, sizeof value);
    if (error) {
        fwprintf(stderr, L"Cannot write EnableLUA into the offline hive (Win32 %lu).\n", error);
        wintrust_hive_close(&hive);
        return FALSE;
    }
    if (!wintrust_hive_publish(&hive)) {
        wintrust_hive_close(&hive);
        return FALSE;
    }
    return TRUE;
}

static int run_lua(int argc, wchar_t **argv)
{
    BOOL enable = !_wcsicmp(argv[1], L"/enable-lua");
    if (argc > 3) {
        fwprintf(stderr, L"Usage: nttimebomb %ls [OFFLINE_ROOT]\n", argv[1]);
        return 2;
    }
    DWORD value = enable ? 1 : 0;
    BOOL ok;
    wchar_t path[PATH_SIZE];
    if (argc == 3) {
        if (!normalize(path, argv[2])) {
            fwprintf(stderr, L"Use a local drive path.\n");
            return 2;
        }
        if (wintrust_running(path)) {
            if (!lua_elevated())
                return 2;
            ok = lua_online(value);
        } else {
            if ((in_winpe() && !is_system()) || !enable_privilege(L"SeBackupPrivilege") ||
                !enable_privilege(L"SeRestorePrivilege")) {
                privilege_hint();
                return 3;
            }
            ok = lua_offline(path, value);
        }
    } else {
        if (!lua_elevated())
            return 2;
        ok = lua_online(value);
    }
    if (ok)
        wprintf(L"EnableLUA is now %lu in %ls. Restart that system for the change to take effect.\n",
                (unsigned long)value, argc == 3 ? argv[2] : L"the running installation");
    return ok ? 0 : 1;
}
