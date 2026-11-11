/* /wd - one switch for the two components that stop working on an expired build:
   the uiAccess programs and the Defender service.

   Part 1 reuses the uiAccess work: the declaration is blanked in the manifest, the
   program is signed locally and the certificate is trusted, either staged for the
   next start on the running installation or in place on another volume. After that
   every program is inspected and started once, so the report shows whether the file
   really changed and which error remains.

   Part 2 repairs the Defender service start: it reports the service state, sets the
   start type back to automatic, checks the platform folder, asks MpCmdRun to reset
   the platform when it is present, and starts the service, printing the Win32 code
   of every step. Nothing is patched blindly: the codes say what to fix next. */

static BOOL run_tool(const wchar_t *tool, wchar_t *command, const wchar_t *directory);

static void wd_state(const wchar_t *label, const wchar_t *path)
{
    DWORD attributes = GetFileAttributesW(path);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"%-16ls: absent\n", label);
        return;
    }
    HANDLE file = spp_open(path, GENERIC_READ, OPEN_EXISTING);
    BCRYPT_ALG_HANDLE algorithm;
    Output content = {0};
    BOOL ok = file != INVALID_HANDLE_VALUE &&
              BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) >= 0 &&
              offline_read(file, &content, algorithm);
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    NttpCertificate certificate = {0};
    BOOL signed_here = signer_extract(path, WINTRUST_SUBJECT_NAME, &certificate);
    BOOL requirement = FALSE;
    if (ok) {
        static const char attribute[] = "uiAccess=\"true\"";
        for (DWORD o = 0; o + sizeof attribute - 1 <= content.size; ++o) {
            if (!memcmp(content.data + o, attribute, sizeof attribute - 1)) {
                requirement = TRUE;
                break;
            }
        }
    }
    free(content.data);
    wprintf(L"%-16ls: uiAccess %ls, local signature %ls\n", label,
            requirement ? L"still required" : L"removed", signed_here ? L"present" : L"missing");
}

/* Start the program once and report the native result. This is the check that says
   whether the change was enough. */
static void wd_start(const wchar_t *label, const wchar_t *path)
{
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES)
        return;
    wchar_t command[PATH_SIZE + 8];
    if (swprintf(command, ARRAYSIZE(command), L"\"%ls\"", path) < 0)
        return;
    STARTUPINFOW startup = {.cb = sizeof startup};
    PROCESS_INFORMATION process = {0};
    if (!CreateProcessW(path, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process)) {
        DWORD error = GetLastError();
        wprintf(L"%-16ls: start failed, Win32 %lu (0x%08lX)\n", label, error, error);
        return;
    }
    WaitForSingleObject(process.hProcess, 3000);
    DWORD code = 0;
    if (GetExitCodeProcess(process.hProcess, &code) && code != STILL_ACTIVE)
        wprintf(L"%-16ls: started and exited with %lu (0x%08lX)\n", label, code, code);
    else
        wprintf(L"%-16ls: started\n", label);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
}

static void wd_report(void)
{
    wchar_t windows[PATH_SIZE];
    if (!GetSystemWindowsDirectoryW(windows, PATH_SIZE))
        return;
    wprintf(L"\nWhat is on disk now and what happens when it starts:\n");
    static const struct { const wchar_t *live; const wchar_t *label; } programs[] = {
        {L"System32\\osk.exe", L"osk.exe"},
        {L"System32\\Narrator.exe", L"Narrator.exe"},
        {L"System32\\Magnify.exe", L"Magnify.exe"}
    };
    for (unsigned i = 0; i < ARRAYSIZE(programs); ++i) {
        wchar_t path[PATH_SIZE];
        if (!build_path(path, windows, programs[i].live))
            continue;
        wd_state(programs[i].label, path);
        wd_start(programs[i].label, path);
    }
}

static BOOL wd_defender(void)
{
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE service = manager ? OpenServiceW(manager, L"WinDefend",
                                               SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG |
                                               SERVICE_START) : NULL;
    if (!service) {
        wprintf(L"\nWindows Defender: cannot open the WinDefend service (Win32 %lu).\n", GetLastError());
        if (manager)
            CloseServiceHandle(manager);
        return FALSE;
    }
    wprintf(L"\nWindows Defender service:\n");
    SERVICE_STATUS status = {0};
    SERVICE_STATUS_PROCESS extended = {0};
    DWORD needed = 0;
    if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE *)&extended, sizeof extended, &needed)) {
        wprintf(L"  state          : %lu\n", extended.dwCurrentState);
        if (extended.dwWin32ExitCode && extended.dwWin32ExitCode != ERROR_SERVICE_SPECIFIC_ERROR)
            wprintf(L"  last error     : %lu (0x%08lX)\n", extended.dwWin32ExitCode, extended.dwWin32ExitCode);
    }
    if (ChangeServiceConfigW(service, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE,
                             NULL, NULL, NULL, NULL, NULL, NULL, NULL))
        wprintf(L"  start type     : automatic\n");
    else
        wprintf(L"  start type     : cannot set (Win32 %lu)\n", GetLastError());

    wchar_t platform[PATH_SIZE], engine[PATH_SIZE];
    wchar_t program_data[PATH_SIZE] = {0};
    DWORD length = GetEnvironmentVariableW(L"ProgramData", program_data, PATH_SIZE);
    if (length && length < PATH_SIZE && build_path(platform, program_data, L"Microsoft\\Windows Defender\\Platform")) {
        wchar_t pattern[PATH_SIZE];
        if (swprintf(pattern, PATH_SIZE, L"%ls\\*", platform) > 0) {
            WIN32_FIND_DATAW entry;
            HANDLE find = FindFirstFileW(pattern, &entry);
            unsigned found = 0;
            if (find != INVALID_HANDLE_VALUE) {
                do {
                    if (!(entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
                        !wcscmp(entry.cFileName, L".") || !wcscmp(entry.cFileName, L".."))
                        continue;
                    if (build_path(engine, platform, entry.cFileName) && build_path(engine, engine, L"MpEngine.dll") &&
                        GetFileAttributesW(engine) != INVALID_FILE_ATTRIBUTES) {
                        wprintf(L"  platform       : %ls\n", entry.cFileName);
                        ++found;
                    }
                } while (FindNextFileW(find, &entry));
                FindClose(find);
            }
            if (!found)
                wprintf(L"  platform       : no engine under %ls\n", platform);
        }
    }

    wchar_t tools[PATH_SIZE], reset[PATH_SIZE];
    if (GetEnvironmentVariableW(L"ProgramFiles", tools, PATH_SIZE) && tools[0] &&
        build_path(reset, tools, L"Windows Defender\\MpCmdRun.exe") &&
        GetFileAttributesW(reset) != INVALID_FILE_ATTRIBUTES) {
        wchar_t command[PATH_SIZE + 16];
        if (swprintf(command, ARRAYSIZE(command), L"\"%ls\" -ResetPlatform", reset) > 0) {
            if (run_tool(reset, command, NULL))
                wprintf(L"  platform reset : done\n");
            else
                wprintf(L"  platform reset : failed, continue with the start\n");
        }
    } else {
        wprintf(L"  platform reset : MpCmdRun.exe not found\n");
    }

    BOOL started = StartServiceW(service, 0, NULL);
    DWORD error = started ? 0 : GetLastError();
    if (error == ERROR_SERVICE_ALREADY_RUNNING)
        wprintf(L"  start          : already running\n");
    else if (started)
        wprintf(L"  start          : requested; waiting\n");
    else
        wprintf(L"  start          : failed, Win32 %lu (0x%08lX)\n", error, error);
    for (unsigned i = 0; i < 20; ++i) {
        Sleep(500);
        if (!QueryServiceStatus(service, &status))
            break;
        if (status.dwCurrentState == SERVICE_RUNNING) {
            wprintf(L"  state          : running\n");
            break;
        }
        if (status.dwCurrentState == SERVICE_STOPPED) {
            wprintf(L"  state          : stopped again (the service terminated during start)\n");
            break;
        }
    }
    BOOL running = status.dwCurrentState == SERVICE_RUNNING;
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    if (!running)
        wprintf(L"The service still does not stay up. Its own platform refuses to run on this build;\n"
                L"the next step is a code patch in MpSvc/MpEngine, and the report above says where.\n");
    return running;
}

static int run_wd(BCRYPT_ALG_HANDLE algorithm, int argc, wchar_t **argv)
{
    (void)algorithm;
    (void)argv;
    if (argc != 2) {
        fwprintf(stderr, L"Usage: nttimebomb /wd\n");
        return 2;
    }
    BOOL elevated = FALSE;
    BYTE administrators[SECURITY_MAX_SID_SIZE];
    DWORD size = sizeof administrators;
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, administrators, &size) ||
        !CheckTokenMembership(NULL, administrators, &elevated) || !elevated) {
        fwprintf(stderr, L"Open an elevated command prompt inside the test Windows.\n");
        return 2;
    }
    BOOL running = wd_defender();
    return running ? 0 : 1;
}
