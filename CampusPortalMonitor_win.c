/*
 * Campus Portal Monitor - native Windows prototype
 *
 * Build with LLVM clang-cl + Windows SDK:
 *
 *   clang-cl /O2 /W4 campus_monitor_win.c ^
 *       /link winhttp.lib crypt32.lib iphlpapi.lib ws2_32.lib ^
 *       /out:CampusPortalMonitor.exe
 *
 * First run:
 *   CampusPortalMonitor.exe --init
 *
 * Credentials are stored encrypted with Windows DPAPI and are tied to the
 * current Windows user account. The plaintext password is never written to
 * disk by this program.
 *
 * Runtime:
 *   CampusPortalMonitor.exe
 *
 * Useful test:
 *   CampusPortalMonitor.exe --diagnose
 */

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <iphlpapi.h>
#include <iptypes.h>
#include <netioapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <strsafe.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define PORTAL_HOST        L"192.168.2.1"
#define PORTAL_PORT        8090
#define PROBE_HOST         L"connectivitycheck.gstatic.com"
#define PROBE_PATH         L"/generate_204"
#define LOGIN_PATH         L"/login.xml"

#define CHECK_INTERVAL_MS  5000
#define POST_LOGIN_WAIT_MS 5000
#define RENEW_INTERVAL_MS  (2ULL * 60ULL * 60ULL * 1000ULL)
#define HTTP_TIMEOUT_MS    5000

#define CONFIG_DIR_NAME    L"CampusPortal"
#define CREDENTIALS_NAME   L"credentials.dat"

typedef struct {
    char username[256];
    char password[512];
} Credentials;

typedef struct {
    DWORD status;
    wchar_t location[2048];
    char *body;
    DWORD body_len;
    DWORD elapsed_ms;
    BOOL transport_ok;
} HttpResult;

typedef enum {
    STATE_UNKNOWN,
    STATE_ONLINE,
    STATE_CAPTIVE,
    STATE_OFFLINE,
    STATE_LOGIN_FAILED
} MonitorState;

/* ------------------------------------------------------------------------- */
/* Utility                                                                    */
/* ------------------------------------------------------------------------- */

static void print_time(void)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    printf("[%02u:%02u:%02u] ",
           st.wHour, st.wMinute, st.wSecond);
}

static void log_line(const char *fmt, ...)
{
    va_list ap;
    print_time();
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
}

static BOOL ensure_config_dir(wchar_t *out, size_t out_count)
{
    DWORD n = GetEnvironmentVariableW(L"APPDATA", out, (DWORD)out_count);
    if (n == 0 || n >= out_count - 32)
        return FALSE;

    if (FAILED(StringCchCatW(out, out_count, L"\\" CONFIG_DIR_NAME)))
        return FALSE;

    if (!CreateDirectoryW(out, NULL)) {
        DWORD e = GetLastError();
        if (e != ERROR_ALREADY_EXISTS)
            return FALSE;
    }

    return TRUE;
}

static BOOL credentials_path(wchar_t *out, size_t out_count)
{
    if (!ensure_config_dir(out, out_count))
        return FALSE;

    if (FAILED(StringCchCatW(out, out_count, L"\\" CREDENTIALS_NAME)))
        return FALSE;

    return TRUE;
}

static char *url_encode(const char *input)
{
    size_t len = strlen(input);
    size_t max = len * 3 + 1;
    char *out = (char *)malloc(max);
    size_t j = 0;

    if (!out)
        return NULL;

    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)input[i];

        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            out[j++] = (char)c;
        } else {
            static const char hex[] = "0123456789ABCDEF";
            out[j++] = '%';
            out[j++] = hex[c >> 4];
            out[j++] = hex[c & 15];
        }
    }

    out[j] = '\0';
    return out;
}

/* ------------------------------------------------------------------------- */
/* DPAPI credential storage                                                   */
/* ------------------------------------------------------------------------- */

static BOOL save_credentials(const Credentials *cred)
{
    wchar_t path[MAX_PATH];
    DATA_BLOB input = {0};
    DATA_BLOB encrypted = {0};
    HANDLE h = INVALID_HANDLE_VALUE;
    DWORD written = 0;
    BOOL ok = FALSE;

    if (!credentials_path(path, MAX_PATH))
        return FALSE;

    /*
     * File format:
     *   4 bytes magic: "CPM1"
     *   4 bytes username length
     *   4 bytes password length
     *   encrypted DPAPI blob
     *
     * DPAPI binds the encrypted data to this Windows user by default.
     */
    DWORD user_len = (DWORD)strlen(cred->username);
    DWORD pass_len = (DWORD)strlen(cred->password);

    size_t plain_len = 12 + user_len + pass_len;
    BYTE *plain = (BYTE *)calloc(1, plain_len);

    if (!plain)
        return FALSE;

    memcpy(plain, "CPM1", 4);
    memcpy(plain + 4, &user_len, 4);
    memcpy(plain + 8, &pass_len, 4);
    memcpy(plain + 12, cred->username, user_len);
    memcpy(plain + 12 + user_len, cred->password, pass_len);

    input.pbData = plain;
    input.cbData = (DWORD)plain_len;

    if (!CryptProtectData(
            &input,
            L"Campus Portal Monitor credentials",
            NULL,
            NULL,
            NULL,
            CRYPTPROTECT_UI_FORBIDDEN,
            &encrypted)) {
        free(plain);
        return FALSE;
    }

    h = CreateFileW(
        path,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_HIDDEN,
        NULL);

    if (h != INVALID_HANDLE_VALUE) {
        ok = WriteFile(h, encrypted.pbData, encrypted.cbData, &written, NULL) &&
             written == encrypted.cbData;
        CloseHandle(h);
    }

    SecureZeroMemory(plain, plain_len);
    free(plain);
    LocalFree(encrypted.pbData);

    return ok;
}

static BOOL load_credentials(Credentials *cred)
{
    wchar_t path[MAX_PATH];
    HANDLE h = INVALID_HANDLE_VALUE;
    DWORD size = 0;
    DWORD read = 0;
    BYTE *encrypted = NULL;
    DATA_BLOB input = {0};
    DATA_BLOB output = {0};
    BOOL ok = FALSE;

    memset(cred, 0, sizeof(*cred));

    if (!credentials_path(path, MAX_PATH))
        return FALSE;

    h = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_HIDDEN,
        NULL);

    if (h == INVALID_HANDLE_VALUE)
        return FALSE;

    size = GetFileSize(h, NULL);
    if (size == INVALID_FILE_SIZE || size < 16 || size > 1024 * 1024) {
        CloseHandle(h);
        return FALSE;
    }

    encrypted = (BYTE *)malloc(size);
    if (!encrypted) {
        CloseHandle(h);
        return FALSE;
    }

    if (!ReadFile(h, encrypted, size, &read, NULL) || read != size) {
        free(encrypted);
        CloseHandle(h);
        return FALSE;
    }
    CloseHandle(h);

    input.pbData = encrypted;
    input.cbData = size;

    if (!CryptUnprotectData(
            &input,
            NULL,
            NULL,
            NULL,
            NULL,
            CRYPTPROTECT_UI_FORBIDDEN,
            &output)) {
        free(encrypted);
        return FALSE;
    }

    if (output.cbData >= 12 &&
        memcmp(output.pbData, "CPM1", 4) == 0) {

        DWORD user_len = 0;
        DWORD pass_len = 0;

        memcpy(&user_len, output.pbData + 4, 4);
        memcpy(&pass_len, output.pbData + 8, 4);

        if (user_len < sizeof(cred->username) &&
            pass_len < sizeof(cred->password) &&
            12ULL + user_len + pass_len <= output.cbData) {

            memcpy(cred->username, output.pbData + 12, user_len);
            cred->username[user_len] = '\0';

            memcpy(
                cred->password,
                output.pbData + 12 + user_len,
                pass_len);

            cred->password[pass_len] = '\0';
            ok = TRUE;
        }
    }

    SecureZeroMemory(output.pbData, output.cbData);
    LocalFree(output.pbData);
    free(encrypted);

    return ok;
}

/* ------------------------------------------------------------------------- */
/* WinHTTP                                                                    */
/* ------------------------------------------------------------------------- */

static void free_http_result(HttpResult *r)
{
    if (r->body) {
        free(r->body);
        r->body = NULL;
    }
    r->body_len = 0;
}

static BOOL utf8_to_wide(const char *src, wchar_t *dst, int dst_count)
{
    int n = MultiByteToWideChar(
        CP_UTF8, 0, src, -1, dst, dst_count);
    return n > 0;
}

static BOOL wide_to_utf8(
    const wchar_t *src,
    char *dst,
    int dst_count)
{
    int n = WideCharToMultiByte(
        CP_UTF8, 0, src, -1, dst, dst_count, NULL, NULL);
    return n > 0;
}

static BOOL http_request(
    const wchar_t *host,
    INTERNET_PORT port,
    const wchar_t *path,
    const wchar_t *method,
    const char *post_data,
    const wchar_t *extra_headers,
    HttpResult *result)
{
    HINTERNET session = NULL;
    HINTERNET connect = NULL;
    HINTERNET request = NULL;
    DWORD flags = WINHTTP_FLAG_BYPASS_PROXY_CACHE;
    DWORD status = 0;
    DWORD status_size = sizeof(status);
    DWORD size = 0;
    DWORD total = 0;
    BOOL ok = FALSE;
    ULONGLONG start;

    memset(result, 0, sizeof(*result));

    session = WinHttpOpen(
        L"CampusPortalMonitor/1.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!session)
        goto cleanup;

    WinHttpSetTimeouts(
        session,
        HTTP_TIMEOUT_MS,
        HTTP_TIMEOUT_MS,
        HTTP_TIMEOUT_MS,
        HTTP_TIMEOUT_MS);

    connect = WinHttpConnect(session, host, port, 0);
    if (!connect)
        goto cleanup;

    /*
     * Redirects are deliberately disabled. This is important because the
     * known-good Bash implementation inspected the 30x Location header.
     */
    request = WinHttpOpenRequest(
        connect,
        method,
        path,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags);

    if (!request)
        goto cleanup;

    WinHttpSetOption(
        request,
        WINHTTP_OPTION_REDIRECT_POLICY,
        &(DWORD){ WINHTTP_OPTION_REDIRECT_POLICY_NEVER },
        sizeof(DWORD));

    start = GetTickCount64();

    if (!WinHttpSendRequest(
            request,
            extra_headers,
            extra_headers ? (DWORD)-1L : 0,
            (LPVOID)post_data,
            post_data ? (DWORD)strlen(post_data) : 0,
            post_data ? (DWORD)strlen(post_data) : 0,
            0))
        goto cleanup;

    if (!WinHttpReceiveResponse(request, NULL))
        goto cleanup;

    if (!WinHttpQueryHeaders(
            request,
            WINHTTP_QUERY_STATUS_CODE,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &status,
            &status_size,
            WINHTTP_NO_HEADER_INDEX))
        goto cleanup;

    result->status = status;
    result->elapsed_ms = (DWORD)(GetTickCount64() - start);

    /* Location header */
    {
        wchar_t location[2048];
        DWORD loc_size = sizeof(location);

        if (WinHttpQueryHeaders(
                request,
                WINHTTP_QUERY_LOCATION,
                WINHTTP_HEADER_NAME_BY_INDEX,
                location,
                &loc_size,
                WINHTTP_NO_HEADER_INDEX)) {

            wcsncpy_s(
                result->location,
                _countof(result->location),
                location,
                _TRUNCATE);
        }
    }

    /* Response body */
    do {
        size = 0;

        if (!WinHttpQueryDataAvailable(request, &size))
            goto cleanup;

        if (size == 0)
            break;

        if (total + size > 2 * 1024 * 1024)
            goto cleanup;

        char *new_body = (char *)realloc(result->body, total + size + 1);
        if (!new_body)
            goto cleanup;

        result->body = new_body;

        DWORD read_now = 0;
        if (!WinHttpReadData(
                request,
                result->body + total,
                size,
                &read_now))
            goto cleanup;

        total += read_now;
    } while (size > 0);

    if (result->body)
        result->body[total] = '\0';

    result->body_len = total;
    result->transport_ok = TRUE;
    ok = TRUE;

cleanup:
    if (request)
        WinHttpCloseHandle(request);
    if (connect)
        WinHttpCloseHandle(connect);
    if (session)
        WinHttpCloseHandle(session);

    return ok;
}

/* ------------------------------------------------------------------------- */
/* Portal protocol                                                            */
/* ------------------------------------------------------------------------- */

static BOOL location_is_portal(const wchar_t *location)
{
    if (!location || !*location)
        return FALSE;

    return wcsstr(location, L"192.168.2.1:8090") != NULL;
}

static MonitorState probe_internet(HttpResult *result)
{
    if (!http_request(
            PROBE_HOST,
            INTERNET_DEFAULT_HTTP_PORT,
            PROBE_PATH,
            L"GET",
            NULL,
            NULL,
            result)) {

        return STATE_OFFLINE;
    }

    if (result->status == 204)
        return STATE_ONLINE;

    if ((result->status == 301 ||
         result->status == 302 ||
         result->status == 303 ||
         result->status == 307 ||
         result->status == 308) &&
        location_is_portal(result->location)) {

        return STATE_CAPTIVE;
    }

    if (result->status == 200 && result->body) {
        if (strstr(result->body, "httpclient.html") ||
            strstr(result->body, "192.168.2.1:8090")) {
            return STATE_CAPTIVE;
        }
    }

    return STATE_OFFLINE;
}

static BOOL portal_reachable(void)
{
    HttpResult result;
    BOOL ok = http_request(
        PORTAL_HOST,
        PORTAL_PORT,
        L"/",
        L"GET",
        NULL,
        NULL,
        &result);

    free_http_result(&result);
    return ok && result.status != 0;
}

static BOOL login_portal(const Credentials *cred, HttpResult *result)
{
    char *user = url_encode(cred->username);
    char *pass = url_encode(cred->password);
    char post[2048];
    BOOL ok = FALSE;

    if (!user || !pass)
        goto cleanup;

    snprintf(
        post,
        sizeof(post),
        "mode=191&username=%s&password=%s&a=%llu&producttype=0",
        user,
        pass,
        (unsigned long long)GetTickCount64());

    if (!http_request(
            PORTAL_HOST,
            PORTAL_PORT,
            LOGIN_PATH,
            L"POST",
            post,
            L"Content-Type: application/x-www-form-urlencoded\r\n",
            result))
        goto cleanup;

    if (result->status == 200 &&
        result->body &&
        strstr(result->body, "<status>") &&
        strstr(result->body, "LIVE")) {
        ok = TRUE;
    }

cleanup:
    if (user) {
        SecureZeroMemory(user, strlen(user));
        free(user);
    }

    if (pass) {
        SecureZeroMemory(pass, strlen(pass));
        free(pass);
    }

    SecureZeroMemory(post, sizeof(post));
    return ok;
}

/* ------------------------------------------------------------------------- */
/* Network information                                                        */
/* ------------------------------------------------------------------------- */

static void show_network_info(void)
{
    ULONG size = 15000;
    IP_ADAPTER_ADDRESSES *addresses =
        (IP_ADAPTER_ADDRESSES *)malloc(size);

    if (!addresses)
        return;

    DWORD ret = GetAdaptersAddresses(
        AF_INET,
        GAA_FLAG_INCLUDE_PREFIX,
        NULL,
        addresses,
        &size);

    if (ret == ERROR_BUFFER_OVERFLOW) {
        free(addresses);
        addresses = (IP_ADAPTER_ADDRESSES *)malloc(size);
        if (!addresses)
            return;

        ret = GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_INCLUDE_PREFIX,
            NULL,
            addresses,
            &size);
    }

    if (ret == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES *a = addresses; a; a = a->Next) {
            if (a->OperStatus != IfOperStatusUp)
                continue;

            char name[IF_NAMESIZE] = {0};
            WideCharToMultiByte(
                CP_UTF8, 0,
                a->FriendlyName, -1,
                name, sizeof(name),
                NULL, NULL);

            printf("Interface: %s\n", name);

            if (a->FirstGatewayAddress) {
                SOCKADDR_IN *gw =
                    (SOCKADDR_IN *)a->FirstGatewayAddress->Address.lpSockaddr;

                char addr[INET_ADDRSTRLEN] = {0};
                InetNtopA(
                    AF_INET,
                    &gw->sin_addr,
                    addr,
                    sizeof(addr));

                printf("Gateway:   %s\n", addr);
            }

            for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress;
                 u;
                 u = u->Next) {

                SOCKADDR_IN *sa =
                    (SOCKADDR_IN *)u->Address.lpSockaddr;

                char addr[INET_ADDRSTRLEN] = {0};

                InetNtopA(
                    AF_INET,
                    &sa->sin_addr,
                    addr,
                    sizeof(addr));

                printf("IPv4:      %s\n", addr);
                break;
            }

            break;
        }
    }

    free(addresses);
}

/* ------------------------------------------------------------------------- */
/* Commands                                                                   */
/* ------------------------------------------------------------------------- */

static BOOL init_credentials(void)
{
    Credentials cred;

    memset(&cred, 0, sizeof(cred));

    printf("Campus Portal Monitor - Windows native setup\n");
    printf("Portal: http://192.168.2.1:8090 (fixed)\n");
    printf("Probe:  http://connectivitycheck.gstatic.com/generate_204 (fixed)\n\n");

    printf("Portal username: ");
    if (!fgets(cred.username, sizeof(cred.username), stdin))
        return FALSE;

    printf("Portal password: ");
    if (!fgets(cred.password, sizeof(cred.password), stdin))
        return FALSE;

    cred.username[strcspn(cred.username, "\r\n")] = '\0';
    cred.password[strcspn(cred.password, "\r\n")] = '\0';

    if (!cred.username[0] || !cred.password[0]) {
        printf("Username and password cannot be empty.\n");
        SecureZeroMemory(&cred, sizeof(cred));
        return FALSE;
    }

    if (!save_credentials(&cred)) {
        printf("Failed to save encrypted credentials. Win32 error: %lu\n",
               GetLastError());
        SecureZeroMemory(&cred, sizeof(cred));
        return FALSE;
    }

    wchar_t wpath[MAX_PATH];
    if (credentials_path(wpath, MAX_PATH)) {
        wprintf(L"Encrypted credentials saved to: %ls\n", wpath);
    }

    SecureZeroMemory(&cred, sizeof(cred));
    return TRUE;
}

static void print_probe(const HttpResult *r, MonitorState state)
{
    printf("Connectivity probe (redirects disabled):\n");
    printf("  State:    ");

    switch (state) {
    case STATE_ONLINE:       printf("ONLINE\n"); break;
    case STATE_CAPTIVE:      printf("CAPTIVE\n"); break;
    case STATE_OFFLINE:      printf("OFFLINE\n"); break;
    default:                 printf("UNKNOWN\n"); break;
    }

    printf("  HTTP:     %lu\n", r->status);

    if (r->location[0]) {
        wprintf(L"  Location: %ls\n", r->location);
    } else {
        printf("  Location: -\n");
    }

    printf("  RTT:      %lu ms\n", r->elapsed_ms);

    if (r->body && r->body_len) {
        printf("  Body:     %lu bytes\n", r->body_len);
    }
}

static int diagnose(void)
{
    Credentials cred;
    HttpResult probe;
    HttpResult login_result;
    HttpResult verify;
    MonitorState state;

    memset(&cred, 0, sizeof(cred));

    if (!load_credentials(&cred)) {
        printf("No usable credentials found.\n");
        printf("Run: CampusPortalMonitor.exe --init\n");
        return 1;
    }

    printf("Campus Portal Monitor - Windows diagnostic\n");
    printf("Portal: http://192.168.2.1:8090\n");
    printf("Probe:  http://connectivitycheck.gstatic.com/generate_204\n\n");

    show_network_info();
    printf("\n");

    state = probe_internet(&probe);
    print_probe(&probe, state);

    printf("\nInitial portal GET:\n");
    printf("  Reachable: %s\n", portal_reachable() ? "yes" : "no");

    if (state == STATE_ONLINE) {
        printf("\nAlready ONLINE. Login is not required for this pass.\n");
        free_http_result(&probe);
        SecureZeroMemory(&cred, sizeof(cred));
        return 0;
    }

    if (!portal_reachable()) {
        printf("Portal is unreachable; cannot authenticate.\n");
        free_http_result(&probe);
        SecureZeroMemory(&cred, sizeof(cred));
        return 1;
    }

    printf("\nAttempting portal login...\n");

    if (login_portal(&cred, &login_result)) {
        printf("SUCCESS: Portal reports LIVE\n");

        Sleep(POST_LOGIN_WAIT_MS);

        state = probe_internet(&verify);
        printf("Post-login probe: ");
        switch (state) {
        case STATE_ONLINE:  printf("ONLINE"); break;
        case STATE_CAPTIVE: printf("CAPTIVE"); break;
        default:            printf("OFFLINE"); break;
        }
        printf(" / HTTP %lu\n", verify.status);

        free_http_result(&verify);
    } else {
        printf("FAILED: Portal did not report LIVE\n");

        if (login_result.body && login_result.body_len) {
            printf("Response: %.*s\n",
                   (int)(login_result.body_len > 1000 ? 1000 : login_result.body_len),
                   login_result.body);
        }
    }

    free_http_result(&probe);
    free_http_result(&login_result);
    SecureZeroMemory(&cred, sizeof(cred));

    return 0;
}

/* ------------------------------------------------------------------------- */
/* Monitor                                                                    */
/* ------------------------------------------------------------------------- */

static BOOL authenticate_if_needed(
    const Credentials *cred,
    BOOL force)
{
    HttpResult probe;
    HttpResult login_result;
    HttpResult verify;
    MonitorState state;

    state = probe_internet(&probe);

    if (state == STATE_ONLINE && !force) {
        printf("ONLINE\n");
        free_http_result(&probe);
        return TRUE;
    }

    if (state == STATE_ONLINE && force)
        log_line("Renewing portal session...");

    else if (state == STATE_CAPTIVE)
        log_line("Captive portal detected.");

    else if (state == STATE_OFFLINE)
        log_line("Internet unavailable; checking campus portal.");

    free_http_result(&probe);

    if (!portal_reachable()) {
        log_line("Portal gateway unreachable.");
        return FALSE;
    }

    if (!login_portal(cred, &login_result)) {
        log_line("Portal login failed.");
        free_http_result(&login_result);
        return FALSE;
    }

    log_line("Portal login successful.");
    free_http_result(&login_result);

    Sleep(POST_LOGIN_WAIT_MS);

    state = probe_internet(&verify);

    if (state == STATE_ONLINE) {
        log_line("Internet verification passed.");
        free_http_result(&verify);
        return TRUE;
    }

    log_line("Post-login verification failed.");
    free_http_result(&verify);
    return FALSE;
}

static int monitor(void)
{
    Credentials cred;
    ULONGLONG next_renewal = GetTickCount64() + RENEW_INTERVAL_MS;

    memset(&cred, 0, sizeof(cred));

    if (!load_credentials(&cred)) {
        printf("No credentials found.\n");
        printf("Run: CampusPortalMonitor.exe --init\n");
        return 1;
    }

    printf("Campus Portal Monitor - Windows native\n");
    printf("Automatic login: enabled\n");
    printf("Automatic renewal: every 2 hours\n");
    printf("Press Ctrl+C to stop.\n\n");

    for (;;) {
        BOOL force = GetTickCount64() >= next_renewal;

        authenticate_if_needed(&cred, force);

        if (force)
            next_renewal = GetTickCount64() + RENEW_INTERVAL_MS;

        Sleep(CHECK_INTERVAL_MS);
    }

    /* unreachable */
    SecureZeroMemory(&cred, sizeof(cred));
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Entry point                                                                */
/* ------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "--init") == 0)
        return init_credentials() ? 0 : 1;

    if (argc >= 2 && strcmp(argv[1], "--diagnose") == 0)
        return diagnose();

    return monitor();
}
