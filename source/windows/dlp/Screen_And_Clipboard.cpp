#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

struct BlacklistEntry {
    std::string originalPath;
    std::string fullName;
    std::string baseName;
};

const std::string LOG_FILE = "C:\\Users\\Public\\yara_debug.log";
const std::string BLACKLIST_FILE = "C:\\Users\\Public\\blacklist.txt";
const std::string TEMP_CLIP_FILE = "C:\\Users\\Public\\wazuh_clip_temp.txt";
const std::string BUILD_TAG = "guard-2026-11-22-clipfix1";
const std::string YARA_EXE = "C:\\Program Files (x86)\\ossec-agent\\dependencies\\yara\\yara64.exe";
const std::string YARA_RULE = "C:\\Program Files (x86)\\ossec-agent\\shared\\sensitive_data.yar";

const int MAX_BLOCKS_ALLOWED = 5;
const int MAX_COPY_ALLOWED = 10;

const std::vector<std::string> TRUSTED_APPS = {
    "winword.exe",
    "excel.exe",
    "notepad.exe",
    "explorer.exe",
    "screenguard.exe",
    "cmd.exe",
    "powershell.exe"
};

const std::vector<std::wstring> BLACKLIST_PROCESSES = {
    L"SnippingTool.exe",
    L"ScreenClippingHost.exe",
    L"ScreenSketch.exe"
};

std::recursive_mutex g_mutex;
std::vector<BlacklistEntry> g_blacklist;
std::unordered_map<DWORD, std::string> g_pidCommandCache;

HHOOK g_keyboardHook = nullptr;
HHOOK g_mouseHook = nullptr;
HWND g_hiddenWindow = nullptr;

bool g_sensitiveOnScreen = false;
bool g_sensitiveLogged = false;
bool g_shieldDisabled = false;
bool g_clipboardToxic = false;
bool g_clipboardOverride = false;

std::string g_matchedPath;
std::string g_matchedProcess;
std::string g_toxicSourceApp;
std::string g_toxicSourceTitle;
std::string g_toxicReason = "YARA_Sensitive_Data";
std::string g_lastWindowDebugKey;
std::set<std::string> g_loggedWindowTitles;

int g_blockedScreenshots = 0;
int g_toxicCopies = 0;

std::chrono::system_clock::time_point g_firstBlockTime;
std::chrono::system_clock::time_point g_disableStart;
std::chrono::system_clock::time_point g_firstToxicCopy;
std::chrono::system_clock::time_point g_overrideStart;

std::string toLower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

std::string timestamp() {
    auto now = std::time(nullptr);
    auto local = *std::localtime(&now);

    std::ostringstream result;
    result << std::put_time(&local, "%Y-%m-%d %H:%M:%S");
    return result.str();
}

void writeLog(const std::string& message) {
    std::ofstream file(LOG_FILE, std::ios::app);
    if (file) {
        file << timestamp() << " " << message << "\n";
    }
}

void logEnvironment() {
    DWORD sessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);

    char winstaName[256] = {};
    char desktopName[256] = {};
    GetUserObjectInformationA(GetProcessWindowStation(), UOI_NAME,
                              winstaName, sizeof(winstaName), nullptr);
    GetUserObjectInformationA(GetThreadDesktop(GetCurrentThreadId()), UOI_NAME,
                              desktopName, sizeof(desktopName), nullptr);

    writeLog("DEBUG: build=" + BUILD_TAG +
             " session=" + std::to_string(sessionId) +
             " winsta=" + winstaName + " desktop=" + desktopName);
}

void logYaraVersion() {
    std::string command = "\"\"" + YARA_EXE + "\" --version 2>&1\"";
    FILE* pipe = _popen(command.c_str(), "r");
    std::string output;
    char buffer[128];
    while (pipe && fgets(buffer, sizeof buffer, pipe)) {
        output += buffer;
    }
    if (pipe) {
        _pclose(pipe);
    }

    std::replace(output.begin(), output.end(), '\r', ' ');
    std::replace(output.begin(), output.end(), '\n', ' ');
    writeLog("DEBUG: yara version output=[" + output + "]");
}

std::string toUtf8(const std::wstring& text) {
    if (text.empty()) {
        return {};
    }

    int size = WideCharToMultiByte(CP_UTF8, 0, text.data(),
                                   static_cast<int>(text.size()),
                                   nullptr, 0, nullptr, nullptr);
    std::string result(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                        result.data(), size, nullptr, nullptr);
    return result;
}

bool containsWord(const std::string& text, const std::string& word) {
    size_t position = text.find(word);
    while (position != std::string::npos) {
        bool leftOk = position == 0 ||
                      !std::isalnum(static_cast<unsigned char>(text[position - 1]));
        bool rightOk = position + word.size() == text.size() ||
                       !std::isalnum(static_cast<unsigned char>(text[position + word.size()]));
        if (leftOk && rightOk) {
            return true;
        }
        position = text.find(word, position + 1);
    }
    return false;
}

std::string processName(HWND window) {
    DWORD pid = 0;
    GetWindowThreadProcessId(window, &pid);

    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) {
        return "unknownapp.exe";
    }

    char path[MAX_PATH];
    DWORD size = MAX_PATH;
    std::string name = "unknownapp.exe";

    if (QueryFullProcessImageNameA(process, 0, path, &size)) {
        name = path;
        size_t slash = name.find_last_of("\\/");
        if (slash != std::string::npos) {
            name = name.substr(slash + 1);
        }
        name = toLower(name);
    }

    CloseHandle(process);
    return name;
}

std::string cleanTitle(std::string title) {
    const char* suffixes[] = {
        " - Microsoft",
        " - Google Chrome",
        " - Mozilla Firefox",
        " - Notepad",
        " - Word"
    };

    for (const char* suffix : suffixes) {
        size_t position = title.find(suffix);
        if (position != std::string::npos) {
            title = title.substr(0, position);
        }
    }
    return title;
}

std::string commandLineFromPid(DWORD pid) {
    std::string command = "wmic process where processid=" + std::to_string(pid) +
                          " get commandline";
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        return {};
    }

    char buffer[512];
    std::string output;
    while (fgets(buffer, sizeof buffer, pipe)) {
        output += buffer;
    }
    _pclose(pipe);

    output.erase(std::remove(output.begin(), output.end(), '\r'), output.end());
    output.erase(std::remove(output.begin(), output.end(), '\n'), output.end());

    if (toLower(output).find(".exe") == std::string::npos) {
        return {};
    }

    writeLog("DEBUG: wmic raw=[" + output + "]");
    return output;
}

void loadBlacklist() {
    std::lock_guard<std::recursive_mutex> lock(g_mutex);
    g_blacklist.clear();

    std::ifstream file(BLACKLIST_FILE);
    std::string line;
    while (std::getline(file, line)) {
        if (line.size() >= 3 &&
            static_cast<unsigned char>(line[0]) == 0xEF &&
            static_cast<unsigned char>(line[1]) == 0xBB &&
            static_cast<unsigned char>(line[2]) == 0xBF) {
            line.erase(0, 3);
        }

        size_t first = line.find_first_not_of(" \t\r");
        size_t last = line.find_last_not_of(" \t\r");
        line = first == std::string::npos
                   ? std::string{}
                   : line.substr(first, last - first + 1);

        if (line.empty()) {
            continue;
        }

        BlacklistEntry entry;
        entry.originalPath = line;

        size_t slash = line.find_last_of("\\/");
        entry.fullName = toLower(slash == std::string::npos ? line : line.substr(slash + 1));

        size_t dot = entry.fullName.find_last_of('.');
        entry.baseName = dot == std::string::npos
                             ? entry.fullName
                             : entry.fullName.substr(0, dot);

        g_blacklist.push_back(entry);
    }
}

DWORD WINAPI showScreenshotWarning(LPVOID) {
    MessageBoxA(nullptr,
        "Screenshot attempt blocked!\nSensitive data is currently displayed on your screen.",
        "Wazuh DLP - Security Alert",
        MB_ICONWARNING | MB_OK | MB_TOPMOST);
    return 0;
}

DWORD WINAPI showOverrideNotice(LPVOID) {
    MessageBoxA(nullptr,
        "Emergency Override Activated!\nScreenshot protection is disabled for 60 seconds.",
        "Wazuh DLP - Emergency Override",
        MB_ICONINFORMATION | MB_OK | MB_TOPMOST);
    return 0;
}

DWORD WINAPI showClipboardWarning(LPVOID) {
    MessageBoxA(nullptr,
        "Clipboard Blocked!\nSensitive data cannot be pasted into an untrusted application.",
        "Wazuh DLP - Zero Trust Protection",
        MB_ICONERROR | MB_OK | MB_TOPMOST);
    return 0;
}

std::string readClipboardText() {
    if (!OpenClipboard(nullptr)) {
        return {};
    }

    std::string text;
    HANDLE handle = GetClipboardData(CF_UNICODETEXT);
    if (handle) {
        wchar_t* data = static_cast<wchar_t*>(GlobalLock(handle));
        if (data) {
            text = toUtf8(data);
            GlobalUnlock(handle);
        }
    }
    CloseClipboard();
    return text;
}

bool clipboardHasBlacklistedFiles() {
    if (!OpenClipboard(nullptr)) {
        return false;
    }

    bool found = false;
    HANDLE handle = GetClipboardData(CF_HDROP);
    if (handle) {
        HDROP drop = static_cast<HDROP>(GlobalLock(handle));
        UINT fileCount = drop ? DragQueryFileA(drop, 0xFFFFFFFF, nullptr, 0) : 0;
        char path[MAX_PATH];

        for (UINT i = 0; drop && i < fileCount; ++i) {
            if (!DragQueryFileA(drop, i, path, MAX_PATH)) {
                continue;
            }
            for (const auto& entry : g_blacklist) {
                if (toLower(path) == toLower(entry.originalPath)) {
                    g_toxicSourceApp = "Windows Explorer (File Copy)";
                    g_toxicSourceTitle = path;
                    found = true;
                }
            }
        }

        if (drop) {
            GlobalUnlock(handle);
        }
    }
    CloseClipboard();
    return found;
}

std::string tempClipFile() {
    char tempPath[MAX_PATH] = {};
    DWORD length = GetTempPathA(MAX_PATH, tempPath);
    if (length == 0 || length >= MAX_PATH) {
        return TEMP_CLIP_FILE;
    }

    return std::string(tempPath) + "wazuh_clip_" +
           std::to_string(GetCurrentProcessId()) + "_" +
           std::to_string(GetTickCount64()) + ".txt";
}

bool textMatchesYara(const std::string& text) {
    const std::string tempFile = tempClipFile();

    {
        std::ofstream file(tempFile, std::ios::binary);
        if (!file) {
            writeLog("ERROR: cannot create temp file [" + tempFile + "]");
            return false;
        }
        file << text;
        if (!file) {
            writeLog("ERROR: cannot write temp file [" + tempFile + "]");
            return false;
        }
        file.close();
        if (!file) {
            writeLog("ERROR: cannot close temp file [" + tempFile + "]");
            return false;
        }
    }

    std::string command = "\"\"" + YARA_EXE + "\" -w \"" + YARA_RULE + "\" \"" +
                          tempFile + "\" 2>&1\"";
    writeLog("DEBUG: yara command=" + command);

    std::string output;
    for (int attempt = 1; attempt <= 10; ++attempt) {
        HANDLE readCheck = CreateFileA(
            tempFile.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (readCheck == INVALID_HANDLE_VALUE) {
            writeLog("ERROR: temp file read check failed. attempt=" +
                     std::to_string(attempt) + " error=" +
                     std::to_string(GetLastError()));
        } else {
            CloseHandle(readCheck);
        }

        output.clear();
        FILE* pipe = _popen(command.c_str(), "r");
        char buffer[128];
        while (pipe && fgets(buffer, sizeof buffer, pipe)) {
            output += buffer;
        }
        int exitCode = pipe ? _pclose(pipe) : -1;

        std::string cleanOutput = output;
        std::replace(cleanOutput.begin(), cleanOutput.end(), '\r', ' ');
        std::replace(cleanOutput.begin(), cleanOutput.end(), '\n', ' ');
        writeLog("DEBUG: yara attempt=" + std::to_string(attempt) +
                 " exit=" + std::to_string(exitCode) +
                 " output=[" + cleanOutput + "]");

        if (output.find("Access is denied") == std::string::npos) {
            break;
        }

        Sleep(100);
    }

    if (!DeleteFileA(tempFile.c_str())) {
        writeLog("DEBUG: cannot delete temp file [" + tempFile + "] error=" +
                 std::to_string(GetLastError()));
    }

    return output.find("Detect_Sensitive_Info") != std::string::npos;
}

void blockClipboard(const std::string& app, const std::string& title) {
    if (OpenClipboard(nullptr)) {
        EmptyClipboard();
        CloseClipboard();
    }

    writeLog("wazuh-dlp: alert - Clipboard Blocked | Source: [" + g_toxicSourceApp +
             " - " + g_toxicSourceTitle + "] | Destination: [" + app + " - " + title +
             "] | Rule: [" + g_toxicReason + "]");

    CreateThread(nullptr, 0, showClipboardWarning, nullptr, 0, nullptr);
}

bool windowMatchesBlacklist(HWND window, std::string* matchedPath) {
    if (!window) {
        return false;
    }

    std::string process = processName(window);
    if (process == "explorer.exe" || process == "cmd.exe" ||
        process == "conhost.exe" || process == "screen_and_clipboard.exe") {
        return false;
    }

    char titleBuffer[512] = {};
    GetWindowTextA(window, titleBuffer, sizeof titleBuffer);
    std::string title = toLower(titleBuffer);

    for (const auto& entry : g_blacklist) {
        if (containsWord(title, entry.fullName) ||
            containsWord(title, entry.baseName)) {
            if (matchedPath) {
                *matchedPath = entry.originalPath;
            }
            return true;
        }
    }

    return false;
}

LRESULT CALLBACK hiddenWindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    std::lock_guard<std::recursive_mutex> lock(g_mutex);

    if (message == WM_CLIPBOARDUPDATE && !g_clipboardOverride) {
        writeLog("DEBUG: clipboard update");

        HWND foreground = GetForegroundWindow();
        std::string sourceApp = processName(foreground);
        char sourceTitleBuffer[512] = {};
        GetWindowTextA(foreground, sourceTitleBuffer, sizeof sourceTitleBuffer);
        std::string sourceTitle = cleanTitle(sourceTitleBuffer);

        std::string matchedPath;
        bool sourceSensitive = windowMatchesBlacklist(foreground, &matchedPath);

        if (clipboardHasBlacklistedFiles()) {
            g_clipboardToxic = true;
            g_toxicSourceApp = "Windows Explorer (File Copy)";
            g_toxicSourceTitle = matchedPath;
            g_toxicReason = "Blacklisted_File_Copy";
            g_toxicCopies = 0;
            writeLog("DEBUG: clipboard has blacklisted file");
        } else {
            std::string text = readClipboardText();

            if (!text.empty()) {
                bool toxic = sourceSensitive;
                if (!toxic) {
                    toxic = textMatchesYara(text);
                }

                writeLog(std::string("DEBUG: clipboard text length=") +
                         std::to_string(text.size()) +
                         " sourceSensitive=" + (sourceSensitive ? "true" : "false") +
                         " toxic=" + (toxic ? "true" : "false") +
                         " source=[" + sourceApp + " - " + sourceTitle + "]");

                if (toxic) {
                    auto now = std::chrono::system_clock::now();
                    if (g_toxicCopies == 0) {
                        g_firstToxicCopy = now;
                    }

                    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
                        now - g_firstToxicCopy).count();
                    if (seconds > 30) {
                        g_firstToxicCopy = now;
                        g_toxicCopies = 0;
                    }
                    g_toxicCopies++;

                    if (g_toxicCopies >= MAX_COPY_ALLOWED) {
                        g_clipboardOverride = true;
                        g_overrideStart = now;
                        g_toxicCopies = 0;
                        writeLog("wazuh-dlp: alert - Secret clipboard override activated. "
                                 "Paste allowed to any app.");
                    } else {
                        g_clipboardToxic = true;
                        g_toxicSourceApp = sourceApp;
                        g_toxicSourceTitle = sourceTitle;
                        g_toxicReason = sourceSensitive
                                            ? "Blacklisted_Source_Window"
                                            : "YARA_Sensitive_Data";
                    }
                } else {
                    g_clipboardToxic = false;
                    g_toxicCopies = 0;
                }
            } else {
                g_clipboardToxic = false;
                writeLog("DEBUG: clipboard text empty");
            }
        }
    }

    return DefWindowProc(hwnd, message, wParam, lParam);
}

bool isTrustedApp(const std::string& process) {
    for (const auto& app : TRUSTED_APPS) {
        if (process == app) {
            return true;
        }
    }
    return false;
}

LRESULT CALLBACK keyboardHookProc(int code, WPARAM wParam, LPARAM lParam) {
    std::lock_guard<std::recursive_mutex> lock(g_mutex);

    if (code >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        auto* key = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);

        bool isPrintScreen = key->vkCode == VK_SNAPSHOT;
        bool isSnippingShortcut =
            key->vkCode == 'S' &&
            ((GetAsyncKeyState(VK_LWIN) & 0x8000) != 0 ||
             (GetAsyncKeyState(VK_RWIN) & 0x8000) != 0) &&
            (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;

        if ((isPrintScreen || isSnippingShortcut) &&
            g_sensitiveOnScreen && !g_shieldDisabled) {
            auto now = std::chrono::system_clock::now();
            if (g_blockedScreenshots == 0) {
                g_firstBlockTime = now;
            }

            auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
                now - g_firstBlockTime).count();
            if (seconds > 20) {
                g_firstBlockTime = now;
                g_blockedScreenshots = 0;
            }
            g_blockedScreenshots++;

            if (g_blockedScreenshots >= MAX_BLOCKS_ALLOWED) {
                g_shieldDisabled = true;
                g_disableStart = now;
                g_blockedScreenshots = 0;
                writeLog("wazuh-dlp: alert - Emergency override activated. Target Path: [" +
                         g_matchedPath + "] | App: [" + g_matchedProcess + "]");
                CreateThread(nullptr, 0, showOverrideNotice, nullptr, 0, nullptr);
                return CallNextHookEx(g_keyboardHook, code, wParam, lParam);
            }

            writeLog("wazuh-dlp: alert - Screenshot blocked. Source Path: [" + g_matchedPath +
                     "] | App: [" + g_matchedProcess + "]");
            CreateThread(nullptr, 0, showScreenshotWarning, nullptr, 0, nullptr);
            return 1;
        }

        bool isPaste = (key->vkCode == 'V' && (GetAsyncKeyState(VK_CONTROL) & 0x8000)) ||
                       (key->vkCode == VK_INSERT && (GetAsyncKeyState(VK_SHIFT) & 0x8000));

        if (isPaste && g_clipboardToxic && !g_clipboardOverride) {
            HWND foreground = GetForegroundWindow();
            std::string process = processName(foreground);

            if (!isTrustedApp(process)) {
                char titleBuffer[512];
                GetWindowTextA(foreground, titleBuffer, sizeof titleBuffer);
                std::string title = cleanTitle(titleBuffer);
                writeLog("DEBUG: paste blocked to app=[" + process +
                         "] title=[" + title + "]");
                blockClipboard(process, title);
                g_clipboardToxic = false;
                return 1;
            }

            writeLog("DEBUG: paste allowed to trusted app=[" + process + "]");
        }
    }

    return CallNextHookEx(g_keyboardHook, code, wParam, lParam);
}

LRESULT CALLBACK mouseHookProc(int code, WPARAM wParam, LPARAM lParam) {
    std::lock_guard<std::recursive_mutex> lock(g_mutex);

    if (code >= 0 && (wParam == WM_RBUTTONDOWN || wParam == WM_RBUTTONUP) &&
        g_clipboardToxic && !g_clipboardOverride) {
        HWND foreground = GetForegroundWindow();
        std::string process = processName(foreground);

        if (!isTrustedApp(process)) {
            char title[512];
            GetWindowTextA(foreground, title, sizeof title);
            blockClipboard(process, cleanTitle(title));
            g_clipboardToxic = false;
        }
    }

    return CallNextHookEx(g_mouseHook, code, wParam, lParam);
}

void killProcessByName(const std::wstring& name) {
    if (g_shieldDisabled) {
        return;
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W entry{sizeof entry};

    for (BOOL ok = Process32FirstW(snapshot, &entry); ok; ok = Process32NextW(snapshot, &entry)) {
        if (name == entry.szExeFile) {
            HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
            if (process) {
                TerminateProcess(process, 9);
                CloseHandle(process);
                writeLog("wazuh-dlp: alert - Screen clipping tool (" + toUtf8(name) +
                         ") killed. Protecting Source Path: [" + g_matchedPath + "]");
            }
        }
    }
    CloseHandle(snapshot);
}

BOOL CALLBACK findSensitiveWindow(HWND window, LPARAM lParam) {
    bool* found = reinterpret_cast<bool*>(lParam);

    if (!IsWindowVisible(window) || IsIconic(window)) {
        return TRUE;
    }

    DWORD pid = 0;
    GetWindowThreadProcessId(window, &pid);

    std::string process = processName(window);
    if (process == "explorer.exe" || process == "cmd.exe" || process == "conhost.exe") {
        return TRUE;
    }

    char titleBuffer[512];
    GetWindowTextA(window, titleBuffer, sizeof titleBuffer);
    std::string title = toLower(titleBuffer);

    if (!title.empty()) {
        std::string windowKey = std::to_string(pid) + "|" + title;
        if (g_loggedWindowTitles.insert(windowKey).second) {
            writeLog("DEBUG: window title=[" + title + "] app=[" + process + "]");
        }
    }

    for (const auto& entry : g_blacklist) {
        bool match = containsWord(title, entry.fullName) ||
                     containsWord(title, entry.baseName);

        if (match) {
            auto cached = g_pidCommandCache.find(pid);
            std::string commandLine = cached != g_pidCommandCache.end()
                                          ? cached->second
                                          : commandLineFromPid(pid);
            if (!commandLine.empty()) {
                g_pidCommandCache[pid] = commandLine;
            }

            bool pathFound =
                !commandLine.empty() &&
                toLower(commandLine).find(toLower(entry.originalPath)) !=
                    std::string::npos;

            std::string debugKey =
                std::to_string(pid) + "|" + title + "|" + entry.originalPath;
            if (debugKey != g_lastWindowDebugKey) {
                writeLog("DEBUG: title match title=[" + title + "] app=[" + process +
                         "] pathFound=[" + (pathFound ? "true" : "false") +
                         "] expected=[" + entry.originalPath + "]");
                g_lastWindowDebugKey = debugKey;
            }
        }

        if (match) {
            *found = true;
            g_matchedPath = entry.originalPath;
            g_matchedProcess = process;
            return FALSE;
        }
    }

    return TRUE;
}

DWORD WINAPI monitorLoop(LPVOID) {
    int reloadCounter = 0;

    while (true) {
        {
            std::lock_guard<std::recursive_mutex> lock(g_mutex);

            if (++reloadCounter >= 10) {
                loadBlacklist();
                reloadCounter = 0;
            }

            if (g_shieldDisabled &&
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now() - g_disableStart).count() >= 60) {
                g_shieldDisabled = false;
            }

            if (g_clipboardOverride &&
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now() - g_overrideStart).count() >= 60) {
                g_clipboardOverride = false;
                g_clipboardToxic = false;
                g_toxicCopies = 0;
            }

            bool found = false;
            EnumWindows(findSensitiveWindow, reinterpret_cast<LPARAM>(&found));
            g_sensitiveOnScreen = found;

            if (found != g_sensitiveLogged) {
                writeLog(std::string("DEBUG: sensitiveOnScreen=") +
                         (found ? "true" : "false") + " path=[" + g_matchedPath +
                         "] app=[" + g_matchedProcess + "]");
                g_sensitiveLogged = found;
            }

            if (found && !g_shieldDisabled) {
                for (const auto& blacklistedProcess : BLACKLIST_PROCESSES) {
                    killProcessByName(blacklistedProcess);
                }
            }
        }

        Sleep(500);
    }

    return 0;
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "-hide") {
            ShowWindow(GetConsoleWindow(), SW_HIDE);
        }
    }

    loadBlacklist();
    writeLog("INFO: Endpoint Guardian Daemon started (Zero-Trust Mode).");
    writeLog("INFO: Blacklist entries: " + std::to_string(g_blacklist.size()));
    logEnvironment();
    logYaraVersion();

    CreateThread(nullptr, 0, monitorLoop, nullptr, 0, nullptr);

    g_keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, keyboardHookProc, nullptr, 0);
    g_mouseHook = SetWindowsHookEx(WH_MOUSE_LL, mouseHookProc, nullptr, 0);
    if (!g_keyboardHook || !g_mouseHook) {
        writeLog("ERROR: Input hook install failed. keyboard=" +
                 std::to_string(g_keyboardHook != nullptr) +
                 " mouse=" + std::to_string(g_mouseHook != nullptr) +
                 " error=" + std::to_string(GetLastError()));
    }

    WNDCLASSA windowClass{};
    windowClass.lpfnWndProc = hiddenWindowProc;
    windowClass.hInstance = GetModuleHandleA(nullptr);
    windowClass.lpszClassName = "WazuhDLPHiddenWindow";
    RegisterClassA(&windowClass);

    g_hiddenWindow = CreateWindowExA(0, windowClass.lpszClassName, "Hidden", 0,
                                     0, 0, 0, 0, HWND_MESSAGE, nullptr,
                                     windowClass.hInstance, nullptr);
    if (!g_hiddenWindow) {
        writeLog("ERROR: Hidden window creation failed. error=" +
                 std::to_string(GetLastError()));
    } else if (!AddClipboardFormatListener(g_hiddenWindow)) {
        writeLog("ERROR: AddClipboardFormatListener failed. error=" +
                 std::to_string(GetLastError()));
    }

    MSG message;
    while (GetMessage(&message, nullptr, 0, 0)) {
        TranslateMessage(&message);
        DispatchMessage(&message);
    }

    RemoveClipboardFormatListener(g_hiddenWindow);
    UnhookWindowsHookEx(g_keyboardHook);
    UnhookWindowsHookEx(g_mouseHook);
    return 0;
}
