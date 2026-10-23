#include "gui/Settings.h"

#include <shlobj.h>
#include <string>
#include <vector>

#include "common/Util.h"

#pragma comment(lib, "advapi32.lib")

namespace {

const wchar_t kSettingsKey[] = L"Software\\HashCalc";
const wchar_t kVerb[] = L"HashCalc";

struct ShellEntry
{
    const wchar_t* classKey;   // under HKCU\Software\Classes
    const wchar_t* text;       // menu text
    const wchar_t* args;       // command line arguments after the exe path
};

const ShellEntry kShellEntries[] = {
    { L"*",                     L"Calculate hash with HashCalc", L"\"%1\"" },
    { L"Directory",             L"Hash folder with HashCalc",    L"/folder \"%1\"" },
    { L"Directory\\Background", L"Hash this folder with HashCalc", L"/folder \"%V\"" },
};

std::wstring VerbKey(const ShellEntry& entry)
{
    return std::wstring(L"Software\\Classes\\") + entry.classKey + L"\\shell\\" + kVerb;
}

std::wstring CommandFor(const ShellEntry& entry)
{
    return L"\"" + ExePath() + L"\" " + entry.args;
}

DWORD ReadDword(HKEY key, const wchar_t* name, DWORD fallback)
{
    DWORD value = 0, size = sizeof(value);
    return RegGetValueW(key, nullptr, name, RRF_RT_REG_DWORD, nullptr, &value, &size) == ERROR_SUCCESS
        ? value : fallback;
}

bool SetString(HKEY root, const std::wstring& subKey, const wchar_t* name, const std::wstring& value)
{
    return RegSetKeyValueW(root, subKey.c_str(), name, REG_SZ, value.c_str(),
        static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
}

std::wstring ReadString(HKEY key, const wchar_t* name)
{
    wchar_t value[2048];
    DWORD size = sizeof(value);
    return RegGetValueW(key, nullptr, name, RRF_RT_REG_SZ, nullptr, value, &size) == ERROR_SUCCESS
        ? value : L"";
}

// --- User PATH -------------------------------------------------------------
const wchar_t kEnvironmentKey[] = L"Environment";

// For comparing PATH entries: expand %VARS%, drop quotes, spaces and a
// trailing backslash, ignore case.
std::wstring NormalizeFolder(std::wstring folder)
{
    wchar_t expanded[4096];
    DWORD n = ExpandEnvironmentStringsW(folder.c_str(), expanded, ARRAYSIZE(expanded));
    if (n > 0 && n <= ARRAYSIZE(expanded))
        folder = expanded;
    size_t first = folder.find_first_not_of(L" \t\"");
    size_t last = folder.find_last_not_of(L" \t\"");
    folder = first == std::wstring::npos ? L"" : folder.substr(first, last - first + 1);
    while (folder.size() > 3 && (folder.back() == L'\\' || folder.back() == L'/'))
        folder.pop_back();
    CharLowerBuffW(folder.data(), static_cast<DWORD>(folder.size()));
    return folder;
}

// Reads HKCU\Environment\Path without expanding it. A missing value is empty.
bool ReadUserPath(std::wstring& value, DWORD& type)
{
    value.clear();
    type = REG_EXPAND_SZ;
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kEnvironmentKey, 0, KEY_READ, &key) != ERROR_SUCCESS)
        return true;
    DWORD size = 0;
    LSTATUS status = RegQueryValueExW(key, L"Path", nullptr, &type, nullptr, &size);
    if (status == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ))
    {
        std::wstring buffer(size / sizeof(wchar_t) + 1, L'\0');
        status = RegQueryValueExW(key, L"Path", nullptr, &type, reinterpret_cast<BYTE*>(buffer.data()), &size);
        if (status == ERROR_SUCCESS)
            value.assign(buffer.c_str());
    }
    RegCloseKey(key);
    return status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND;
}

// Writes the user PATH (keeping its registry type) and tells Explorer and other
// programs, so new console windows get the updated PATH.
bool WriteUserPath(const std::wstring& value, DWORD type)
{
    LSTATUS status = value.empty()
        ? RegDeleteKeyValueW(HKEY_CURRENT_USER, kEnvironmentKey, L"Path")
        : RegSetKeyValueW(HKEY_CURRENT_USER, kEnvironmentKey, L"Path", type, value.c_str(),
              static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
    if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND)
        return false;
    SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, reinterpret_cast<LPARAM>(L"Environment"),
        SMTO_ABORTIFHUNG, 5000, nullptr);
    return true;
}

std::vector<std::wstring> SplitPath(const std::wstring& value)
{
    std::vector<std::wstring> entries;
    size_t start = 0;
    while (start <= value.size())
    {
        size_t end = value.find(L';', start);
        if (end == std::wstring::npos) end = value.size();
        if (end > start) entries.push_back(value.substr(start, end - start));
        start = end + 1;
    }
    return entries;
}

} // namespace

Settings LoadSettings()
{
    Settings s;
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kSettingsKey, 0, KEY_READ, &key) == ERROR_SUCCESS)
    {
        s.algorithms = ReadDword(key, L"Algorithms", s.algorithms);
        s.includeSubfolders = ReadDword(key, L"IncludeSubfolders", s.includeSubfolders) != 0;
        s.alwaysOnTop = ReadDword(key, L"AlwaysOnTop", s.alwaysOnTop) != 0;
        s.singleInstance = ReadDword(key, L"SingleInstance", s.singleInstance) != 0;
        s.showExtended = ReadDword(key, L"ShowExtended", s.showExtended) != 0;
        s.pathFolder = ReadString(key, L"PathFolder");
        RegCloseKey(key);
    }
    return s;
}

void SaveSettings(const Settings& settings)
{
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kSettingsKey, 0, nullptr, 0, KEY_WRITE, nullptr, &key, nullptr) != ERROR_SUCCESS)
        return;
    DWORD subfolders = settings.includeSubfolders ? 1 : 0;
    DWORD onTop = settings.alwaysOnTop ? 1 : 0;
    DWORD single = settings.singleInstance ? 1 : 0;
    RegSetValueExW(key, L"SingleInstance", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&single), sizeof(DWORD));
    DWORD extended = settings.showExtended ? 1 : 0;
    RegSetValueExW(key, L"ShowExtended", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&extended), sizeof(DWORD));
    RegSetValueExW(key, L"Algorithms", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&settings.algorithms), sizeof(DWORD));
    RegSetValueExW(key, L"IncludeSubfolders", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&subfolders), sizeof(DWORD));
    RegSetValueExW(key, L"AlwaysOnTop", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&onTop), sizeof(DWORD));
    if (settings.pathFolder.empty())
        RegDeleteValueW(key, L"PathFolder");
    else
        RegSetValueExW(key, L"PathFolder", 0, REG_SZ, reinterpret_cast<const BYTE*>(settings.pathFolder.c_str()),
            static_cast<DWORD>((settings.pathFolder.size() + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
}

bool IsShellIntegrationInstalled()
{
    for (const ShellEntry& entry : kShellEntries)
    {
        std::wstring commandKey = VerbKey(entry) + L"\\command";
        wchar_t value[2048];
        DWORD size = sizeof(value);
        if (RegGetValueW(HKEY_CURRENT_USER, commandKey.c_str(), nullptr, RRF_RT_REG_SZ, nullptr, value, &size) != ERROR_SUCCESS)
            return false;
        if (_wcsicmp(value, CommandFor(entry).c_str()) != 0)
            return false; // registered by a copy of HashCalc in another location
    }
    return true;
}

bool InstallShellIntegration()
{
    std::wstring icon = L"\"" + ExePath() + L"\",0";
    bool ok = true;
    for (const ShellEntry& entry : kShellEntries)
    {
        std::wstring key = VerbKey(entry);
        ok = SetString(HKEY_CURRENT_USER, key, nullptr, entry.text) && ok;
        ok = SetString(HKEY_CURRENT_USER, key, L"Icon", icon) && ok;
        ok = SetString(HKEY_CURRENT_USER, key + L"\\command", nullptr, CommandFor(entry)) && ok;
    }
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
    return ok;
}

bool IsFolderInUserPath(const std::wstring& folder)
{
    std::wstring value;
    DWORD type;
    if (folder.empty() || !ReadUserPath(value, type))
        return false;
    std::wstring wanted = NormalizeFolder(folder);
    for (const std::wstring& entry : SplitPath(value))
        if (NormalizeFolder(entry) == wanted)
            return true;
    return false;
}

bool AddFolderToUserPath(const std::wstring& folder)
{
    if (IsFolderInUserPath(folder))
        return true;
    std::wstring value;
    DWORD type;
    if (!ReadUserPath(value, type))
        return false;
    while (!value.empty() && value.back() == L';')
        value.pop_back();
    if (!value.empty())
        value += L';';
    value += folder;
    return WriteUserPath(value, type);
}

bool RemoveFolderFromUserPath(const std::wstring& folderToRemove)
{
    std::wstring value;
    DWORD type;
    if (!ReadUserPath(value, type))
        return false;
    std::wstring folder = NormalizeFolder(folderToRemove);
    std::wstring kept;
    bool removed = false;
    for (const std::wstring& entry : SplitPath(value))
    {
        if (NormalizeFolder(entry) == folder)
        {
            removed = true;
            continue;
        }
        kept += (kept.empty() ? L"" : L";") + entry;
    }
    return !removed || WriteUserPath(kept, type);
}

bool RemoveShellIntegration()
{
    bool ok = true;
    for (const ShellEntry& entry : kShellEntries)
    {
        LSTATUS status = RegDeleteTreeW(HKEY_CURRENT_USER, VerbKey(entry).c_str());
        ok = (status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND) && ok;
    }
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, nullptr, nullptr);
    return ok;
}
