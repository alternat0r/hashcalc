#include "gui/Settings.h"

#include <shlobj.h>
#include <string>

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
    RegSetValueExW(key, L"Algorithms", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&settings.algorithms), sizeof(DWORD));
    RegSetValueExW(key, L"IncludeSubfolders", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&subfolders), sizeof(DWORD));
    RegSetValueExW(key, L"AlwaysOnTop", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&onTop), sizeof(DWORD));
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
