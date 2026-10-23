#pragma once

#include <windows.h>

// ---------------------------------------------------------------------------
// Persisted settings (HKCU\Software\HashCalc)
// ---------------------------------------------------------------------------
struct Settings
{
    DWORD algorithms = 1u << 3;   // bit per HashAlg; default SHA256
    bool includeSubfolders = true;
    bool alwaysOnTop = false;
};

Settings LoadSettings();
void SaveSettings(const Settings& settings);

// ---------------------------------------------------------------------------
// Explorer context menu ("Calculate hash with HashCalc"), per user, no admin
// rights needed. Registered under HKCU\Software\Classes for files, folders and
// folder backgrounds, pointing at the currently running executable.
// ---------------------------------------------------------------------------

// True if the entries exist and point at this executable.
bool IsShellIntegrationInstalled();
bool InstallShellIntegration();
bool RemoveShellIntegration();
