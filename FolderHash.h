#pragma once

#include <windows.h>
#include <string>
#include <vector>

#include "Hashes.h"

// Implemented in main.cpp: reads the current selection from the main window.
// Returns false (with a message) if nothing usable is selected.
bool GetMainHashOptions(HashOptions& options, std::wstring& error);

// Opens the folder hash window (or brings the existing one to the front).
// A non-empty folder is filled in and, if autoStart is set, hashed right away.
void ShowFolderHashWindow(HWND owner, const std::wstring& folder, bool autoStart);

// The folder hash window, or nullptr; used by the message loop.
HWND FolderHashWindow();
