#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

std::wstring GetDlgText(HWND dlg, int id);

std::vector<BYTE> ToUtf8(const std::wstring& s);

bool CopyToClipboard(HWND owner, const std::wstring& text);

// "1.5 MB", "312 bytes", ...
std::wstring FormatSize(uint64_t bytes);

// System message for a Win32 error code, without the trailing newline.
std::wstring ErrorMessage(DWORD error);

// Adds the \\?\ prefix to absolute paths so paths longer than MAX_PATH work.
std::wstring LongPath(const std::wstring& path);

bool IsDirectory(const std::wstring& path);

// Full path of the running executable.
std::wstring ExePath();

// Shows the folder picker. folder is the initial folder and receives the result.
bool BrowseForFolder(HWND owner, std::wstring& folder);

// WM_NCHITTEST handler for dialogs: reports the empty background (and labels,
// which are transparent to the mouse) as title bar, so the window can be
// dragged from anywhere. Returns TRUE if it set the result.
INT_PTR DragAnywhereHitTest(HWND dlg, WPARAM wParam, LPARAM lParam);

// Writes UTF-8 text to a file (optionally with a byte order mark).
bool WriteUtf8File(const std::wstring& path, const std::wstring& text, bool bom);

// Keeps dialog controls anchored to the right/bottom edges while resizing.
class AnchorLayout
{
public:
    enum Flags : UINT { MoveX = 1, MoveY = 2, GrowX = 4, GrowY = 8 };

    void Add(int id, UINT flags) { m_items.push_back({ id, flags, {} }); }

    // Records the current layout; call at the end of WM_INITDIALOG.
    void Capture(HWND dlg);

    // Call from WM_SIZE with the new client size.
    void Apply(int cx, int cy);

    // Window size at Capture time (used as the minimum track size).
    SIZE InitialWindowSize() const { return m_initialWindow; }

private:
    struct Item
    {
        int id;
        UINT flags;
        RECT rect;
    };
    HWND m_dlg = nullptr;
    SIZE m_initialClient{};
    SIZE m_initialWindow{};
    std::vector<Item> m_items;
};
