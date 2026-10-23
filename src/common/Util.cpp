#include "common/Util.h"

#include <shobjidl.h>

#pragma comment(lib, "ole32.lib")

std::wstring GetDlgText(HWND dlg, int id)
{
    HWND ctl = GetDlgItem(dlg, id);
    int len = GetWindowTextLengthW(ctl);
    std::wstring s(len + 1, L'\0');
    GetWindowTextW(ctl, s.data(), len + 1);
    s.resize(len);
    return s;
}

std::vector<BYTE> ToUtf8(const std::wstring& s)
{
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    std::vector<BYTE> out(n);
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
        reinterpret_cast<char*>(out.data()), n, nullptr, nullptr);
    return out;
}

bool CopyToClipboard(HWND owner, const std::wstring& text)
{
    if (text.empty() || !OpenClipboard(owner))
        return false;

    bool ok = false;
    EmptyClipboard();
    size_t bytes = (text.size() + 1) * sizeof(wchar_t);
    if (HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, bytes))
    {
        memcpy(GlobalLock(mem), text.c_str(), bytes);
        GlobalUnlock(mem);
        ok = SetClipboardData(CF_UNICODETEXT, mem) != nullptr;
        if (!ok)
            GlobalFree(mem);
    }
    CloseClipboard();
    return ok;
}

std::wstring FormatSize(uint64_t bytes)
{
    static const wchar_t* const kUnits[] = { L"KB", L"MB", L"GB", L"TB" };
    wchar_t buf[64];
    if (bytes < 1024)
    {
        swprintf_s(buf, L"%llu bytes", static_cast<unsigned long long>(bytes));
        return buf;
    }
    double value = static_cast<double>(bytes);
    int unit = -1;
    while (value >= 1024 && unit < 3)
    {
        value /= 1024;
        ++unit;
    }
    swprintf_s(buf, L"%.1f %s", value, kUnits[unit]);
    return buf;
}

std::wstring ErrorMessage(DWORD error)
{
    wchar_t* text = nullptr;
    DWORD len = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error, 0, reinterpret_cast<LPWSTR>(&text), 0, nullptr);
    std::wstring s = len ? std::wstring(text, len) : L"Error " + std::to_wstring(error);
    LocalFree(text);
    while (!s.empty() && (s.back() == L'\n' || s.back() == L'\r' || s.back() == L' ' || s.back() == L'.'))
        s.pop_back();
    return s;
}

std::wstring LongPath(const std::wstring& path)
{
    if (path.size() < 3 || path.compare(0, 4, L"\\\\?\\") == 0)
        return path;
    if (path.compare(0, 2, L"\\\\") == 0)
        return L"\\\\?\\UNC\\" + path.substr(2);   // \\server\share -> \\?\UNC\server\share
    if (path[1] == L':' && (path[2] == L'\\' || path[2] == L'/'))
        return L"\\\\?\\" + path;
    return path;
}

bool IsDirectory(const std::wstring& path)
{
    DWORD attr = GetFileAttributesW(LongPath(path).c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY);
}

std::wstring ExePath()
{
    std::wstring path(MAX_PATH, L'\0');
    for (;;)
    {
        DWORD len = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (len < path.size())
        {
            path.resize(len);
            return path;
        }
        path.resize(path.size() * 2);
    }
}

bool BrowseForFolder(HWND owner, std::wstring& folder)
{
    IFileOpenDialog* dialog = nullptr;
    if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&dialog))))
        return false;

    bool ok = false;
    DWORD options = 0;
    dialog->GetOptions(&options);
    dialog->SetOptions(options | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
    dialog->SetTitle(L"Select a folder to hash");

    IShellItem* initial = nullptr;
    if (!folder.empty() && SUCCEEDED(SHCreateItemFromParsingName(folder.c_str(), nullptr, IID_PPV_ARGS(&initial))))
    {
        dialog->SetFolder(initial);
        initial->Release();
    }

    IShellItem* result = nullptr;
    if (SUCCEEDED(dialog->Show(owner)) && SUCCEEDED(dialog->GetResult(&result)))
    {
        PWSTR path = nullptr;
        if (SUCCEEDED(result->GetDisplayName(SIGDN_FILESYSPATH, &path)))
        {
            folder = path;
            CoTaskMemFree(path);
            ok = true;
        }
        result->Release();
    }
    dialog->Release();
    return ok;
}

INT_PTR DragAnywhereHitTest(HWND dlg, WPARAM wParam, LPARAM lParam)
{
    if (IsZoomed(dlg) || DefWindowProcW(dlg, WM_NCHITTEST, wParam, lParam) != HTCLIENT)
        return FALSE;
    SetWindowLongPtrW(dlg, DWLP_MSGRESULT, HTCAPTION);
    return TRUE;
}

void AnchorLayout::Capture(HWND dlg)
{
    m_dlg = dlg;
    RECT client, window;
    GetClientRect(dlg, &client);
    GetWindowRect(dlg, &window);
    m_initialClient = { client.right, client.bottom };
    m_initialWindow = { window.right - window.left, window.bottom - window.top };
    for (Item& item : m_items)
    {
        GetWindowRect(GetDlgItem(dlg, item.id), &item.rect);
        MapWindowPoints(nullptr, dlg, reinterpret_cast<POINT*>(&item.rect), 2);
    }
}

void AnchorLayout::Apply(int cx, int cy)
{
    if (!m_dlg)
        return;
    int dx = cx - m_initialClient.cx;
    int dy = cy - m_initialClient.cy;
    HDWP defer = BeginDeferWindowPos(static_cast<int>(m_items.size()));
    for (const Item& item : m_items)
    {
        RECT r = item.rect;
        if (item.flags & MoveX) { r.left += dx; r.right += dx; }
        if (item.flags & GrowX) r.right += dx;
        if (item.flags & MoveY) { r.top += dy; r.bottom += dy; }
        if (item.flags & GrowY) r.bottom += dy;
        defer = DeferWindowPos(defer, GetDlgItem(m_dlg, item.id), nullptr, r.left, r.top,
            r.right - r.left, r.bottom - r.top, SWP_NOZORDER | SWP_NOACTIVATE);
    }
    EndDeferWindowPos(defer);
    InvalidateRect(m_dlg, nullptr, TRUE);
}

bool WriteUtf8File(const std::wstring& path, const std::wstring& text, bool bom)
{
    HANDLE file = CreateFileW(LongPath(path).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return false;

    std::vector<BYTE> data;
    if (bom)
        data = { 0xEF, 0xBB, 0xBF };
    std::vector<BYTE> body = ToUtf8(text);
    data.insert(data.end(), body.begin(), body.end());

    DWORD written = 0;
    bool ok = WriteFile(file, data.data(), static_cast<DWORD>(data.size()), &written, nullptr)
        && written == data.size();
    CloseHandle(file);
    return ok;
}
