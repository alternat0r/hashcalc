#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <objbase.h>
#include <aclapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <windowsx.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <cwctype>
#include <deque>
#include <exception>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "cli/Cli.h"
#include "common/Util.h"
#include "core/Hashes.h"
#include "gui/FolderHash.h"
#include "gui/Settings.h"
#include "resource.h"
#include "version.h"

#pragma comment(lib, "comctl32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' " \
    "version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

namespace {

constexpr UINT WM_APP_CALC_DONE = WM_APP + 1;
constexpr UINT WM_APP_TASK_DONE = WM_APP + 2;   // wParam = algorithm index
constexpr UINT WM_APP_OPEN_FOLDER = WM_APP + 3; // startup: open the folder window
constexpr UINT WM_APP_OPEN_REQUEST = WM_APP + 4; // lParam = new std::wstring, from another instance
constexpr UINT WM_APP_NEXT_FILE = WM_APP + 5;   // hash the next queued file
constexpr size_t kReadChunkSize = 1 << 20;   // bytes per chunk handed to the hash threads
constexpr size_t kMaxQueuedChunks = 16;      // per algorithm; bounds memory use
constexpr int kProgressRange = 1000;
constexpr UINT_PTR kProgressTimer = 1;
constexpr UINT_PTR kCopyAllTimer = 2;
constexpr UINT_PTR kCopyRowTimer = 3;        // copy checkmark in a result row
constexpr UINT kProgressIntervalMs = 100;
constexpr UINT kCopyFeedbackMs = 1000;
constexpr UINT kSysCmdAbout = 0x0110;        // system menu items; below 0xF000, low 4 bits clear
constexpr UINT kSysCmdTopmost = 0x0120;

// Segoe MDL2 Assets glyphs
constexpr wchar_t kGlyphCopy[] = L"\xE8C8";
constexpr wchar_t kGlyphDone[] = L"\xE73E";
constexpr wchar_t kGlyphShield[] = L"\xEA18";

constexpr wchar_t kVirusTotalUrl[] = L"https://www.virustotal.com/gui/file/";
constexpr wchar_t kRepoUrl[] = L"https://github.com/alternat0r/hashcalc";

// Combo box item indices
enum DataFormat { DataFile = 0, DataText = 1, DataHex = 2 };
enum KeyFormat { KeyText = 0, KeyHex = 1 };

using Chunk = std::shared_ptr<const std::vector<BYTE>>;

// One selected algorithm, running on its own thread and fed from a bounded queue.
struct AlgTask
{
    std::unique_ptr<Hasher> hasher;
    std::thread thread;

    std::mutex mutex;
    std::condition_variable cv;
    std::deque<Chunk> queue;
    bool endOfInput = false;

    std::atomic<uint64_t> processed{ 0 };
    std::wstring result;
};

struct CalcJob
{
    // Input (captured from the UI before the worker starts)
    int dataFormat = DataFile;
    std::wstring data;
    bool hmac = false;
    int keyFormat = KeyHex;
    std::wstring key;
    bool selected[kHashAlgCount] = {};

    // Progress (read by the UI thread)
    std::atomic<uint64_t> totalBytes{ 0 };

    // Output (filled by the worker threads)
    AlgTask tasks[kHashAlgCount];
    std::wstring error;
};

// What to do right after startup (from the command line / Explorer).
struct StartupArgs
{
    std::wstring file;     // hash this file
    std::wstring folder;   // open the folder window and hash this folder
};

HWND g_dlg = nullptr;
StartupArgs g_startup;
AnchorLayout g_layout;
std::unique_ptr<CalcJob> g_job;
std::thread g_worker;
bool g_rowDone[kHashAlgCount] = {};      // result shown (UI thread only)
int g_rowProgress[kHashAlgCount] = {};   // 0..kProgressRange while a row is working
std::wstring g_results[kHashAlgCount];   // value shown in each result row
std::vector<int> g_rows;                 // algorithm shown in each list row
int g_copiedAlg = -1;                    // row showing the copy checkmark
bool g_showExtended = false;             // View > PE & Similarity Hashes
bool g_extendedLayoutShown = true;       // the dialog is designed with them shown
bool g_layoutPaused = false;             // while ApplyExtendedView moves controls
std::atomic<bool> g_cancel{ false };
bool g_userCancelled = false;            // Cancel button pressed (UI thread only)
HANDLE g_instanceMutex = nullptr;        // held while Single Instance is on
bool g_resultsAreHmac = false;           // shown results are HMACs (not file hashes)
std::deque<std::wstring> g_pendingFiles; // files sent by other instances while busy
HFONT g_logoFont = nullptr;
HFONT g_iconFont = nullptr;

// ---------------------------------------------------------------------------
// Worker threads
// ---------------------------------------------------------------------------

// Runs on one thread per selected algorithm.
void HashThread(AlgTask& task, int alg)
{
    try
    {
        for (;;)
        {
            Chunk chunk;
            {
                std::unique_lock<std::mutex> lock(task.mutex);
                task.cv.wait(lock, [&] { return !task.queue.empty() || task.endOfInput || g_cancel; });
                if (g_cancel)
                    return;
                if (task.queue.empty())
                    break; // end of input
                chunk = std::move(task.queue.front());
                task.queue.pop_front();
            }
            task.cv.notify_all(); // wake the reader if it waits for queue space

            task.hasher->Update(chunk->data(), chunk->size());
            task.processed += chunk->size();
        }
        task.result = task.hasher->FinishText();
    }
    catch (const std::exception&)
    {
        task.result = L"(error)";
    }
    // Show this result right away instead of waiting for slower algorithms.
    if (!g_cancel)
        PostMessageW(g_dlg, WM_APP_TASK_DONE, alg, 0);
}

// Algorithms slow enough to throttle the others (MD2 runs at ~10 MB/s) read
// the input in their own pass instead of sharing the main reader.
bool RunsOnOwnPass(HashAlg alg)
{
    return alg == HashAlg::MD2;
}

using TaskGroup = std::vector<AlgTask*>;

// Hands a chunk to every algorithm in the group, waiting while a queue is full.
void Distribute(const TaskGroup& group, const Chunk& chunk)
{
    for (AlgTask* task : group)
    {
        std::unique_lock<std::mutex> lock(task->mutex);
        task->cv.wait(lock, [&] { return task->queue.size() < kMaxQueuedChunks || g_cancel; });
        if (g_cancel) return;
        task->queue.push_back(chunk);
        lock.unlock();
        task->cv.notify_all();
    }
}

// Reads the input once and feeds it to the group's hash threads.
// Returns an error message or "".
std::wstring FeedInput(CalcJob& job, const TaskGroup& group)
{
    if (job.dataFormat != DataFile)
    {
        auto bytes = std::make_shared<std::vector<BYTE>>();
        if (job.dataFormat == DataHex)
        {
            if (!ParseHex(job.data, *bytes))
                return L"The data is not a valid hex string.";
        }
        else
            *bytes = ToUtf8(job.data);
        job.totalBytes = bytes->size();
        Distribute(group, bytes);
        return L"";
    }

    HANDLE file = CreateFileW(LongPath(job.data).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return L"Cannot open file:\n" + job.data + L"\n\n" + ErrorMessage(GetLastError());

    LARGE_INTEGER size = {};
    if (GetFileSizeEx(file, &size))
        job.totalBytes = static_cast<uint64_t>(size.QuadPart);

    std::wstring error;
    while (!g_cancel)
    {
        auto buffer = std::make_shared<std::vector<BYTE>>(kReadChunkSize);
        DWORD read = 0;
        if (!ReadFile(file, buffer->data(), static_cast<DWORD>(buffer->size()), &read, nullptr))
        {
            error = L"Error reading file:\n" + job.data + L"\n\n" + ErrorMessage(GetLastError());
            break;
        }
        if (read == 0)
            break;
        buffer->resize(read);
        Distribute(group, buffer);
    }
    CloseHandle(file);
    return error;
}

void RunJob(CalcJob& job)
{
    std::vector<BYTE> key;
    const std::vector<BYTE>* keyPtr = nullptr;
    if (job.hmac)
    {
        if (job.keyFormat == KeyHex)
        {
            if (!ParseHex(job.key, key))
            {
                job.error = L"The HMAC key is not a valid hex string.";
                return;
            }
        }
        else
            key = ToUtf8(job.key);
        keyPtr = &key;
    }

    for (int i = 0; i < kHashAlgCount; ++i)
    {
        if (!job.selected[i]) continue;
        HashAlg alg = static_cast<HashAlg>(i);
        AlgTask& task = job.tasks[i];
        try
        {
            task.hasher = CreateHasher(alg, keyPtr);
            if (!task.hasher)
                task.result = IsImplemented(alg) ? L"(HMAC not supported)" : L"(not implemented)";
        }
        catch (const std::exception&)
        {
            task.result = L"(error)";
        }
    }

    // One shared pass for the fast algorithms, plus a separate pass for each slow one.
    std::vector<TaskGroup> groups(1);
    for (int i = 0; i < kHashAlgCount; ++i)
    {
        AlgTask& task = job.tasks[i];
        if (!task.hasher) continue;
        task.thread = std::thread(HashThread, std::ref(task), i);
        if (RunsOnOwnPass(static_cast<HashAlg>(i)))
            groups.push_back({ &task });
        else
            groups[0].push_back(&task);
    }

    std::vector<std::wstring> errors(groups.size());
    std::vector<std::thread> readers;
    for (size_t g = 0; g < groups.size(); ++g)
    {
        if (groups[g].empty()) continue;
        readers.emplace_back([&, g] {
            errors[g] = FeedInput(job, groups[g]);
            if (!errors[g].empty())
            {
                g_cancel = true; // abort all hash threads; their results are meaningless
                for (AlgTask& task : job.tasks)
                    task.cv.notify_all();
            }
            // Let this group finish now rather than waiting for slower passes.
            for (AlgTask* task : groups[g])
            {
                {
                    std::lock_guard<std::mutex> lock(task->mutex);
                    task->endOfInput = true;
                }
                task->cv.notify_all();
            }
        });
    }
    for (std::thread& reader : readers)
        reader.join();
    for (AlgTask& task : job.tasks)
        if (task.thread.joinable())
            task.thread.join();

    for (const std::wstring& e : errors)
        if (job.error.empty())
            job.error = e;
}

void WorkerMain(HWND dlg)
{
    try
    {
        RunJob(*g_job);
    }
    catch (const std::exception& e)
    {
        std::string what = e.what();
        g_job->error = L"Hash calculation failed: " + std::wstring(what.begin(), what.end());
    }
    PostMessageW(dlg, WM_APP_CALC_DONE, 0, 0);
}

// Sets the cancel flag and wakes every hash thread and reader. Taking each
// lock first ensures a thread that is about to wait cannot miss the wake-up.
void SignalCancel()
{
    g_cancel = true;
    if (!g_job)
        return;
    for (AlgTask& task : g_job->tasks)
    {
        { std::lock_guard<std::mutex> lock(task.mutex); }
        task.cv.notify_all();
    }
}

void StopWorker()
{
    if (g_worker.joinable())
    {
        SignalCancel();
        g_worker.join();
    }
}

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------
bool IsChecked(HWND dlg, int id)
{
    return IsDlgButtonChecked(dlg, id) == BST_CHECKED;
}

bool IsBusy()
{
    return g_worker.joinable();
}

// ---------------------------------------------------------------------------
// Hash types (checkbox grid) and the results list
// ---------------------------------------------------------------------------

// Order of the checkbox grid and of the result rows.
const HashAlg kDisplayOrder[] = {
    HashAlg::MD5, HashAlg::SHA1, HashAlg::SHA256, HashAlg::SHA384,
    HashAlg::SHA512, HashAlg::MD4, HashAlg::MD2, HashAlg::RIPEMD160,
    HashAlg::TIGER, HashAlg::PANAMA, HashAlg::ADLER32, HashAlg::CRC32,
    HashAlg::EDONKEY, HashAlg::IMPHASH, HashAlg::AUTHENTIHASH, HashAlg::RICHHASH,
    HashAlg::SSDEEP, HashAlg::TLSH,
};

enum ResultColumn { ColName, ColValue, ColCopy, ColVirusTotal };

HWND ResultList(HWND dlg)
{
    return GetDlgItem(dlg, IDC_RESULTS);
}

// Hidden types (View > PE & Similarity Hashes off) are not shown or computed.
bool IsVisibleType(int alg)
{
    return g_showExtended || !IsExtendedHash(static_cast<HashAlg>(alg));
}

// Ticked, visible and usable (HMAC limits the types) - these get a result row.
bool IsTypeSelected(HWND dlg, int alg)
{
    bool hmac = IsChecked(dlg, IDC_HMAC);
    return IsVisibleType(alg) && IsChecked(dlg, IDC_CHK_BASE + alg) &&
        (!hmac || SupportsHmac(static_cast<HashAlg>(alg)));
}

bool IsShowingPercent(int alg)
{
    return IsBusy() && g_job && g_job->selected[alg] && !g_rowDone[alg];
}

int RowOf(int alg)
{
    for (size_t r = 0; r < g_rows.size(); ++r)
        if (g_rows[r] == alg)
            return static_cast<int>(r);
    return -1;
}

void RedrawRow(HWND dlg, int alg)
{
    int row = RowOf(alg);
    if (row >= 0)
        ListView_RedrawItems(ResultList(dlg), row, row);
}

// Value column fills the width left by the name and the two icon columns.
void SizeResultColumns(HWND dlg)
{
    HWND list = ResultList(dlg);
    RECT client;
    GetClientRect(list, &client);
    const int dpi = static_cast<int>(GetDpiForWindow(dlg));
    const int name = MulDiv(84, dpi, 96);
    const int icon = MulDiv(26, dpi, 96);
    ListView_SetColumnWidth(list, ColName, name);
    ListView_SetColumnWidth(list, ColValue, std::max<int>(MulDiv(60, dpi, 96), client.right - name - 2 * icon));
    ListView_SetColumnWidth(list, ColCopy, icon);
    ListView_SetColumnWidth(list, ColVirusTotal, icon);
}

// One row per selected type, in grid order.
void RebuildResultRows(HWND dlg)
{
    g_rows.clear();
    for (HashAlg a : kDisplayOrder)
        if (IsTypeSelected(dlg, static_cast<int>(a)))
            g_rows.push_back(static_cast<int>(a));
    HWND list = ResultList(dlg);
    ListView_SetItemCountEx(list, static_cast<int>(g_rows.size()), LVSICF_NOSCROLL);
    InvalidateRect(list, nullptr, TRUE);
    SizeResultColumns(dlg);   // a scrollbar may have appeared or gone
}

void SetResult(HWND dlg, int alg, const std::wstring& text)
{
    g_results[alg] = text;
    RedrawRow(dlg, alg);
}

// Reflects the hash checkboxes in the "All" checkbox (checked / partial / unchecked).
void UpdateAllCheckbox(HWND dlg)
{
    int available = 0, checked = 0;
    for (int i = 0; i < kHashAlgCount; ++i)
    {
        if (!IsVisibleType(i) || !IsWindowEnabled(GetDlgItem(dlg, IDC_CHK_BASE + i))) continue;
        ++available;
        if (IsChecked(dlg, IDC_CHK_BASE + i)) ++checked;
    }
    UINT state = checked == 0 ? BST_UNCHECKED : checked == available ? BST_CHECKED : BST_INDETERMINATE;
    CheckDlgButton(dlg, IDC_CHK_ALL, state);
}

void OnCheckAll(HWND dlg)
{
    // Fully checked -> clear all; unchecked or partial -> check all
    UINT state = IsDlgButtonChecked(dlg, IDC_CHK_ALL) == BST_CHECKED ? BST_UNCHECKED : BST_CHECKED;
    for (int i = 0; i < kHashAlgCount; ++i)
        if (IsVisibleType(i) && IsWindowEnabled(GetDlgItem(dlg, IDC_CHK_BASE + i)))
            CheckDlgButton(dlg, IDC_CHK_BASE + i, state);
    UpdateAllCheckbox(dlg);
    RebuildResultRows(dlg);
}

void UpdateControlStates(HWND dlg)
{
    bool busy = IsBusy();
    bool isFile = SendDlgItemMessageW(dlg, IDC_DATAFORMAT, CB_GETCURSEL, 0, 0) == DataFile;
    bool hmac = IsChecked(dlg, IDC_HMAC);

    EnableWindow(GetDlgItem(dlg, IDC_DATAFORMAT), !busy);
    EnableWindow(GetDlgItem(dlg, IDC_DATA), !busy);
    EnableWindow(GetDlgItem(dlg, IDC_BROWSE), !busy && isFile);
    EnableWindow(GetDlgItem(dlg, IDC_HMAC), !busy);
    EnableWindow(GetDlgItem(dlg, IDC_KEYFORMAT), !busy && hmac);
    EnableWindow(GetDlgItem(dlg, IDC_KEY), !busy && hmac);

    for (int i = 0; i < kHashAlgCount; ++i)
    {
        bool usable = !hmac || SupportsHmac(static_cast<HashAlg>(i));
        EnableWindow(GetDlgItem(dlg, IDC_CHK_BASE + i), !busy && usable);
    }
    EnableWindow(GetDlgItem(dlg, IDC_CHK_ALL), !busy);
    if (!busy)
        UpdateAllCheckbox(dlg);

    // While a calculation runs, the Calculate button becomes Cancel.
    bool cancelling = busy && g_cancel;
    EnableWindow(GetDlgItem(dlg, IDC_CALCULATE), !cancelling);
    SetDlgItemTextW(dlg, IDC_CALCULATE, !busy ? L"Calculate" : cancelling ? L"Cancelling..." : L"Cancel");
}

void ClearResults(HWND dlg)
{
    for (int i = 0; i < kHashAlgCount; ++i)
    {
        g_results[i].clear();
        g_rowProgress[i] = 0;
    }
    InvalidateRect(ResultList(dlg), nullptr, TRUE);
}

// Called on a timer while a calculation runs: the rows still working show a
// grey percentage with a thin progress line under it.
void RefreshProgress(HWND dlg)
{
    if (!g_job)
        return;
    uint64_t total = g_job->totalBytes;
    for (int i = 0; i < kHashAlgCount; ++i)
    {
        if (!g_job->selected[i] || g_rowDone[i]) continue;
        uint64_t done = g_job->tasks[i].processed;
        int pos = total ? static_cast<int>(std::min<uint64_t>(done, total) * kProgressRange / total) : 0;
        if (pos != g_rowProgress[i])
        {
            g_rowProgress[i] = pos;
            RedrawRow(dlg, i);
        }
    }
}

// ---------------------------------------------------------------------------
// VirusTotal lookup. Its file page accepts MD5, SHA1 and SHA256, so only those
// rows have the shield. Only the hash goes to VirusTotal (in the browser).
// ---------------------------------------------------------------------------
bool SupportsVirusTotal(int alg)
{
    HashAlg a = static_cast<HashAlg>(alg);
    return a == HashAlg::MD5 || a == HashAlg::SHA1 || a == HashAlg::SHA256;
}

// The row shows a complete hash VirusTotal can look up: right length, hex only,
// and not an HMAC (that depends on the key, so VirusTotal cannot know it).
bool IsVirusTotalHash(int alg, const std::wstring& text)
{
    if (!SupportsVirusTotal(alg))
        return false;
    size_t length = alg == static_cast<int>(HashAlg::MD5) ? 32 : alg == static_cast<int>(HashAlg::SHA1) ? 40 : 64;
    return !g_resultsAreHmac && text.size() == length &&
        std::all_of(text.begin(), text.end(), [](wchar_t c) { return iswxdigit(c) != 0; });
}

// A real value, not a "(not a Windows program)"-style message.
bool CanCopy(int alg)
{
    return !g_results[alg].empty() && g_results[alg][0] != L'(' && !IsShowingPercent(alg);
}

void OnVirusTotal(HWND dlg, int alg)
{
    std::wstring hash = g_results[alg];
    if (IsShowingPercent(alg) || !IsVirusTotalHash(alg, hash))
        return;
    CharLowerBuffW(hash.data(), static_cast<DWORD>(hash.size()));
    ShellExecuteW(dlg, L"open", (kVirusTotalUrl + hash).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

void OnCopy(HWND dlg, int alg)
{
    if (!CanCopy(alg) || !CopyToClipboard(dlg, g_results[alg]))
        return;

    // Brief checkmark in the row as feedback
    int previous = g_copiedAlg;
    g_copiedAlg = alg;
    if (previous >= 0)
        RedrawRow(dlg, previous);
    RedrawRow(dlg, alg);
    SetTimer(dlg, kCopyRowTimer, kCopyFeedbackMs, nullptr);
}

// Copies the input description followed by one "NAME: hash" line per result.
// The HMAC key is deliberately left out.
void OnCopyAll(HWND dlg)
{
    std::wstring results;
    for (int alg : g_rows)
    {
        if (g_results[alg].empty() || IsShowingPercent(alg)) continue;   // messages are kept
        results += HashAlgName(static_cast<HashAlg>(alg));
        results += L": " + g_results[alg] + L"\r\n";
    }
    if (results.empty())
        return;

    static const wchar_t* const kFormatNames[] = { L"File", L"Text", L"Hex" };
    int format = static_cast<int>(SendDlgItemMessageW(dlg, IDC_DATAFORMAT, CB_GETCURSEL, 0, 0));
    std::wstring text = kFormatNames[format == CB_ERR ? DataFile : format];
    text += L": " + GetDlgText(dlg, IDC_DATA) + L"\r\n";
    if (IsChecked(dlg, IDC_HMAC))
        text += L"HMAC: yes\r\n";
    text += results;

    if (!CopyToClipboard(dlg, text))
        return;

    SetDlgItemTextW(dlg, IDC_COPY_ALL, L"Copied!");
    SetTimer(dlg, kCopyAllTimer, kCopyFeedbackMs, nullptr);
}

// The copy and VirusTotal columns are drawn as icons (Segoe MDL2 Assets).
void DrawRowIcon(HWND dlg, const NMLVCUSTOMDRAW* cd, int alg)
{
    HWND list = ResultList(dlg);
    const int row = static_cast<int>(cd->nmcd.dwItemSpec);
    RECT rc;
    if (!ListView_GetSubItemRect(list, row, cd->iSubItem, LVIR_BOUNDS, &rc))
        return;

    const bool selected = (ListView_GetItemState(list, row, LVIS_SELECTED) & LVIS_SELECTED) != 0;
    const bool focused = GetFocus() == list;
    COLORREF background = GetSysColor(selected ? (focused ? COLOR_HIGHLIGHT : COLOR_BTNFACE) : COLOR_WINDOW);
    COLORREF normal = GetSysColor(selected && focused ? COLOR_HIGHLIGHTTEXT : COLOR_WINDOWTEXT);
    HDC hdc = cd->nmcd.hdc;
    SetBkColor(hdc, background);
    ExtTextOutW(hdc, 0, 0, ETO_OPAQUE, &rc, nullptr, 0, nullptr);

    const wchar_t* glyph = nullptr;
    bool enabled = false;
    if (cd->iSubItem == ColCopy)
    {
        glyph = g_copiedAlg == alg ? kGlyphDone : kGlyphCopy;
        enabled = CanCopy(alg);
    }
    else if (SupportsVirusTotal(alg))
    {
        glyph = kGlyphShield;
        enabled = !IsShowingPercent(alg) && IsVirusTotalHash(alg, g_results[alg]);
    }
    if (!glyph)
        return;
    // Unavailable icons: grey text mixed halfway into the background, so they
    // clearly look inactive next to the working ones.
    COLORREF grey = GetSysColor(COLOR_GRAYTEXT);
    COLORREF faded = RGB((GetRValue(grey) + GetRValue(background)) / 2,
                         (GetGValue(grey) + GetGValue(background)) / 2,
                         (GetBValue(grey) + GetBValue(background)) / 2);
    HGDIOBJ oldFont = SelectObject(hdc, g_iconFont);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, enabled ? normal : faded);
    DrawTextW(hdc, glyph, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(hdc, oldFont);
}

LRESULT OnResultsCustomDraw(HWND dlg, NMLVCUSTOMDRAW* cd)
{
    switch (cd->nmcd.dwDrawStage)
    {
    case CDDS_PREPAINT:
        return CDRF_NOTIFYITEMDRAW;
    case CDDS_ITEMPREPAINT:
        return CDRF_NOTIFYSUBITEMDRAW;
    case CDDS_ITEMPREPAINT | CDDS_SUBITEM:
    {
        const size_t row = cd->nmcd.dwItemSpec;
        if (row >= g_rows.size())
            return CDRF_DODEFAULT;
        const int alg = g_rows[row];
        if (cd->iSubItem == ColCopy || cd->iSubItem == ColVirusTotal)
        {
            DrawRowIcon(dlg, cd, alg);
            return CDRF_SKIPDEFAULT;
        }
        HWND list = ResultList(dlg);
        const bool highlighted = (ListView_GetItemState(list, static_cast<int>(row), LVIS_SELECTED) & LVIS_SELECTED) &&
                                 GetFocus() == list;
        if (cd->iSubItem == ColValue && IsShowingPercent(alg))
        {
            cd->clrText = GetSysColor(COLOR_GRAYTEXT);
            return CDRF_NEWFONT | CDRF_NOTIFYPOSTPAINT;
        }
        cd->clrText = GetSysColor(highlighted ? COLOR_HIGHLIGHTTEXT : COLOR_WINDOWTEXT);
        return CDRF_NEWFONT;
    }
    case CDDS_ITEMPOSTPAINT | CDDS_SUBITEM:
    {
        // Thin progress line under the percentage
        const size_t row = cd->nmcd.dwItemSpec;
        if (row >= g_rows.size() || cd->iSubItem != ColValue)
            return CDRF_DODEFAULT;
        const int alg = g_rows[row];
        RECT rc;
        if (IsShowingPercent(alg) && g_rowProgress[alg] > 0 &&
            ListView_GetSubItemRect(ResultList(dlg), static_cast<int>(row), ColValue, LVIR_BOUNDS, &rc))
        {
            const int dpi = static_cast<int>(GetDpiForWindow(dlg));
            RECT bar = { rc.left + 4, rc.bottom - MulDiv(3, dpi, 96), 0, rc.bottom - 1 };
            bar.right = bar.left + MulDiv(rc.right - rc.left - 8, g_rowProgress[alg], kProgressRange);
            HBRUSH green = CreateSolidBrush(RGB(6, 176, 37));
            FillRect(cd->nmcd.hdc, &bar, green);
            DeleteObject(green);
        }
        return CDRF_DODEFAULT;
    }
    }
    return CDRF_DODEFAULT;
}

void ShowResultMenu(HWND dlg, int alg, POINT screen)
{
    HMENU menu = CreatePopupMenu();
    if (alg >= 0)
    {
        AppendMenuW(menu, MF_STRING | (CanCopy(alg) ? 0 : MF_GRAYED), 1, L"&Copy");
        if (SupportsVirusTotal(alg))
            AppendMenuW(menu, MF_STRING | (!IsShowingPercent(alg) && IsVirusTotalHash(alg, g_results[alg]) ? 0 : MF_GRAYED),
                2, L"Check on &VirusTotal");
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    }
    AppendMenuW(menu, MF_STRING, 3, L"Copy &All");
    int choice = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screen.x, screen.y, 0, dlg, nullptr);
    DestroyMenu(menu);
    if (choice == 1) OnCopy(dlg, alg);
    else if (choice == 2) OnVirusTotal(dlg, alg);
    else if (choice == 3) OnCopyAll(dlg);
}

int SelectedRowAlg(HWND dlg)
{
    int row = ListView_GetNextItem(ResultList(dlg), -1, LVNI_SELECTED);
    return row >= 0 && row < static_cast<int>(g_rows.size()) ? g_rows[row] : -1;
}

// WM_NOTIFY from the results list. Returns true if handled (result in *result).
bool OnResultsNotify(HWND dlg, NMHDR* header, LRESULT* result)
{
    *result = 0;
    switch (header->code)
    {
    case LVN_GETDISPINFOW:
    {
        auto* info = reinterpret_cast<NMLVDISPINFOW*>(header);
        const size_t row = static_cast<size_t>(info->item.iItem);
        if (!(info->item.mask & LVIF_TEXT) || row >= g_rows.size())
            return true;
        const int alg = g_rows[row];
        std::wstring text;
        if (info->item.iSubItem == ColName)
            text = HashAlgName(static_cast<HashAlg>(alg));
        else if (info->item.iSubItem == ColValue)
            text = IsShowingPercent(alg) ? std::to_wstring(std::min(g_rowProgress[alg] / 10, 99)) + L"%" : g_results[alg];
        wcsncpy_s(info->item.pszText, info->item.cchTextMax, text.c_str(), _TRUNCATE);
        return true;
    }
    case LVN_GETINFOTIPW:
    {
        auto* tip = reinterpret_cast<NMLVGETINFOTIPW*>(header);
        const size_t row = static_cast<size_t>(tip->iItem);
        if (row >= g_rows.size())
            return true;
        const int alg = g_rows[row];
        std::wstring text = std::wstring(HashAlgName(static_cast<HashAlg>(alg))) + L": " +
            (g_results[alg].empty() ? L"(not calculated)" : g_results[alg]);
        text += SupportsVirusTotal(alg) ? L"\nClick the copy icon to copy, or the shield to check it on VirusTotal."
                                        : L"\nClick the copy icon (or double-click the row) to copy.";
        wcsncpy_s(tip->pszText, tip->cchTextMax, text.c_str(), _TRUNCATE);
        return true;
    }
    case NM_CUSTOMDRAW:
        *result = OnResultsCustomDraw(dlg, reinterpret_cast<NMLVCUSTOMDRAW*>(header));
        return true;
    case NM_CLICK:
    case NM_DBLCLK:
    {
        auto* click = reinterpret_cast<NMITEMACTIVATE*>(header);
        if (click->iItem < 0 || click->iItem >= static_cast<int>(g_rows.size()))
            return true;
        const int alg = g_rows[click->iItem];
        if (header->code == NM_DBLCLK || click->iSubItem == ColCopy)
            OnCopy(dlg, alg);
        else if (click->iSubItem == ColVirusTotal)
            OnVirusTotal(dlg, alg);
        return true;
    }
    case LVN_KEYDOWN:
    {
        auto* key = reinterpret_cast<NMLVKEYDOWN*>(header);
        if (key->wVKey == 'C' && (GetKeyState(VK_CONTROL) & 0x8000) && SelectedRowAlg(dlg) >= 0)
            OnCopy(dlg, SelectedRowAlg(dlg));
        return true;
    }
    }
    return false;
}

void InitResultList(HWND dlg)
{
    HFONT dlgFont = reinterpret_cast<HFONT>(SendMessageW(dlg, WM_GETFONT, 0, 0));
    LOGFONTW lf = {};
    GetObjectW(dlgFont, sizeof(lf), &lf);
    lf.lfWeight = FW_NORMAL;
    lf.lfItalic = FALSE;
    lf.lfUnderline = FALSE;
    wcscpy_s(lf.lfFaceName, L"Segoe MDL2 Assets");
    g_iconFont = CreateFontIndirectW(&lf);

    HWND list = ResultList(dlg);
    ListView_SetExtendedListViewStyle(list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_INFOTIP);
    const wchar_t* titles[] = { L"Type", L"Value", L"Copy", L"VirusTotal" };
    for (int c = 0; c < 4; ++c)
    {
        LVCOLUMNW col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.pszText = const_cast<LPWSTR>(titles[c]);
        col.cx = 40;
        ListView_InsertColumn(list, c, &col);
    }
    if (HWND tooltip = ListView_GetToolTips(list))
        SendMessageW(tooltip, TTM_SETMAXTIPWIDTH, 0, 420);   // wrap long hashes
}

// ---------------------------------------------------------------------------
// View > PE & Similarity Hashes. The dialog is designed with those types
// shown; hiding them removes the last grid row and moves the list and the
// buttons up by that row.
// ---------------------------------------------------------------------------
void ApplyExtendedView(HWND dlg, bool show)
{
    if (show == g_extendedLayoutShown)
        return;
    for (int i = 0; i < kHashAlgCount; ++i)
        if (IsExtendedHash(static_cast<HashAlg>(i)))
            ShowWindow(GetDlgItem(dlg, IDC_CHK_BASE + i), show ? SW_SHOW : SW_HIDE);

    RECT row = { 0, 0, 0, 12 };   // one grid row (dialog units)
    MapDialogRect(dlg, &row);
    const int shift = show ? row.bottom : -row.bottom;

    g_layoutPaused = true;   // positions are set here, not by the anchors
    for (int id : { IDC_RESULTS, IDC_LOGO, IDC_CALCULATE, IDCANCEL, IDC_HELPBTN })
    {
        HWND ctl = GetDlgItem(dlg, id);
        RECT r;
        GetWindowRect(ctl, &r);
        MapWindowPoints(nullptr, dlg, reinterpret_cast<POINT*>(&r), 2);
        SetWindowPos(ctl, nullptr, r.left, r.top + shift, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    }
    RECT window;
    GetWindowRect(dlg, &window);
    SetWindowPos(dlg, nullptr, 0, 0, window.right - window.left, window.bottom - window.top + shift,
        SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    g_layoutPaused = false;

    g_layout.Capture(dlg);   // the new positions are the base for resizing
    g_extendedLayoutShown = show;
    InvalidateRect(dlg, nullptr, TRUE);
}

void OnToggleExtended(HWND dlg)
{
    if (IsBusy())
        return;
    Settings settings = LoadSettings();
    settings.showExtended = !settings.showExtended;
    SaveSettings(settings);
    g_showExtended = settings.showExtended;
    ApplyExtendedView(dlg, g_showExtended);
    UpdateAllCheckbox(dlg);
    RebuildResultRows(dlg);
}

bool OnBrowse(HWND dlg)
{
    wchar_t path[MAX_PATH * 4] = {};
    OPENFILENAMEW ofn = { sizeof(ofn) };
    ofn.hwndOwner = dlg;
    ofn.lpstrFilter = L"All Files (*.*)\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = ARRAYSIZE(path);
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    if (!GetOpenFileNameW(&ofn))
        return false;
    SendDlgItemMessageW(dlg, IDC_DATAFORMAT, CB_SETCURSEL, DataFile, 0);
    SetDlgItemTextW(dlg, IDC_DATA, path);
    UpdateControlStates(dlg);
    return true;
}

void OnCalculate(HWND dlg);

// A drive path (C:\ or C:/), a network path (\\server) or an existing file or
// folder. Typing such a path keeps the File format even before it exists.
bool LooksLikePath(const std::wstring& s)
{
    if (s.size() >= 3 && iswalpha(s[0]) && s[1] == L':' && (s[2] == L'\\' || s[2] == L'/'))
        return true;
    if (s.size() >= 3 && s[0] == L'\\' && s[1] == L'\\')
        return true;
    return GetFileAttributesW(LongPath(s).c_str()) != INVALID_FILE_ATTRIBUTES;
}

// Data box changed (typed, pasted, dropped or set by code): pick the Data
// Format automatically. Paths -> File; other text while File is selected ->
// Text string. Hex is never guessed (plenty of words are valid hex), so a
// manually chosen Hex string is kept unless a path is entered.
void OnDataChanged(HWND dlg)
{
    static bool updating = false;
    if (updating || IsBusy())
        return;

    std::wstring text = GetDlgText(dlg, IDC_DATA);
    if (text.empty())
        return;

    // Explorer's "Copy as path" adds quotes; remove them.
    if (text.size() >= 3 && text.front() == L'"' && text.back() == L'"' &&
        LooksLikePath(text.substr(1, text.size() - 2)))
    {
        text = text.substr(1, text.size() - 2);
        updating = true;
        SetDlgItemTextW(dlg, IDC_DATA, text.c_str());
        SendDlgItemMessageW(dlg, IDC_DATA, EM_SETSEL, text.size(), text.size());
        updating = false;
    }

    int format = static_cast<int>(SendDlgItemMessageW(dlg, IDC_DATAFORMAT, CB_GETCURSEL, 0, 0));
    int detected = LooksLikePath(text) ? DataFile : (format == DataFile ? DataText : format);
    if (detected != format)
    {
        SendDlgItemMessageW(dlg, IDC_DATAFORMAT, CB_SETCURSEL, detected, 0);
        UpdateControlStates(dlg);
    }
}

void OnDropFiles(HWND dlg, HDROP drop)
{
    UINT len = DragQueryFileW(drop, 0, nullptr, 0);
    std::wstring path(len + 1, L'\0');
    DragQueryFileW(drop, 0, path.data(), len + 1);
    path.resize(len);
    DragFinish(drop);

    if (IsDirectory(path))
    {
        ShowFolderHashWindow(dlg, path, true);
        return;
    }
    if (!IsBusy())
    {
        SendDlgItemMessageW(dlg, IDC_DATAFORMAT, CB_SETCURSEL, DataFile, 0);
        SetDlgItemTextW(dlg, IDC_DATA, path.c_str());
        UpdateControlStates(dlg);
    }
}

// Cancel button: stop the running calculation. Results that already finished
// are kept; the rest are cleared when the worker reports back (OnCalcDone).
void OnCancel(HWND dlg)
{
    if (!IsBusy() || g_cancel)
        return;
    g_userCancelled = true;
    SignalCancel();
    UpdateControlStates(dlg);
}

void OnCalculate(HWND dlg)
{
    if (IsBusy())
    {
        OnCancel(dlg);
        return;
    }

    auto job = std::make_unique<CalcJob>();
    job->dataFormat = static_cast<int>(SendDlgItemMessageW(dlg, IDC_DATAFORMAT, CB_GETCURSEL, 0, 0));
    job->data = GetDlgText(dlg, IDC_DATA);
    job->hmac = IsChecked(dlg, IDC_HMAC);
    job->keyFormat = static_cast<int>(SendDlgItemMessageW(dlg, IDC_KEYFORMAT, CB_GETCURSEL, 0, 0));
    job->key = GetDlgText(dlg, IDC_KEY);

    bool any = false;
    for (int i = 0; i < kHashAlgCount; ++i)
    {
        job->selected[i] = IsTypeSelected(dlg, i);
        any = any || job->selected[i];
    }

    if (job->dataFormat == DataFile && job->data.empty())
    {
        MessageBoxW(dlg, L"Please select a file.", L"HashCalc", MB_ICONINFORMATION);
        return;
    }
    if (job->dataFormat == DataFile && IsDirectory(job->data))
    {
        ShowFolderHashWindow(dlg, job->data, true);
        return;
    }
    if (!any)
    {
        MessageBoxW(dlg, L"Please select at least one hash algorithm.", L"HashCalc", MB_ICONINFORMATION);
        return;
    }

    g_resultsAreHmac = job->hmac;
    ClearResults(dlg);
    for (int i = 0; i < kHashAlgCount; ++i)
        g_rowDone[i] = false;
    RebuildResultRows(dlg);
    g_job = std::move(job);
    g_cancel = false;
    g_worker = std::thread(WorkerMain, dlg);
    SetTimer(dlg, kProgressTimer, kProgressIntervalMs, nullptr);
    UpdateControlStates(dlg);
    RefreshProgress(dlg);   // show 0% right away
}

// ---------------------------------------------------------------------------
// Single Instance (Settings menu, off by default). A per-session mutex says a
// HashCalc window is open; a new GUI launch then hands its file or folder to
// that window with WM_COPYDATA and exits. The command line is not affected.
// ---------------------------------------------------------------------------
const wchar_t kInstanceMutex[] = L"Local\\HashCalc.SingleInstance";
const wchar_t kInstanceProp[] = L"HashCalc.MainWindow";   // marks our main window
constexpr ULONG_PTR kCopyDataOpen = 0x48435331;            // 'HCS1'
constexpr DWORD kMaxCopyDataBytes = 64 * 1024;

// Takes the single-instance mutex. False if another instance already has it.
bool ClaimSingleInstance()
{
    if (g_instanceMutex)
        return true;
    HANDLE mutex = CreateMutexW(nullptr, FALSE, kInstanceMutex);
    if (!mutex)
        return true;   // cannot tell: just run normally
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        CloseHandle(mutex);
        return false;
    }
    g_instanceMutex = mutex;
    return true;
}

void ReleaseSingleInstance()
{
    if (g_instanceMutex)
    {
        CloseHandle(g_instanceMutex);
        g_instanceMutex = nullptr;
    }
}

BOOL CALLBACK FindInstanceProc(HWND window, LPARAM found)
{
    if (!GetPropW(window, kInstanceProp))
        return TRUE;
    *reinterpret_cast<HWND*>(found) = window;
    return FALSE;
}

// Sends this launch's file/folder (from g_startup) to the running instance.
// True if it accepted; false means: open a window of our own after all.
bool ForwardToRunningInstance()
{
    HWND target = nullptr;
    for (int i = 0; i < 40 && !target; ++i)   // it may still be starting: up to 2 s
    {
        EnumWindows(FindInstanceProc, reinterpret_cast<LPARAM>(&target));
        if (!target)
            Sleep(50);
    }
    if (!target)
        return false;

    // "F<path>" = hash a file, "D<path>" = hash a folder, "" = just show the window
    std::wstring message = !g_startup.folder.empty() ? L"D" + g_startup.folder
                         : !g_startup.file.empty()   ? L"F" + g_startup.file
                         : L"";
    DWORD pid = 0;
    GetWindowThreadProcessId(target, &pid);
    AllowSetForegroundWindow(pid);   // we are in front (just launched); let it come forward

    COPYDATASTRUCT data = { kCopyDataOpen, static_cast<DWORD>((message.size() + 1) * sizeof(wchar_t)),
                            const_cast<wchar_t*>(message.c_str()) };
    DWORD_PTR accepted = 0;
    return SendMessageTimeoutW(target, WM_COPYDATA, 0, reinterpret_cast<LPARAM>(&data),
               SMTO_ABORTIFHUNG, 5000, &accepted) && accepted == 1;
}

// WM_COPYDATA from another instance: check it, then handle it after returning
// (the sender waits for this call, so nothing slow or modal happens here).
bool OnCopyData(HWND dlg, const COPYDATASTRUCT* data)
{
    if (!data || data->dwData != kCopyDataOpen || !data->lpData || data->cbData < sizeof(wchar_t) ||
        data->cbData > kMaxCopyDataBytes || data->cbData % sizeof(wchar_t) != 0)
        return false;
    std::wstring message(static_cast<const wchar_t*>(data->lpData), data->cbData / sizeof(wchar_t));
    message.resize(wcsnlen(message.c_str(), message.size()));   // up to the first NUL
    if (!message.empty() && message[0] != L'F' && message[0] != L'D')
        return false;
    PostMessageW(dlg, WM_APP_OPEN_REQUEST, 0, reinterpret_cast<LPARAM>(new std::wstring(message)));
    return true;
}

// Hashes a file now, or after the running calculation.
void OpenFileRequest(HWND dlg, const std::wstring& path)
{
    if (IsBusy())
    {
        g_pendingFiles.push_back(path);
        return;
    }
    SendDlgItemMessageW(dlg, IDC_DATAFORMAT, CB_SETCURSEL, DataFile, 0);
    SetDlgItemTextW(dlg, IDC_DATA, path.c_str());
    UpdateControlStates(dlg);
    OnCalculate(dlg);
}

void OnOpenRequest(HWND dlg, std::unique_ptr<std::wstring> message)
{
    if (IsIconic(dlg))
        ShowWindow(dlg, SW_RESTORE);
    SetForegroundWindow(dlg);
    if (message->size() < 2)
        return;   // just show the window
    std::wstring path = message->substr(1);
    if ((*message)[0] == L'D')
        ShowFolderHashWindow(dlg, path, true);
    else
        OpenFileRequest(dlg, path);
}

void OnToggleSingleInstance()
{
    Settings settings = LoadSettings();
    settings.singleInstance = !settings.singleInstance;
    SaveSettings(settings);
    if (settings.singleInstance)
        ClaimSingleInstance();
    else
        ReleaseSingleInstance();
}

void OnCalcDone(HWND dlg)
{
    KillTimer(dlg, kProgressTimer);
    if (g_worker.joinable())
        g_worker.join();
    if (!g_pendingFiles.empty())
        PostMessageW(dlg, WM_APP_NEXT_FILE, 0, 0);   // after this result is shown

    std::unique_ptr<CalcJob> job = std::move(g_job);
    bool cancelled = g_userCancelled;
    g_userCancelled = false;
    bool finished[kHashAlgCount];
    for (int i = 0; i < kHashAlgCount; ++i)
    {
        finished[i] = g_rowDone[i];
        g_rowDone[i] = true;
    }
    UpdateControlStates(dlg);
    if (!job)
        return;

    if (cancelled)
    {
        // Keep the hashes that completed, clear the ones that were stopped.
        for (int i = 0; i < kHashAlgCount; ++i)
            if (job->selected[i] && !finished[i])
                SetResult(dlg, i, L"");
        return;
    }

    if (!job->error.empty())
    {
        ClearResults(dlg);
        MessageBoxW(dlg, job->error.c_str(), L"HashCalc", MB_ICONERROR);
        return;
    }
    for (int i = 0; i < kHashAlgCount; ++i)
        if (job->selected[i])
            SetResult(dlg, i, job->tasks[i].result);
}

void OnTaskDone(HWND dlg, int alg)
{
    if (!g_job)
        return;
    g_rowDone[alg] = true;
    SetResult(dlg, alg, g_job->tasks[alg].result);
}

void OnHelp(HWND dlg)
{
    MessageBoxW(dlg,
        L"HashCalc " VERSION_STR L"\n\n"
        L"1. Enter the data, browse with \"...\" or drop a file on the window.\n"
        L"2. The data format follows the input: a path selects File, other text selects "
        L"Text string (UTF-8). Choose Hex string yourself for hex input.\n"
        L"3. Optionally enable HMAC and enter a key.\n"
        L"4. Tick the algorithms you need (\"All\" toggles every one) and press Calculate. "
        L"While it runs, the same button cancels.\n\n"
        L"File > Reset (Ctrl+R) clears everything and restores the default settings.\n\n"
        L"Each algorithm runs on its own thread; the bar under each result shows its progress. "
        L"Each ticked type gets a row in the list. Click the copy icon (or double-click the row, or "
        L"press Ctrl+C) to copy it; \"Copy All\" copies every result. The shield (MD5, SHA1 and SHA256) "
        L"looks the hash up on VirusTotal in your browser. Right-click a row for the same options.\n\n"
        L"View > PE & Similarity Hashes adds Imphash, Authentihash and RichHash (for Windows programs) "
        L"and the similarity hashes ssdeep and TLSH.\n\n"
        L"File > Hash Folder (or dropping a folder on the window) hashes every file in a folder "
        L"with the algorithms ticked here, and can export the results as CSV or a checksum file.\n\n"
        L"Settings > Add to Explorer Context Menu adds \"Calculate hash with HashCalc\" for files "
        L"and \"Hash folder with HashCalc\" for folders. On Windows 11 they are under \"Show more options\".\n\n"
        L"Command line: run \"HashCalc -h\" in a console for all options. "
        L"Settings > Add to PATH lets you type \"hashcalc\" in any new console window.\n\n"
        L"Settings > Single Instance (off by default) keeps one window: opening HashCalc again, or "
        L"right-clicking a file, uses the window that is already open.",
        L"HashCalc Help", MB_ICONINFORMATION);
}

// TaskDialog instead of MessageBox so the repository link is clickable
HRESULT CALLBACK AboutCallback(HWND hwnd, UINT msg, WPARAM, LPARAM lParam, LONG_PTR)
{
    if (msg == TDN_HYPERLINK_CLICKED)
        ShellExecuteW(hwnd, L"open", reinterpret_cast<LPCWSTR>(lParam), nullptr, nullptr, SW_SHOWNORMAL);
    return S_OK;
}

void OnAbout(HWND dlg)
{
    const std::wstring content =
        L"File, folder and text hash calculator.\n\n"
        L"Algorithms: MD2, MD4, MD5, SHA1, SHA256, SHA384, SHA512, RIPEMD160, "
        L"PANAMA, TIGER, ADLER32, CRC32 and eDonkey/eMule, with optional HMAC.\n\n"
        L"<a href=\"" + std::wstring(kRepoUrl) + L"\">" + kRepoUrl + L"</a>";

    TASKDIALOGCONFIG config = { sizeof(config) };
    config.hwndParent = dlg;
    config.dwFlags = TDF_ENABLE_HYPERLINKS | TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW;
    config.dwCommonButtons = TDCBF_OK_BUTTON;
    config.pszWindowTitle = L"About HashCalc";
    config.pszMainIcon = TD_INFORMATION_ICON;
    config.pszMainInstruction = L"HashCalc " VERSION_STR;
    config.pszContent = content.c_str();
    config.pfCallback = AboutCallback;
    TaskDialogIndirect(&config, nullptr, nullptr, nullptr);
}

void OnToggleShellIntegration(HWND dlg)
{
    if (IsShellIntegrationInstalled())
    {
        if (!RemoveShellIntegration())
            MessageBoxW(dlg, L"Could not remove the Explorer context menu entries.", L"HashCalc", MB_ICONERROR);
        return;
    }
    if (!InstallShellIntegration())
    {
        MessageBoxW(dlg, L"Could not add the Explorer context menu entries.", L"HashCalc", MB_ICONERROR);
        return;
    }
    MessageBoxW(dlg,
        L"Added to the Explorer context menu:\n\n"
        L"  \x2022 Files: \"Calculate hash with HashCalc\"\n"
        L"  \x2022 Folders: \"Hash folder with HashCalc\"\n\n"
        L"On Windows 11 these entries are under \"Show more options\" (Shift+F10).\n"
        L"The entries point to this copy of HashCalc; if you move it, add them again.",
        L"HashCalc", MB_ICONINFORMATION);
}

bool IsAlwaysOnTop(HWND dlg)
{
    return (GetWindowLongPtrW(dlg, GWL_EXSTYLE) & WS_EX_TOPMOST) != 0;
}

void ApplyAlwaysOnTop(HWND dlg, bool on)
{
    SetWindowPos(dlg, on ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    CheckMenuItem(GetSystemMenu(dlg, FALSE), kSysCmdTopmost, MF_BYCOMMAND | (on ? MF_CHECKED : MF_UNCHECKED));
}

void OnToggleAlwaysOnTop(HWND dlg)
{
    bool on = !IsAlwaysOnTop(dlg);
    ApplyAlwaysOnTop(dlg, on);
    Settings settings = LoadSettings();
    settings.alwaysOnTop = on;
    SaveSettings(settings);
}

// File > Reset: back to the state of a first start - empty input, default
// algorithm (SHA256), designed window size, not on top, default saved settings.
// The Explorer context menu is a separate choice and is left as it is.
void OnReset(HWND dlg)
{
    if (IsBusy())
        return;

    SendDlgItemMessageW(dlg, IDC_DATAFORMAT, CB_SETCURSEL, DataFile, 0);
    SetDlgItemTextW(dlg, IDC_DATA, L"");
    CheckDlgButton(dlg, IDC_HMAC, BST_UNCHECKED);
    SendDlgItemMessageW(dlg, IDC_KEYFORMAT, CB_SETCURSEL, KeyHex, 0);
    SetDlgItemTextW(dlg, IDC_KEY, L"");

    Settings defaults;
    defaults.pathFolder = LoadSettings().pathFolder;   // Add to PATH is kept, like the Explorer menu
    for (int i = 0; i < kHashAlgCount; ++i)
        CheckDlgButton(dlg, IDC_CHK_BASE + i, (defaults.algorithms >> i) & 1 ? BST_CHECKED : BST_UNCHECKED);
    ClearResults(dlg);

    SIZE size = g_layout.InitialWindowSize();
    SetWindowPos(dlg, nullptr, 0, 0, size.cx, size.cy, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
    ApplyAlwaysOnTop(dlg, false);

    SaveSettings(defaults);
    ReleaseSingleInstance();   // Single Instance is off by default
    g_pendingFiles.clear();
    g_showExtended = false;    // PE & similarity hashes are hidden by default
    ApplyExtendedView(dlg, false);
    UpdateControlStates(dlg);
    RebuildResultRows(dlg);
}

// Default folder for Add to PATH: %LOCALAPPDATA%\Programs\HashCalc, which only
// this user (and administrators) can write to. A shared folder such as C:\tools
// lets other users replace HashCalc.exe or plant DLLs next to it.
std::wstring DefaultPathFolder()
{
    std::wstring folder;
    PWSTR programs = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_UserProgramFiles, 0, nullptr, &programs)))
        folder = programs;
    CoTaskMemFree(programs);
    if (folder.empty())
    {
        wchar_t expanded[MAX_PATH];
        if (ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\Programs", expanded, ARRAYSIZE(expanded)))
            folder = expanded;
    }
    return folder + L"\\HashCalc";
}

// True if a broad group (Everyone, Authenticated Users, Users, Interactive)
// may create files in the folder or change the files in it.
bool IsWritableByOthers(const std::wstring& folder)
{
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetNamedSecurityInfoW(folder.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &dacl, nullptr, &sd) != ERROR_SUCCESS)
        return false;

    BYTE sids[4][SECURITY_MAX_SID_SIZE];
    const WELL_KNOWN_SID_TYPE broad[4] = { WinWorldSid, WinAuthenticatedUserSid, WinBuiltinUsersSid, WinInteractiveSid };
    for (int i = 0; i < 4; ++i)
    {
        DWORD size = SECURITY_MAX_SID_SIZE;
        CreateWellKnownSid(broad[i], nullptr, sids[i], &size);
    }

    bool writable = dacl == nullptr;   // no DACL: everyone has full access
    const DWORD anyWrite = GENERIC_WRITE | GENERIC_ALL | WRITE_DAC | WRITE_OWNER;
    for (DWORD i = 0; dacl && i < dacl->AceCount && !writable; ++i)
    {
        ACE_HEADER* header = nullptr;
        if (!GetAce(dacl, i, reinterpret_cast<void**>(&header)) || header->AceType != ACCESS_ALLOWED_ACE_TYPE)
            continue;
        auto* ace = reinterpret_cast<ACCESS_ALLOWED_ACE*>(header);
        PSID sid = &ace->SidStart;
        bool broadSid = false;
        for (auto& s : sids)
            broadSid = broadSid || EqualSid(sid, s);
        if (!broadSid)
            continue;
        bool forFolder = !(header->AceFlags & INHERIT_ONLY_ACE);
        bool forFiles = (header->AceFlags & OBJECT_INHERIT_ACE) != 0;
        if (forFolder && (ace->Mask & (FILE_ADD_FILE | anyWrite)))
            writable = true;
        if (forFiles && (ace->Mask & (FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE | anyWrite)))
            writable = true;
    }
    LocalFree(sd);
    return writable;
}

bool IsOnPath()
{
    return IsFolderInUserPath(LoadSettings().pathFolder);
}

// "Add HashCalc to PATH" window: asks for the folder to copy HashCalc.exe to.
// lParam points to the folder string (initial value in, chosen folder out).
INT_PTR CALLBACK PathSetupProc(HWND dlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_INITDIALOG:
        SetWindowLongPtrW(dlg, GWLP_USERDATA, lParam);
        SetDlgItemTextW(dlg, IDC_P_FOLDER, reinterpret_cast<std::wstring*>(lParam)->c_str());
        return TRUE;

    case WM_COMMAND:
    {
        auto* folder = reinterpret_cast<std::wstring*>(GetWindowLongPtrW(dlg, GWLP_USERDATA));
        switch (LOWORD(wParam))
        {
        case IDC_P_BROWSE:
        {
            std::wstring current = GetDlgText(dlg, IDC_P_FOLDER);
            if (BrowseForFolder(dlg, current, L"Folder for HashCalc.exe"))
                SetDlgItemTextW(dlg, IDC_P_FOLDER, current.c_str());
            return TRUE;
        }
        case IDOK:
        {
            std::wstring text = GetDlgText(dlg, IDC_P_FOLDER);
            size_t first = text.find_first_not_of(L" \t\"");
            size_t last = text.find_last_not_of(L" \t\"");
            text = first == std::wstring::npos ? L"" : text.substr(first, last - first + 1);
            while (text.size() > 3 && (text.back() == L'\\' || text.back() == L'/'))
                text.pop_back();
            if (text.empty() || PathIsRelativeW(text.c_str()))
            {
                MessageBoxW(dlg, L"Please enter a full folder path that starts with a drive letter.",
                    L"Add HashCalc to PATH", MB_ICONINFORMATION);
                return TRUE;
            }
            *folder = text;
            EndDialog(dlg, IDOK);
            return TRUE;
        }
        case IDCANCEL:
            EndDialog(dlg, IDCANCEL);
            return TRUE;
        }
        break;
    }
    }
    return FALSE;
}

// Copies this exe to <folder>\HashCalc.exe and puts the folder on the user PATH.
void AddToPath(HWND dlg)
{
    Settings settings = LoadSettings();
    std::wstring folder = settings.pathFolder.empty() ? DefaultPathFolder() : settings.pathFolder;
    if (DialogBoxParamW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDD_PATHSETUP), dlg, PathSetupProc,
            reinterpret_cast<LPARAM>(&folder)) != IDOK)
        return;

    int created = SHCreateDirectoryExW(nullptr, folder.c_str(), nullptr);   // no shell error UI
    if (created != ERROR_SUCCESS && created != ERROR_ALREADY_EXISTS && created != ERROR_FILE_EXISTS)
    {
        MessageBoxW(dlg, (L"Cannot create the folder:\n" + folder + L"\n\n" + ErrorMessage(created)).c_str(),
            L"HashCalc", MB_ICONERROR);
        return;
    }

    if (IsWritableByOthers(folder) &&
        MessageBoxW(dlg, (L"Other users of this PC can add or change files in:\n" + folder + L"\n\n"
            L"They could replace HashCalc.exe, or put a harmful DLL next to it, and that code would then "
            L"run every time you type \"hashcalc\".\n\n"
            L"Recommended: " + DefaultPathFolder() + L" (only you can change it).\n\n"
            L"Use this folder anyway?").c_str(),
            L"HashCalc", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
    {
        if (created == ERROR_SUCCESS)
            RemoveDirectoryW(folder.c_str());   // only removes it if still empty
        return;
    }

    std::wstring source = ExePath();
    std::wstring target = folder + L"\\HashCalc.exe";
    if (_wcsicmp(source.c_str(), target.c_str()) != 0 && !CopyFileW(source.c_str(), target.c_str(), FALSE))
    {
        MessageBoxW(dlg, (L"Cannot copy HashCalc.exe to:\n" + target + L"\n\n" + ErrorMessage(GetLastError()) +
            L"\n\nIf HashCalc is running from there, close it first, or choose another folder.").c_str(),
            L"HashCalc", MB_ICONERROR);
        return;
    }

    if (!AddFolderToUserPath(folder))
    {
        MessageBoxW(dlg, L"Could not add the folder to your PATH.", L"HashCalc", MB_ICONERROR);
        return;
    }
    settings.pathFolder = folder;
    SaveSettings(settings);

    MessageBoxW(dlg, (L"HashCalc.exe was copied to " + folder + L" and the folder was added to your PATH.\n\n"
        L"Open a new Command Prompt or PowerShell window and type:\n\n"
        L"    hashcalc -h\n\n"
        L"Windows that are already open keep the old PATH. To update the command after a new "
        L"version, use this menu again (remove, then add).").c_str(),
        L"HashCalc", MB_ICONINFORMATION);
}

void RemoveFromPath(HWND dlg)
{
    Settings settings = LoadSettings();
    std::wstring folder = settings.pathFolder;
    if (MessageBoxW(dlg, (L"Remove " + folder + L" from your PATH?\n\n"
            L"The \"hashcalc\" command will stop working in new console windows.").c_str(),
            L"HashCalc", MB_OKCANCEL | MB_ICONQUESTION) != IDOK)
        return;

    if (!RemoveFolderFromUserPath(folder))
    {
        MessageBoxW(dlg, L"Could not remove the folder from your PATH.", L"HashCalc", MB_ICONERROR);
        return;
    }
    settings.pathFolder.clear();
    SaveSettings(settings);

    // The folder itself is kept: it may hold other tools.
    std::wstring copy = folder + L"\\HashCalc.exe";
    if (GetFileAttributesW(copy.c_str()) != INVALID_FILE_ATTRIBUTES &&
        _wcsicmp(copy.c_str(), ExePath().c_str()) != 0 &&
        MessageBoxW(dlg, (L"Also delete the copy " + copy + L"?").c_str(), L"HashCalc",
            MB_YESNO | MB_ICONQUESTION) == IDYES &&
        !DeleteFileW(copy.c_str()))
    {
        MessageBoxW(dlg, (L"Cannot delete " + copy + L"\n\n" + ErrorMessage(GetLastError())).c_str(),
            L"HashCalc", MB_ICONERROR);
    }
}

// Settings > Add to PATH: copy HashCalc.exe to a tools folder (C:\tools by
// default) on the user PATH, so "hashcalc" works in any new console window.
void OnTogglePath(HWND dlg)
{
    if (IsOnPath())
        RemoveFromPath(dlg);
    else
        AddToPath(dlg);
}

void OnInitMenuPopup(HWND dlg, HMENU menu)
{
    EnableMenuItem(menu, IDM_FILE_RESET, MF_BYCOMMAND | (IsBusy() ? MF_GRAYED : MF_ENABLED));
    CheckMenuItem(menu, IDM_SETTINGS_PATH, MF_BYCOMMAND | (IsOnPath() ? MF_CHECKED : MF_UNCHECKED));
    CheckMenuItem(menu, IDM_SETTINGS_TOPMOST, MF_BYCOMMAND | (IsAlwaysOnTop(dlg) ? MF_CHECKED : MF_UNCHECKED));
    CheckMenuItem(menu, IDM_SETTINGS_SINGLE, MF_BYCOMMAND | (LoadSettings().singleInstance ? MF_CHECKED : MF_UNCHECKED));
    CheckMenuItem(menu, IDM_VIEW_EXTENDED, MF_BYCOMMAND | (g_showExtended ? MF_CHECKED : MF_UNCHECKED));
    EnableMenuItem(menu, IDM_VIEW_EXTENDED, MF_BYCOMMAND | (IsBusy() ? MF_GRAYED : MF_ENABLED));
    CheckMenuItem(menu, IDM_SETTINGS_SHELL, MF_BYCOMMAND |
        (IsShellIntegrationInstalled() ? MF_CHECKED : MF_UNCHECKED));
    EnableMenuItem(menu, IDM_FILE_OPEN, MF_BYCOMMAND | (IsBusy() ? MF_GRAYED : MF_ENABLED));
}

DWORD CheckedAlgorithms(HWND dlg)
{
    DWORD mask = 0;
    for (int i = 0; i < kHashAlgCount; ++i)
        if (IsChecked(dlg, IDC_CHK_BASE + i))
            mask |= 1u << i;
    return mask;
}

void SaveMainSettings(HWND dlg)
{
    Settings settings = LoadSettings();
    settings.algorithms = CheckedAlgorithms(dlg);
    SaveSettings(settings);
}

// Resizing: the inputs and the results list widen; the list also grows in
// height; the buttons stay at the right / bottom edge.
void InitLayout(HWND dlg)
{
    using A = AnchorLayout;
    g_layout.Add(IDC_DATA, A::GrowX);
    g_layout.Add(IDC_BROWSE, A::MoveX);
    g_layout.Add(IDC_KEY, A::GrowX);
    g_layout.Add(IDC_SEP_TOP, A::GrowX);
    g_layout.Add(IDC_COPY_ALL, A::MoveX);
    g_layout.Add(IDC_RESULTS, A::GrowX | A::GrowY);
    g_layout.Add(IDC_LOGO, A::MoveY);
    g_layout.Add(IDC_CALCULATE, A::MoveX | A::MoveY);
    g_layout.Add(IDCANCEL, A::MoveX | A::MoveY);
    g_layout.Add(IDC_HELPBTN, A::MoveX | A::MoveY);
    g_layout.Capture(dlg);
}

void OnInitDialog(HWND dlg)
{
    g_dlg = dlg;
    SetPropW(dlg, kInstanceProp, reinterpret_cast<HANDLE>(1));   // found by Single Instance launches
    SetWindowTextW(dlg, L"HashCalc " VERSION_STR);

    HINSTANCE instance = GetModuleHandleW(nullptr);
    HICON bigIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_APP));
    HICON smallIcon = static_cast<HICON>(LoadImageW(instance, MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0));
    SendMessageW(dlg, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(bigIcon));
    SendMessageW(dlg, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(smallIcon));

    HWND fmt = GetDlgItem(dlg, IDC_DATAFORMAT);
    SendMessageW(fmt, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"File"));
    SendMessageW(fmt, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Text string"));
    SendMessageW(fmt, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Hex string"));
    SendMessageW(fmt, CB_SETCURSEL, DataFile, 0);

    HWND keyFmt = GetDlgItem(dlg, IDC_KEYFORMAT);
    SendMessageW(keyFmt, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Text string"));
    SendMessageW(keyFmt, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Hex string"));
    SendMessageW(keyFmt, CB_SETCURSEL, KeyHex, 0);

    // Remembered algorithm selection (also used by Explorer launches)
    const Settings settings = LoadSettings();
    DWORD algorithms = settings.algorithms;
    g_showExtended = settings.showExtended;
    for (int i = 0; i < kHashAlgCount; ++i)
        CheckDlgButton(dlg, IDC_CHK_BASE + i, (algorithms >> i) & 1 ? BST_CHECKED : BST_UNCHECKED);

    // Bold italic underlined "logo" text, as in the original layout
    HFONT dlgFont = reinterpret_cast<HFONT>(SendMessageW(dlg, WM_GETFONT, 0, 0));
    LOGFONTW lf = {};
    GetObjectW(dlgFont, sizeof(lf), &lf);
    lf.lfWeight = FW_BOLD;
    lf.lfItalic = TRUE;
    lf.lfUnderline = TRUE;
    g_logoFont = CreateFontIndirectW(&lf);
    SendDlgItemMessageW(dlg, IDC_LOGO, WM_SETFONT, reinterpret_cast<WPARAM>(g_logoFont), FALSE);

    // "Always on Top" and "About HashCalc..." in the system (control) menu
    HMENU systemMenu = GetSystemMenu(dlg, FALSE);
    AppendMenuW(systemMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(systemMenu, MF_STRING, kSysCmdTopmost, L"Always on &Top");
    AppendMenuW(systemMenu, MF_STRING, kSysCmdAbout, L"&About HashCalc...");
    if (LoadSettings().alwaysOnTop)
        ApplyAlwaysOnTop(dlg, true);

    InitResultList(dlg);
    InitLayout(dlg);
    ApplyExtendedView(dlg, g_showExtended);
    UpdateControlStates(dlg);
    RebuildResultRows(dlg);

    if (!g_startup.file.empty())
    {
        SetDlgItemTextW(dlg, IDC_DATA, g_startup.file.c_str());
        PostMessageW(dlg, WM_COMMAND, IDC_CALCULATE, 0);
    }
    if (!g_startup.folder.empty())
        PostMessageW(dlg, WM_APP_OPEN_FOLDER, 0, 0);
}

void OnClose(HWND dlg)
{
    KillTimer(dlg, kProgressTimer);
    StopWorker();
    SaveMainSettings(dlg);
    DestroyWindow(dlg);
}

INT_PTR CALLBACK DialogProc(HWND dlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_INITDIALOG:
        OnInitDialog(dlg);
        return TRUE;

    case WM_COMMAND:
    {
        int id = LOWORD(wParam);
        if (id >= IDC_CHK_BASE && id < IDC_CHK_BASE + kHashAlgCount)
        {
            UpdateAllCheckbox(dlg);
            RebuildResultRows(dlg);
            return TRUE;
        }
        switch (id)
        {
        case IDC_CHK_ALL:
            OnCheckAll(dlg);
            return TRUE;
        case IDC_COPY_ALL:
        case IDM_FILE_COPYALL:
            OnCopyAll(dlg);
            return TRUE;
        case IDC_CALCULATE:
            OnCalculate(dlg);
            return TRUE;
        case IDC_BROWSE:
            OnBrowse(dlg);
            return TRUE;
        case IDM_FILE_OPEN:
            if (!IsBusy() && OnBrowse(dlg))
                OnCalculate(dlg);
            return TRUE;
        case IDM_FILE_FOLDER:
            ShowFolderHashWindow(dlg, L"", false);
            return TRUE;
        case IDM_FILE_RESET:
            OnReset(dlg);
            return TRUE;
        case IDM_SETTINGS_SHELL:
            OnToggleShellIntegration(dlg);
            return TRUE;
        case IDM_SETTINGS_SINGLE:
            OnToggleSingleInstance();
            return TRUE;
        case IDM_SETTINGS_TOPMOST:
            OnToggleAlwaysOnTop(dlg);
            return TRUE;
        case IDM_SETTINGS_PATH:
            OnTogglePath(dlg);
            return TRUE;
        case IDC_HELPBTN:
        case IDM_HELP_HELP:
            OnHelp(dlg);
            return TRUE;
        case IDM_HELP_ABOUT:
            OnAbout(dlg);
            return TRUE;
        case IDC_HMAC:
            UpdateControlStates(dlg);
            RebuildResultRows(dlg);
            return TRUE;
        case IDM_VIEW_EXTENDED:
            OnToggleExtended(dlg);
            return TRUE;
        case IDC_DATAFORMAT:
            if (HIWORD(wParam) == CBN_SELCHANGE)
                UpdateControlStates(dlg);
            return TRUE;
        case IDC_DATA:
            if (HIWORD(wParam) == EN_CHANGE)
                OnDataChanged(dlg);
            return TRUE;
        case IDM_FILE_EXIT:
        case IDCANCEL:
            OnClose(dlg);
            return TRUE;
        }
        break;
    }

    case WM_SYSCOMMAND:
        if ((wParam & 0xFFF0) == kSysCmdAbout)
        {
            OnAbout(dlg);
            return TRUE;
        }
        if ((wParam & 0xFFF0) == kSysCmdTopmost)
        {
            OnToggleAlwaysOnTop(dlg);
            return TRUE;
        }
        return FALSE;

    case WM_NCHITTEST:
        // Background and labels drag the window like the title bar.
        return DragAnywhereHitTest(dlg, wParam, lParam);

    case WM_NOTIFY:
    {
        auto* header = reinterpret_cast<NMHDR*>(lParam);
        LRESULT result = 0;
        if (header->idFrom == IDC_RESULTS && OnResultsNotify(dlg, header, &result))
        {
            SetWindowLongPtrW(dlg, DWLP_MSGRESULT, result);
            return TRUE;
        }
        return FALSE;
    }

    case WM_CONTEXTMENU:
        if (reinterpret_cast<HWND>(wParam) == ResultList(dlg))
        {
            POINT pt = { GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            int alg = -1;
            if (pt.x == -1 && pt.y == -1)   // keyboard (Shift+F10 / menu key)
            {
                alg = SelectedRowAlg(dlg);
                RECT r;
                GetWindowRect(ResultList(dlg), &r);
                pt = { r.left + 8, r.top + 8 };
            }
            else
            {
                LVHITTESTINFO hit = {};
                hit.pt = pt;
                ScreenToClient(ResultList(dlg), &hit.pt);
                int row = ListView_HitTest(ResultList(dlg), &hit);
                if (row >= 0 && row < static_cast<int>(g_rows.size()))
                {
                    alg = g_rows[row];
                    ListView_SetItemState(ResultList(dlg), row, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                }
            }
            ShowResultMenu(dlg, alg, pt);
            return TRUE;
        }
        return FALSE;

    case WM_INITMENUPOPUP:
        OnInitMenuPopup(dlg, reinterpret_cast<HMENU>(wParam));
        return TRUE;

    case WM_SIZE:
        if (wParam != SIZE_MINIMIZED && !g_layoutPaused)
        {
            g_layout.Apply(LOWORD(lParam), HIWORD(lParam));
            SizeResultColumns(dlg);
        }
        return TRUE;

    case WM_GETMINMAXINFO:
    {
        // At least the designed size; wider and taller make the list bigger.
        SIZE initial = g_layout.InitialWindowSize();
        if (initial.cx && !g_layoutPaused)
            reinterpret_cast<MINMAXINFO*>(lParam)->ptMinTrackSize = { initial.cx, initial.cy };
        return TRUE;
    }

    case WM_TIMER:
        if (wParam == kProgressTimer)
            RefreshProgress(dlg);
        else if (wParam == kCopyAllTimer)
        {
            KillTimer(dlg, wParam);
            SetDlgItemTextW(dlg, IDC_COPY_ALL, L"Copy All");
        }
        else if (wParam == kCopyRowTimer)
        {
            KillTimer(dlg, wParam);
            int alg = g_copiedAlg;
            g_copiedAlg = -1;
            if (alg >= 0)
                RedrawRow(dlg, alg);
        }
        return TRUE;

    case WM_DROPFILES:
        OnDropFiles(dlg, reinterpret_cast<HDROP>(wParam));
        return TRUE;

    case WM_APP_TASK_DONE:
        OnTaskDone(dlg, static_cast<int>(wParam));
        return TRUE;

    case WM_APP_CALC_DONE:
        OnCalcDone(dlg);
        return TRUE;

    case WM_APP_OPEN_FOLDER:
        ShowFolderHashWindow(dlg, g_startup.folder, true);
        return TRUE;

    case WM_COPYDATA:
        SetWindowLongPtrW(dlg, DWLP_MSGRESULT,
            OnCopyData(dlg, reinterpret_cast<const COPYDATASTRUCT*>(lParam)) ? 1 : 0);
        return TRUE;

    case WM_APP_OPEN_REQUEST:
        OnOpenRequest(dlg, std::unique_ptr<std::wstring>(reinterpret_cast<std::wstring*>(lParam)));
        return TRUE;

    case WM_APP_NEXT_FILE:
        if (!IsBusy() && !g_pendingFiles.empty())
        {
            std::wstring next = std::move(g_pendingFiles.front());
            g_pendingFiles.pop_front();
            OpenFileRequest(dlg, next);
        }
        return TRUE;

    case WM_DESTROY:
        RemovePropW(dlg, kInstanceProp);
        ReleaseSingleInstance();
        for (HFONT* font : { &g_logoFont, &g_iconFont })
        {
            if (*font)
            {
                DeleteObject(*font);
                *font = nullptr;
            }
        }
        PostQuitMessage(0);
        break;
    }
    return FALSE;
}

bool IsGuiSwitch(const wchar_t* arg)
{
    return _wcsicmp(arg, L"-gui") == 0 || _wcsicmp(arg, L"/gui") == 0;
}

// GUI arguments (from Explorer, the context menu or "HashCalc -gui ..."):
// HashCalc.exe <file>            hash the file in the main window
// HashCalc.exe <folder>          open the folder window and hash the folder
// HashCalc.exe /folder <folder>  same (used by the Explorer context menu)
void ParseStartupArgs(int argc, wchar_t** argv)
{
    int first = argc >= 2 && IsGuiSwitch(argv[1]) ? 2 : 1;
    if (argc >= first + 2 && _wcsicmp(argv[first], L"/folder") == 0)
        g_startup.folder = argv[first + 1];
    else if (argc >= first + 1)
    {
        if (IsDirectory(argv[first]))
            g_startup.folder = argv[first];
        else
            g_startup.file = argv[first];
    }
}

// Starts another instance without a console, so the GUI does not keep the
// console prompt waiting.
bool RelaunchDetached(int argc, wchar_t** argv, int firstArg)
{
    std::wstring command = L"\"" + ExePath() + L"\" -gui";
    for (int i = firstArg; i < argc; ++i)
    {
        std::wstring arg = argv[i];
        if (!arg.empty() && arg.back() == L'\\')
            arg += L'\\';   // keep a trailing backslash from escaping the closing quote
        command += L" \"" + arg + L"\"";
    }
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, DETACHED_PROCESS,
            nullptr, nullptr, &si, &pi))
        return false;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

int RunGui(int argc, wchar_t** argv)
{
    ParseStartupArgs(argc, argv);

    // Single Instance: hand this launch to the open window instead.
    if (LoadSettings().singleInstance && !ClaimSingleInstance() && ForwardToRunningInstance())
        return 0;

    HINSTANCE instance = GetModuleHandleW(nullptr);
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES | ICC_BAR_CLASSES | ICC_PROGRESS_CLASS | ICC_LISTVIEW_CLASSES };
    InitCommonControlsEx(&icc);

    HWND dlg = CreateDialogParamW(instance, MAKEINTRESOURCEW(IDD_HASHCALC), nullptr, DialogProc, 0);
    if (!dlg)
        return 1;
    STARTUPINFOW si = { sizeof(si) };
    GetStartupInfoW(&si);
    ShowWindow(dlg, (si.dwFlags & STARTF_USESHOWWINDOW) ? si.wShowWindow : SW_SHOWDEFAULT);

    // Modeless main window + folder window: route keyboard input to the right one.
    HACCEL accel = LoadAcceleratorsW(instance, MAKEINTRESOURCEW(IDR_ACCEL));
    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0) > 0)
    {
        HWND folder = FolderHashWindow();
        if (folder && (msg.hwnd == folder || IsChild(folder, msg.hwnd)) && IsDialogMessageW(folder, &msg))
            continue;
        if ((msg.hwnd == g_dlg || IsChild(g_dlg, msg.hwnd)) && TranslateAcceleratorW(g_dlg, accel, &msg))
            continue;
        if (g_dlg && IsDialogMessageW(g_dlg, &msg))
            continue;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    CoUninitialize();
    return static_cast<int>(msg.wParam);
}

} // namespace

// Implemented for FolderHash.cpp: the current selection of the main window.
bool GetMainHashOptions(HashOptions& options, std::wstring& error)
{
    HWND dlg = g_dlg;
    options = HashOptions();
    options.hmac = IsChecked(dlg, IDC_HMAC);
    if (options.hmac)
    {
        std::wstring key = GetDlgText(dlg, IDC_KEY);
        bool hexKey = SendDlgItemMessageW(dlg, IDC_KEYFORMAT, CB_GETCURSEL, 0, 0) == KeyHex;
        if (!hexKey)
            options.key = ToUtf8(key);
        else if (!ParseHex(key, options.key))
        {
            error = L"The HMAC key in the main window is not a valid hex string.";
            return false;
        }
    }

    bool any = false;
    for (int i = 0; i < kHashAlgCount; ++i)
    {
        // Not IsWindowEnabled: the checkboxes are disabled while the main window calculates.
        bool usable = (!options.hmac || SupportsHmac(static_cast<HashAlg>(i))) && IsVisibleType(i);
        options.selected[i] = usable && IsChecked(dlg, IDC_CHK_BASE + i);
        any = any || options.selected[i];
    }
    if (!any)
    {
        error = L"Please tick at least one hash algorithm in the main window.";
        return false;
    }
    return true;
}

// One executable for both the GUI and the command line. It is a console
// program whose manifest asks Windows 11 24H2+ not to create a console when
// started outside one (consoleAllocationPolicy = detached, see HashCalc.manifest):
//  - started from cmd/PowerShell/Terminal: command line mode; the shell waits
//    for it, so pipes, redirection and exit codes work
//  - started from Explorer, a shortcut or the context menu: the GUI
int wmain(int argc, wchar_t** argv)
{
    // First of all: load DLLs only from System32, never from the folder HashCalc
    // runs from (e.g. Downloads), so a planted DLL there cannot be loaded.
    // bcrypt.dll is delay-loaded (see Common.props) and so is covered too.
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);

    // Processes attached to our console: 0 = none (detached), 1 = a console
    // created just for us (older Windows that ignore the manifest policy, or
    // "start HashCalc"), 2+ = started from a shell. Not GetConsoleWindow():
    // consoles can exist without a window (e.g. scripts run hidden).
    DWORD processes[4];
    DWORD attached = GetConsoleProcessList(processes, ARRAYSIZE(processes));
    bool ownConsole = attached == 1;
    bool fromConsole = attached > 1;
    bool guiSwitch = argc >= 2 && IsGuiSwitch(argv[1]);

    if (fromConsole)
    {
        if (argc >= 2 && !guiSwitch)
            return RunCli(argc, argv);
        // "HashCalc" or "HashCalc -gui [file|folder]": open the GUI in its own
        // process so the prompt comes back right away.
        if (RelaunchDetached(argc, argv, guiSwitch ? 2 : 1))
            return 0;
    }
    else if (!guiSwitch && IsCliInvocation(argc, argv))
    {
        // Options without an interactive console, e.g. output redirected by a script.
        return RunCli(argc, argv);
    }

    if (ownConsole)
    {
        if (HWND console = GetConsoleWindow())
            ShowWindow(console, SW_HIDE);
        FreeConsole();
    }
    return RunGui(argc, argv);
}
