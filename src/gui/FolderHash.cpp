#include "gui/FolderHash.h"

#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <shlwapi.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
#include <exception>
#include <memory>
#include <thread>

#include "common/Util.h"
#include "core/FileHash.h"
#include "gui/Settings.h"
#include "resource.h"

namespace {

constexpr UINT WM_APP_SCANNED = WM_APP + 10;
constexpr UINT WM_APP_FOLDER_DONE = WM_APP + 11;
constexpr UINT_PTR kRefreshTimer = 1;
constexpr UINT_PTR kCopyTimer = 2;
constexpr UINT kRefreshMs = 200;
constexpr UINT kCopyFeedbackMs = 1000;
constexpr int kProgressRange = 1000;
constexpr DWORD kReadChunkSize = 1 << 20;
constexpr unsigned kMaxThreads = 8;

// Hex digits per algorithm, used for column widths.
constexpr int kHexLength[kHashAlgCount] = { 32, 32, 40, 64, 96, 128, 40, 64, 48, 32, 8, 8, 32 };

enum class FileState { Pending, Done, Failed };

struct FileEntry
{
    FileEntry(std::wstring path, uint64_t bytes) : relPath(std::move(path)), size(bytes) {}

    std::wstring relPath;
    uint64_t size;
    std::wstring results[kHashAlgCount];   // written by a worker before state is set
    std::wstring error;
    std::atomic<FileState> state{ FileState::Pending };
};

struct FolderJob
{
    std::wstring root;                     // without trailing backslash
    bool recurse = true;
    HashOptions options;

    std::deque<FileEntry> files;           // fixed once scanning is done
    uint64_t totalBytes = 0;

    std::atomic<bool> cancel{ false };
    std::atomic<bool> scanDone{ false };
    std::atomic<size_t> scanned{ 0 };
    std::atomic<size_t> nextFile{ 0 };
    std::atomic<size_t> finished{ 0 };
    std::atomic<size_t> failed{ 0 };
    std::atomic<uint64_t> bytesDone{ 0 };
    std::wstring error;                    // fatal error, e.g. folder not found
    double seconds = 0;
};

struct FolderWindow
{
    HWND dlg = nullptr;
    std::wstring initialFolder;
    bool autoStart = false;

    std::unique_ptr<FolderJob> job;        // current or last run
    std::thread worker;
    std::vector<int> columns;              // algorithm shown in each hash column

    AnchorLayout layout;
};

FolderWindow* g_folder = nullptr;

// ---------------------------------------------------------------------------
// Worker threads
// ---------------------------------------------------------------------------
void HashOneFile(FolderJob& job, FileEntry& entry, std::vector<BYTE>& buffer)
{
    FileHashResult result;
    bool ok = HashFile(job.root + L"\\" + entry.relPath, job.options, result, buffer, &job.cancel, &job.bytesDone);
    if (job.cancel)
        return; // left as pending

    // Keep the overall progress consistent when a file was skipped or shrank.
    if (result.bytesRead < entry.size)
        job.bytesDone += entry.size - result.bytesRead;

    if (ok)
    {
        for (int i = 0; i < kHashAlgCount; ++i)
            entry.results[i] = std::move(result.hashes[i]);
        entry.state.store(FileState::Done, std::memory_order_release);
    }
    else
    {
        entry.error = std::move(result.error);
        entry.state.store(FileState::Failed, std::memory_order_release);
        ++job.failed;
    }
}

void HashWorker(FolderJob& job)
{
    std::vector<BYTE> buffer(kReadChunkSize);
    for (;;)
    {
        size_t index = job.nextFile++;
        if (index >= job.files.size() || job.cancel)
            return;
        HashOneFile(job, job.files[index], buffer);
        ++job.finished;
    }
}

void RunFolderJob(FolderJob* job, HWND dlg)
{
    auto started = std::chrono::steady_clock::now();

    if (!IsDirectory(job->root))
        job->error = L"Folder not found:\n" + job->root;
    else
    {
        std::vector<FoundFile> found;
        ListFiles(job->root, L"*", job->recurse, found, &job->cancel, &job->scanned);
        for (FoundFile& f : found)
        {
            job->totalBytes += f.size;
            job->files.emplace_back(std::move(f.relPath), f.size);
        }
        job->scanDone = true;
        PostMessageW(dlg, WM_APP_SCANNED, 0, 0);

        // Several files are hashed in parallel; each file is read once and fed
        // to all selected algorithms.
        unsigned threads = std::max(1u, std::min(std::thread::hardware_concurrency(), kMaxThreads));
        threads = static_cast<unsigned>(std::min<size_t>(threads, job->files.size()));
        std::vector<std::thread> workers;
        for (unsigned i = 0; i < threads && !job->cancel; ++i)
            workers.emplace_back(HashWorker, std::ref(*job));
        for (std::thread& t : workers)
            t.join();
    }

    job->seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
    PostMessageW(dlg, WM_APP_FOLDER_DONE, 0, 0);
}

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------
bool IsRunning(const FolderWindow& w)
{
    return w.worker.joinable();
}

void StopJob(FolderWindow& w)
{
    if (w.worker.joinable())
    {
        w.job->cancel = true;
        w.worker.join();
    }
}

std::wstring LowerName(HashAlg alg)
{
    std::wstring s = HashAlgName(alg);
    CharLowerBuffW(s.data(), static_cast<DWORD>(s.size()));
    return s;
}

void UpdateControls(FolderWindow& w)
{
    bool running = IsRunning(w);
    bool stopping = running && w.job->cancel;
    bool hasResults = w.job && w.job->finished > 0;

    EnableWindow(GetDlgItem(w.dlg, IDC_F_FOLDER), !running);
    EnableWindow(GetDlgItem(w.dlg, IDC_F_BROWSE), !running);
    EnableWindow(GetDlgItem(w.dlg, IDC_F_RECURSE), !running);
    EnableWindow(GetDlgItem(w.dlg, IDC_F_START), !stopping);
    EnableWindow(GetDlgItem(w.dlg, IDC_F_COPY), !running && hasResults);
    EnableWindow(GetDlgItem(w.dlg, IDC_F_EXPORT), !running && hasResults);
    SetDlgItemTextW(w.dlg, IDC_F_START, stopping ? L"Stopping..." : running ? L"Stop" : L"Start");
}

void SetupColumns(FolderWindow& w)
{
    HWND list = GetDlgItem(w.dlg, IDC_F_LIST);
    while (ListView_DeleteColumn(list, 0)) {}

    auto addColumn = [&](int index, const wchar_t* title, int width, int format) {
        LVCOLUMNW col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
        col.pszText = const_cast<LPWSTR>(title);
        col.cx = width;
        col.fmt = format;
        ListView_InsertColumn(list, index, &col);
    };

    int dpiScale = static_cast<int>(GetDpiForWindow(w.dlg));
    addColumn(0, L"File", MulDiv(260, dpiScale, 96), LVCFMT_LEFT);
    addColumn(1, L"Size", MulDiv(80, dpiScale, 96), LVCFMT_RIGHT);

    w.columns.clear();
    for (int i = 0; i < kHashAlgCount; ++i)
    {
        if (!w.job->options.selected[i]) continue;
        std::wstring sample(kHexLength[i], L'0');
        int width = ListView_GetStringWidth(list, sample.c_str()) + MulDiv(16, dpiScale, 96);
        addColumn(static_cast<int>(w.columns.size()) + 2, HashAlgName(static_cast<HashAlg>(i)), width, LVCFMT_LEFT);
        w.columns.push_back(i);
    }
}

std::wstring CellText(const FolderWindow& w, size_t row, int column)
{
    const FileEntry& e = w.job->files[row];
    if (column == 0) return e.relPath;
    if (column == 1) return FormatSize(e.size);

    FileState state = e.state.load(std::memory_order_acquire);
    if (state == FileState::Failed)
        return column == 2 ? L"Error: " + e.error : L"";
    if (state != FileState::Done || column - 2 >= static_cast<int>(w.columns.size()))
        return L"";
    return e.results[w.columns[column - 2]];
}

void RefreshStatus(FolderWindow& w)
{
    if (!w.job) return;
    FolderJob& job = *w.job;
    std::wstring text;   // built as a string: paths in it can be long
    int progress = 0;

    if (!job.error.empty() && !IsRunning(w))
    {
        text = job.error;
        std::replace(text.begin(), text.end(), L'\n', L' ');
    }
    else if (!job.scanDone)
    {
        text = L"Scanning folder... " + std::to_wstring(job.scanned.load()) + L" files found";
    }
    else if (IsRunning(w))
    {
        uint64_t done = std::min<uint64_t>(job.bytesDone, job.totalBytes);
        progress = job.totalBytes ? static_cast<int>(done * kProgressRange / job.totalBytes)
                                  : static_cast<int>(job.finished * kProgressRange / std::max<size_t>(1, job.files.size()));
        text = std::to_wstring(std::min(progress / 10, 99)) + L"%  -  hashing " +
            std::to_wstring(job.finished.load()) + L" of " + std::to_wstring(job.files.size()) + L" files  (" +
            FormatSize(done) + L" of " + FormatSize(job.totalBytes) + L")";
    }
    else
    {
        wchar_t seconds[32];
        swprintf_s(seconds, L"%.1f", job.seconds);
        text = std::wstring(job.cancel ? L"Stopped" : L"Done") + L": " +
            std::to_wstring(job.finished.load() - job.failed.load()) + L" of " + std::to_wstring(job.files.size()) +
            L" files hashed  (" + FormatSize(job.totalBytes) + L" in " + seconds + L" s)";
        if (job.failed)
            text += L",  " + std::to_wstring(job.failed.load()) + L" failed";
        progress = job.cancel ? static_cast<int>(SendDlgItemMessageW(w.dlg, IDC_F_PROGRESS, PBM_GETPOS, 0, 0))
                              : kProgressRange;
    }

    SetDlgItemTextW(w.dlg, IDC_F_STATUS, text.c_str());
    // Set without the themed glide animation (backwards moves are instant).
    HWND bar = GetDlgItem(w.dlg, IDC_F_PROGRESS);
    SendMessageW(bar, PBM_SETRANGE32, 0, kProgressRange + 1);
    SendMessageW(bar, PBM_SETPOS, progress + 1, 0);
    SendMessageW(bar, PBM_SETPOS, progress, 0);
    SendMessageW(bar, PBM_SETRANGE32, 0, kProgressRange);

    // Repaint the visible rows so finished hashes appear.
    HWND list = GetDlgItem(w.dlg, IDC_F_LIST);
    int top = ListView_GetTopIndex(list);
    ListView_RedrawItems(list, top, top + ListView_GetCountPerPage(list) + 1);
}

void OnStart(FolderWindow& w)
{
    if (IsRunning(w))
    {
        w.job->cancel = true;
        UpdateControls(w);
        return;
    }

    HashOptions options;
    std::wstring error;
    if (!GetMainHashOptions(options, error))
    {
        MessageBoxW(w.dlg, error.c_str(), L"Folder Hash", MB_ICONINFORMATION);
        return;
    }

    std::wstring folder = GetDlgText(w.dlg, IDC_F_FOLDER);
    if (folder.empty())
    {
        if (!BrowseForFolder(w.dlg, folder))
            return;
        SetDlgItemTextW(w.dlg, IDC_F_FOLDER, folder.c_str());
    }
    while (folder.size() > 1 && (folder.back() == L'\\' || folder.back() == L'/'))
        folder.pop_back();

    auto job = std::make_unique<FolderJob>();
    job->root = folder;
    job->recurse = IsDlgButtonChecked(w.dlg, IDC_F_RECURSE) == BST_CHECKED;
    job->options = std::move(options);

    HWND list = GetDlgItem(w.dlg, IDC_F_LIST);
    ListView_SetItemCountEx(list, 0, 0);
    w.job = std::move(job);
    SetupColumns(w);

    std::wstring algs = L"Algorithms: ";
    for (size_t i = 0; i < w.columns.size(); ++i)
        algs += (i ? L", " : L"") + std::wstring(HashAlgName(static_cast<HashAlg>(w.columns[i])));
    if (w.job->options.hmac)
        algs += L"  (HMAC)";
    SetDlgItemTextW(w.dlg, IDC_F_ALGS, algs.c_str());

    w.worker = std::thread(RunFolderJob, w.job.get(), w.dlg);
    SetTimer(w.dlg, kRefreshTimer, kRefreshMs, nullptr);
    UpdateControls(w);
    RefreshStatus(w);
}

void OnJobDone(FolderWindow& w)
{
    KillTimer(w.dlg, kRefreshTimer);
    if (w.worker.joinable())
        w.worker.join();
    RefreshStatus(w);
    UpdateControls(w);
    if (!w.job->error.empty())
        MessageBoxW(w.dlg, w.job->error.c_str(), L"Folder Hash", MB_ICONERROR);
}

// Tab-separated table for pasting into a spreadsheet.
void OnCopyAll(FolderWindow& w)
{
    if (!w.job) return;
    std::wstring text = L"File\tSize";
    for (int alg : w.columns)
        text += L"\t" + std::wstring(HashAlgName(static_cast<HashAlg>(alg)));
    text += L"\r\n";
    for (size_t row = 0; row < w.job->files.size(); ++row)
    {
        const FileEntry& e = w.job->files[row];
        text += SpreadsheetText(e.relPath) + L"\t" + std::to_wstring(e.size);
        for (size_t c = 0; c < w.columns.size(); ++c)
            text += L"\t" + CellText(w, row, static_cast<int>(c) + 2);
        text += L"\r\n";
    }
    if (CopyToClipboard(w.dlg, text))
    {
        SetDlgItemTextW(w.dlg, IDC_F_COPY, L"Copied!");
        SetTimer(w.dlg, kCopyTimer, kCopyFeedbackMs, nullptr);
    }
}

void OnExport(FolderWindow& w)
{
    if (!w.job || w.columns.empty()) return;

    // Filters: CSV (all algorithms) or a checksum file for the first algorithm,
    // in the "hash *path" format understood by sha256sum/md5sum -c.
    HashAlg checksumAlg = static_cast<HashAlg>(w.columns[0]);
    std::wstring ext = LowerName(checksumAlg);
    std::wstring filter = L"CSV file, all algorithms (*.csv)";
    filter += L'\0'; filter += L"*.csv"; filter += L'\0';
    filter += std::wstring(HashAlgName(checksumAlg)) + L" checksum file (*." + ext + L")";
    filter += L'\0'; filter += L"*." + ext; filter += L'\0';
    filter += L'\0';

    std::wstring folderName = PathFindFileNameW(w.job->root.c_str());
    if (folderName.empty() || folderName.back() == L':') folderName = L"hashes";
    wchar_t path[MAX_PATH * 4] = {};
    wcsncpy_s(path, (folderName + L".csv").c_str(), _TRUNCATE);

    OPENFILENAMEW ofn = { sizeof(ofn) };
    ofn.hwndOwner = w.dlg;
    ofn.lpstrFilter = filter.c_str();
    ofn.lpstrFile = path;
    ofn.nMaxFile = ARRAYSIZE(path);
    ofn.lpstrDefExt = L"csv";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    if (!GetSaveFileNameW(&ofn))
        return;

    std::wstring text;
    bool csv = ofn.nFilterIndex != 2;
    if (csv)
    {
        text = L"File,Size";
        for (int alg : w.columns)
            text += L"," + std::wstring(HashAlgName(static_cast<HashAlg>(alg)));
        text += L",Error\r\n";
        for (size_t row = 0; row < w.job->files.size(); ++row)
        {
            const FileEntry& e = w.job->files[row];
            FileState state = e.state.load(std::memory_order_acquire);
            text += CsvField(e.relPath) + L"," + std::to_wstring(e.size);
            for (int alg : w.columns)
                text += L"," + (state == FileState::Done ? e.results[alg] : L"");
            text += L"," + CsvField(state == FileState::Failed ? e.error : L"") + L"\r\n";
        }
    }
    else
    {
        int alg = w.columns[0];
        for (const FileEntry& e : w.job->files)
        {
            if (e.state.load(std::memory_order_acquire) != FileState::Done) continue;
            std::wstring rel = e.relPath;
            std::replace(rel.begin(), rel.end(), L'\\', L'/');
            text += e.results[alg] + L" *" + rel + L"\n";
        }
    }

    if (!WriteUtf8File(path, text, csv))
        MessageBoxW(w.dlg, (L"Cannot write file:\n" + std::wstring(path) + L"\n\n" + ErrorMessage(GetLastError())).c_str(),
            L"Folder Hash", MB_ICONERROR);
}

void OnBrowse(FolderWindow& w)
{
    std::wstring folder = GetDlgText(w.dlg, IDC_F_FOLDER);
    if (BrowseForFolder(w.dlg, folder))
        SetDlgItemTextW(w.dlg, IDC_F_FOLDER, folder.c_str());
}

void OnDropFiles(FolderWindow& w, HDROP drop)
{
    if (!IsRunning(w))
    {
        UINT len = DragQueryFileW(drop, 0, nullptr, 0);
        std::wstring path(len + 1, L'\0');
        DragQueryFileW(drop, 0, path.data(), len + 1);
        path.resize(len);
        if (!IsDirectory(path))
        {
            size_t slash = path.find_last_of(L'\\');
            if (slash != std::wstring::npos) path.resize(slash);
        }
        SetDlgItemTextW(w.dlg, IDC_F_FOLDER, path.c_str());
    }
    DragFinish(drop);
}

void OnGetDispInfo(FolderWindow& w, NMLVDISPINFOW* info)
{
    if (!(info->item.mask & LVIF_TEXT) || !w.job || !w.job->scanDone)
        return;
    size_t row = static_cast<size_t>(info->item.iItem);
    if (row >= w.job->files.size())
        return;
    std::wstring text = CellText(w, row, info->item.iSubItem);
    wcsncpy_s(info->item.pszText, info->item.cchTextMax, text.c_str(), _TRUNCATE);
}

void CaptureLayout(FolderWindow& w)
{
    using A = AnchorLayout;
    w.layout.Add(IDC_F_FOLDER,   A::GrowX);
    w.layout.Add(IDC_F_BROWSE,   A::MoveX);
    w.layout.Add(IDC_F_ALGS,     A::GrowX);
    w.layout.Add(IDC_F_LIST,     A::GrowX | A::GrowY);
    w.layout.Add(IDC_F_PROGRESS, A::MoveY | A::GrowX);
    w.layout.Add(IDC_F_STATUS,   A::MoveY | A::GrowX);
    w.layout.Add(IDC_F_START,    A::MoveX | A::MoveY);
    w.layout.Add(IDC_F_COPY,     A::MoveX | A::MoveY);
    w.layout.Add(IDC_F_EXPORT,   A::MoveX | A::MoveY);
    w.layout.Add(IDCANCEL,       A::MoveX | A::MoveY);
    w.layout.Capture(w.dlg);
}

void OnInitDialog(FolderWindow& w)
{
    HICON icon = static_cast<HICON>(LoadImageW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_APP), IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0));
    HICON bigIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_APP));
    SendMessageW(w.dlg, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(icon));
    SendMessageW(w.dlg, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(bigIcon));

    HWND list = GetDlgItem(w.dlg, IDC_F_LIST);
    ListView_SetExtendedListViewStyle(list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
    SendDlgItemMessageW(w.dlg, IDC_F_PROGRESS, PBM_SETRANGE32, 0, kProgressRange);

    Settings settings = LoadSettings();
    CheckDlgButton(w.dlg, IDC_F_RECURSE, settings.includeSubfolders ? BST_CHECKED : BST_UNCHECKED);
    SetDlgItemTextW(w.dlg, IDC_F_FOLDER, w.initialFolder.c_str());
    SetDlgItemTextW(w.dlg, IDC_F_ALGS, L"Algorithms: as selected in the main window");
    SetDlgItemTextW(w.dlg, IDC_F_STATUS, L"Choose a folder and press Start.");

    CaptureLayout(w);
    UpdateControls(w);

    if (w.autoStart && !w.initialFolder.empty())
        PostMessageW(w.dlg, WM_COMMAND, IDC_F_START, 0);
}

INT_PTR CALLBACK FolderDialogProc(HWND dlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_INITDIALOG)
    {
        g_folder->dlg = dlg;
        OnInitDialog(*g_folder);
        return TRUE;
    }
    if (!g_folder || g_folder->dlg != dlg)
        return FALSE;
    FolderWindow& w = *g_folder;

    switch (msg)
    {
    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDC_F_START:  OnStart(w); return TRUE;
        case IDC_F_BROWSE: OnBrowse(w); return TRUE;
        case IDC_F_COPY:   OnCopyAll(w); return TRUE;
        case IDC_F_EXPORT: OnExport(w); return TRUE;
        case IDCANCEL:     DestroyWindow(dlg); return TRUE;
        }
        break;

    case WM_NOTIFY:
    {
        auto* hdr = reinterpret_cast<NMHDR*>(lParam);
        if (hdr->idFrom == IDC_F_LIST && hdr->code == LVN_GETDISPINFOW)
        {
            OnGetDispInfo(w, reinterpret_cast<NMLVDISPINFOW*>(lParam));
            return TRUE;
        }
        break;
    }

    case WM_TIMER:
        if (wParam == kRefreshTimer)
            RefreshStatus(w);
        else if (wParam == kCopyTimer)
        {
            KillTimer(dlg, kCopyTimer);
            SetDlgItemTextW(dlg, IDC_F_COPY, L"Copy All");
        }
        return TRUE;

    case WM_APP_SCANNED:
        ListView_SetItemCountEx(GetDlgItem(dlg, IDC_F_LIST), static_cast<int>(w.job->files.size()), 0);
        return TRUE;

    case WM_APP_FOLDER_DONE:
        OnJobDone(w);
        return TRUE;

    case WM_DROPFILES:
        OnDropFiles(w, reinterpret_cast<HDROP>(wParam));
        return TRUE;

    case WM_NCHITTEST:
        return DragAnywhereHitTest(dlg, wParam, lParam);

    case WM_SIZE:
        w.layout.Apply(LOWORD(lParam), HIWORD(lParam));
        return TRUE;

    case WM_GETMINMAXINFO:
    {
        SIZE min = w.layout.InitialWindowSize();
        if (min.cx)
            reinterpret_cast<MINMAXINFO*>(lParam)->ptMinTrackSize = { min.cx, min.cy };
        return TRUE;
    }

    case WM_DESTROY:
    {
        // Also reached when the main window closes (owned windows go first).
        StopJob(w);
        Settings settings = LoadSettings();
        settings.includeSubfolders = IsDlgButtonChecked(dlg, IDC_F_RECURSE) == BST_CHECKED;
        SaveSettings(settings);
        return TRUE;
    }

    case WM_NCDESTROY:
        delete g_folder;
        g_folder = nullptr;
        return FALSE;
    }
    return FALSE;
}

} // namespace

void ShowFolderHashWindow(HWND owner, const std::wstring& folder, bool autoStart)
{
    if (g_folder)
    {
        HWND dlg = g_folder->dlg;
        if (!folder.empty() && !IsRunning(*g_folder))
        {
            SetDlgItemTextW(dlg, IDC_F_FOLDER, folder.c_str());
            if (autoStart)
                PostMessageW(dlg, WM_COMMAND, IDC_F_START, 0);
        }
        ShowWindow(dlg, SW_RESTORE);
        SetForegroundWindow(dlg);
        return;
    }

    g_folder = new FolderWindow;
    g_folder->initialFolder = folder;
    g_folder->autoStart = autoStart;
    HWND dlg = CreateDialogParamW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDD_FOLDERHASH), owner, FolderDialogProc, 0);
    if (!dlg)
    {
        delete g_folder;
        g_folder = nullptr;
        return;
    }
    ShowWindow(dlg, SW_SHOW);
}

HWND FolderHashWindow()
{
    return g_folder ? g_folder->dlg : nullptr;
}
