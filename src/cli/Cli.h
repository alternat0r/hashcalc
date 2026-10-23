#pragma once

// Command line mode of HashCalc.exe (see wmain in main.cpp for when it is used).
// argv[0] is the program path. Returns the process exit code:
// 0 = success, 1 = some files failed / did not verify, 2 = invalid arguments.
int RunCli(int argc, wchar_t** argv);

// True if the arguments are command line options (as opposed to a plain
// file/folder path from Explorer or the context menu, which opens the GUI).
bool IsCliInvocation(int argc, wchar_t** argv);
