#pragma once

#define IDD_HASHCALC            101
#define IDD_FOLDERHASH          102
#define IDR_MAINMENU            103
#define IDR_ACCEL               104
#define IDI_APP                 105
#define IDD_PATHSETUP           106

// Menu commands
#define IDM_FILE_OPEN           40001
#define IDM_FILE_FOLDER         40002
#define IDM_FILE_COPYALL        40003
#define IDM_FILE_EXIT           40004
#define IDM_FILE_RESET          40005
#define IDM_SETTINGS_SHELL      40010
#define IDM_SETTINGS_TOPMOST    40011
#define IDM_SETTINGS_PATH       40012
#define IDM_SETTINGS_SINGLE     40013
#define IDM_VIEW_EXTENDED       40030
#define IDM_HELP_HELP           40020
#define IDM_HELP_ABOUT          40021

#define IDC_DATAFORMAT          1001
#define IDC_DATA                1002
#define IDC_BROWSE              1003
#define IDC_HMAC                1004
#define IDC_KEYFORMAT           1005
#define IDC_KEY                 1006
#define IDC_CALCULATE           1007
#define IDC_HELPBTN             1008
#define IDC_LOGO                1009
#define IDC_CHK_ALL             1010
#define IDC_COPY_ALL            1011
#define IDC_SEP_TOP             1012
#define IDC_RESULTS             1015

// Add to PATH window
#define IDC_P_FOLDER            1600
#define IDC_P_BROWSE            1601

// Folder hash window
#define IDC_F_FOLDER            1500
#define IDC_F_BROWSE            1501
#define IDC_F_RECURSE           1502
#define IDC_F_ALGS              1503
#define IDC_F_LIST              1504
#define IDC_F_PROGRESS          1505
#define IDC_F_STATUS            1506
#define IDC_F_START             1507
#define IDC_F_COPY              1508
#define IDC_F_EXPORT            1509

// Hash type checkboxes: IDC_CHK_BASE + HashAlg
#define IDC_CHK_BASE            1100
#define IDC_CHK_MD5             1100
#define IDC_CHK_MD4             1101
#define IDC_CHK_SHA1            1102
#define IDC_CHK_SHA256          1103
#define IDC_CHK_SHA384          1104
#define IDC_CHK_SHA512          1105
#define IDC_CHK_RIPEMD160       1106
#define IDC_CHK_PANAMA          1107
#define IDC_CHK_TIGER           1108
#define IDC_CHK_MD2             1109
#define IDC_CHK_ADLER32         1110
#define IDC_CHK_CRC32           1111
#define IDC_CHK_EDONKEY         1112
#define IDC_CHK_IMPHASH         1113
#define IDC_CHK_AUTHENTIHASH    1114
#define IDC_CHK_RICHHASH        1115
#define IDC_CHK_SSDEEP          1116
#define IDC_CHK_TLSH            1117

#ifndef IDC_STATIC
#define IDC_STATIC              (-1)
#endif
