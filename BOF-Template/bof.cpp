
#include <windows.h>
#include "base/helpers.h"
#ifdef _DEBUG
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#include "base/mock.h"
#endif

extern "C" {
#include "beacon.h"

//===== DFR resolutions =====
DFR(KERNEL32, FindFirstFileA);
DFR(KERNEL32, FindNextFileA);
DFR(KERNEL32, FindClose);
DFR(KERNEL32, GetProcessHeap);
DFR(KERNEL32, HeapAlloc);
DFR(KERNEL32, HeapFree);

#define FindFirstFileA   KERNEL32$FindFirstFileA
#define FindNextFileA    KERNEL32$FindNextFileA
#define FindClose        KERNEL32$FindClose
#define GetProcessHeap   KERNEL32$GetProcessHeap
#define HeapAlloc        KERNEL32$HeapAlloc
#define HeapFree         KERNEL32$HeapFree

#define MAX_PATH_LEN 260

    //===== ANSI string helpers =====
    static unsigned int StrLen(const char* s) {
        const char* p = s;
        while (*p) p++;
        return (unsigned int)(p - s);
    }
    static void StrCopy(char* d, const char* s) {
        while ((*d++ = *s++)) {}
    }
    static char ToLowerA(char c) {
        return (c >= 'A' && c <= 'Z') ? (c + 32) : c;
    }
    static char* StrPBrk(const char* s, const char* accept) {
        while (*s) {
            const char* a = accept;
            while (*a) {
                if (*s == *a) return (char*)s;
                a++;
            }
            s++;
        }
        return NULL;
    }
    static char* StrRChr(const char* s, char c) {
        const char* last = NULL;
        for (; *s; s++)
            if (*s == c) last = s;
        return (char*)last;
    }
    static int WildMatch(const char* pat, const char* str) {
        while (*pat) {
            if (*pat == '*') {
                pat++;
                if (!*pat) return 1;
                while (*str) {
                    if (WildMatch(pat, str)) return 1;
                    str++;
                }
                return 0;
            }
            if (*pat == '?') {
                if (!*str) return 0;
                pat++;  str++;
            }
            else {
                if (ToLowerA(*pat) != ToLowerA(*str))
                    return 0;
                pat++;  str++;
            }
        }
        return *str == 0;
    }

    //===== aggregate buffer =====
    static char* results = NULL;
    static SIZE_T  results_len = 0;
    static SIZE_T  results_cap = 0;

    // simple memcpy
    static PVOID CopyMemoryEx(PVOID D, PVOID S, SIZE_T L) {
        PBYTE d = (PBYTE)D, s = (PBYTE)S;
        for (SIZE_T i = 0; i < L; i++) d[i] = s[i];
        return D;
    }

    // append one line + '\n' into results buffer
    static BOOL AppendResult(const char* s) {
        SIZE_T sl = StrLen(s);
        SIZE_T need = results_len + sl + 2;  // + '\n' + '\0'
        if (need > results_cap) {
            SIZE_T newcap = results_cap ? results_cap * 2 : 512;
            while (newcap < need) newcap *= 2;
            char* tmp = (char*)HeapAlloc(GetProcessHeap(), 0, newcap);
            if (!tmp) return FALSE;
            if (results_len) CopyMemoryEx(tmp, results, results_len);
            if (results)    HeapFree(GetProcessHeap(), 0, results);
            results = tmp;
            results_cap = newcap;
        }
        CopyMemoryEx(results + results_len, (PVOID)s, sl);
        results_len += sl;
        results[results_len++] = '\n';
        results[results_len] = '\0';
        return TRUE;
    }

    // redefine PrintLine to aggregate
#define PrintLine(s) AppendResult(s)

//----------------------------------------
// recursive directory scan
//----------------------------------------
    static void ScanDir(const char* dir, const char* pat) {
        char search[MAX_PATH_LEN];
        unsigned int L = StrLen(dir);

        // build "<dir>\*"
        StrCopy(search, dir);
        if (L && search[L - 1] != '\\') {
            search[L++] = '\\';
            search[L] = 0;
        }
        StrCopy(search + L, "*");

        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(search, &fd);
        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            const char* name = fd.cFileName;

            // recurse into subdirs
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0)))
                    continue;
                char sub[MAX_PATH_LEN];
                unsigned int LL = StrLen(dir);
                StrCopy(sub, dir);
                if (LL && sub[LL - 1] != '\\') {
                    sub[LL++] = '\\';
                    sub[LL] = 0;
                }
                StrCopy(sub + LL, name);
                ScanDir(sub, pat);
            }
            else {
                // file: wildcard match?
                if (WildMatch(pat, name)) {
                    char fullp[MAX_PATH_LEN];
                    unsigned int LL = StrLen(dir);
                    StrCopy(fullp, dir);
                    if (LL && fullp[LL - 1] != '\\') {
                        fullp[LL++] = '\\';
                        fullp[LL] = 0;
                    }
                    StrCopy(fullp + LL, name);
                    PrintLine(fullp);
                }
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }

    //----------------------------------------
    // BOF entry
    //----------------------------------------
    void go(char* args, int alen) {
        datap  parser;
        char* firstArg, * secondArg;
        char   dir[MAX_PATH_LEN] = { 0 };
        char   pat[MAX_PATH_LEN] = { 0 };

        BeaconDataParse(&parser, args, alen);
        firstArg = BeaconDataExtract(&parser, NULL);
        secondArg = BeaconDataExtract(&parser, NULL);

        // two-arg form?
        if (secondArg) {
            StrCopy(dir, firstArg);
            StrCopy(pat, secondArg);
        }
        else {
            // single-arg: split "<dir>\<wild>"
            const char* arg = firstArg;
            char* wild = StrPBrk(arg, "*?");
            if (wild) {
                char* spl = StrRChr(arg, '\\');
                if (!spl || spl < wild) spl = StrRChr(arg, '/');
                if (spl && spl < wild) {
                    unsigned int dlen = (unsigned int)(spl - arg);
                    if (dlen < MAX_PATH_LEN) {
                        for (unsigned int i = 0; i < dlen; i++)
                            dir[i] = arg[i];
                        dir[dlen] = 0;
                        unsigned int pi = 0;
                        for (const char* p = spl + 1;
                            *p && pi + 1 < MAX_PATH_LEN;
                            p++)
                        {
                            pat[pi++] = *p;
                        }
                        pat[pi] = 0;
                    }
                }
            }
            if (!pat[0]) {
                StrCopy(dir, ".");
                StrCopy(pat, arg);
            }
        }

        // wrap bare substring into *…*
        if (!StrPBrk(pat, "*?")) {
            unsigned int pL = StrLen(pat);
            if (pL + 3 < MAX_PATH_LEN) {
                for (int i = (int)pL; i >= 0; i--)
                    pat[i + 1] = pat[i];
                pat[0] = '*';
                pat[pL + 1] = '*';
                pat[pL + 2] = 0;
            }
        }

        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] Scanning \"%s\" for \"%s\"\n", dir, pat);
        // perform the scan
        ScanDir(dir, pat);

        // flush aggregated results
        if (results_len) {
            BeaconPrintf(CALLBACK_OUTPUT, "%s", results);
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Scan Complete");

        }
        else {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] No matches found ¯\\_(`_`)_/¯ \n");

                    }

        // cleanup
        if (results) HeapFree(GetProcessHeap(), 0, results);
        results = NULL;
        results_len = 0;
        results_cap = 0;
    }

} // extern "C"