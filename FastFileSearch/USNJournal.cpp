#include "stdafx.h"
#include "USNJournal.h"

using namespace std;

#define RECORD_BUF_SIZE 0x1000

bool GetFullPathByFileReferenceNumber(HANDLE hVol, FILE_ID_128 FileReferenceNumber) // 根据文件号获得全路径，上篇文章已经说过，共有3中方法，这是其中之一，代码简单但效率不高
{
	typedef ULONG(__stdcall *PNtCreateFile)(
		PHANDLE FileHandle,
		ULONG DesiredAccess,
		PVOID ObjectAttributes,
		PVOID IoStatusBlock,
		PLARGE_INTEGER AllocationSize,
		ULONG FileAttributes,
		ULONG ShareAccess,
		ULONG CreateDisposition,
		ULONG CreateOptions,
		PVOID EaBuffer,
		ULONG EaLength);
	PNtCreateFile NtCreatefile = (PNtCreateFile)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateFile");

	typedef struct _UNICODE_STRING {
		USHORT Length, MaximumLength;
		PWCH Buffer;
	} UNICODE_STRING, *PUNICODE_STRING;
	UNICODE_STRING fidstr = { 8, 8, (PWSTR)&FileReferenceNumber };

	typedef struct _OBJECT_ATTRIBUTES {
		ULONG Length;
		HANDLE RootDirectory;
		PUNICODE_STRING ObjectName;
		ULONG Attributes;
		PVOID SecurityDescriptor;
		PVOID SecurityQualityOfService;
	} OBJECT_ATTRIBUTES;
	const ULONG OBJ_CASE_INSENSITIVE = 0x00000040UL;
	OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES), hVol, &fidstr, OBJ_CASE_INSENSITIVE, 0, 0 };

	HANDLE hFile;
	ULONG iosb[2];
	const ULONG FILE_OPEN_BY_FILE_ID = 0x00002000UL;
	const ULONG FILE_OPEN = 0x00000001UL;
	ULONG status = NtCreatefile(&hFile, GENERIC_ALL, &oa, iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_OPEN_BY_FILE_ID, NULL, 0);
	if (status == 0)
	{
		typedef struct _IO_STATUS_BLOCK {
			union {
				NTSTATUS Status;
				PVOID Pointer;
			};
			ULONG_PTR Information;
		} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
		typedef enum _FILE_INFORMATION_CLASS {
			// ……
			FileNameInformation = 9
			// ……
		} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;
		typedef NTSTATUS(__stdcall *PNtQueryInformationFile)(
			HANDLE FileHandle,
			PIO_STATUS_BLOCK IoStatusBlock,
			PVOID FileInformation,
			DWORD Length,
			FILE_INFORMATION_CLASS FileInformationClass);
		PNtQueryInformationFile NtQueryInformationFile = (PNtQueryInformationFile)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationFile");

		typedef struct _OBJECT_NAME_INFORMATION {
			UNICODE_STRING Name;
		} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;
		IO_STATUS_BLOCK IoStatus;
		size_t allocSize = sizeof(OBJECT_NAME_INFORMATION) + MAX_PATH * sizeof(WCHAR);
		POBJECT_NAME_INFORMATION pfni = (POBJECT_NAME_INFORMATION)operator new(allocSize);
		status = NtQueryInformationFile(hFile, &IoStatus, pfni, allocSize, FileNameInformation);
		if (status == 0)
		{
			printf("%.*S", pfni->Name.Length / 2, &pfni->Name.Buffer);
		}
		operator delete(pfni);

		CloseHandle(hFile);
	}

	return status == 0;
}

vector<wstring> &GetFileList(LPCWSTR volume, LPCWSTR extName)
{
	vector<wstring> fileList;

	WCHAR *volBuf = new WCHAR[40];

	wsprintf(volBuf, L"\\\\.\\%s:", volume);

	HANDLE hDevice = CreateFile(volBuf, GENERIC_READ, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);

	if (hDevice != INVALID_HANDLE_VALUE)
	{
		USN_JOURNAL_DATA journalData;

		DWORD dwReturn = 0;
		BOOL bResult = FALSE;

		bResult = DeviceIoControl(hDevice, FSCTL_QUERY_USN_JOURNAL, NULL, 0, &journalData, sizeof(journalData), &dwReturn, NULL);

		if (bResult)
		{

			BYTE *buffer = new BYTE[RECORD_BUF_SIZE];
			BYTE *nameBuffer = new BYTE[MAX_PATH];

			MFT_ENUM_DATA enumData;
			ZeroMemory(&enumData, sizeof(enumData));

			enumData.MaxMajorVersion = 3;
			enumData.HighUsn = journalData.NextUsn;

			while (DeviceIoControl(hDevice, FSCTL_ENUM_USN_DATA, &enumData, sizeof(enumData), buffer, RECORD_BUF_SIZE, &dwReturn, NULL))
			{
				if (dwReturn > sizeof(DWORDLONG))
				{
					PUSN_RECORD_V3 pUsnRecord = (PUSN_RECORD_V3)(buffer + sizeof(DWORDLONG));

					while ((PBYTE)pUsnRecord < buffer + RECORD_BUF_SIZE)
					{
						DWORD nameBufLen = pUsnRecord->FileNameLength + sizeof(WCHAR);

						ZeroMemory(nameBuffer, MAX_PATH);
						memcpy(nameBuffer, pUsnRecord->FileName, pUsnRecord->FileNameLength);

						wprintf(L"%s\n", nameBuffer);

						GetFullPathByFileReferenceNumber(hDevice, pUsnRecord->FileReferenceNumber);

						pUsnRecord = (PUSN_RECORD_V3)((PBYTE)pUsnRecord + pUsnRecord->RecordLength);
					}
				}

				enumData.StartFileReferenceNumber = *(DWORDLONG *)buffer;
			}

			delete[] nameBuffer;
			delete[] buffer;
		}

		CloseHandle(hDevice);
	}

	delete[] volBuf;

	return fileList;
}