#include <Windows.h>
#include <stdio.h>
#include <string>
#include <list>
#include <memory>

#include "Header.h"

int ForceDelete(std::wstring path);
int GetProcessHandles(HANDLE hProcess, std::list<ULONG>& handleList);
int GetObjectType(HANDLE hObject, std::wstring& type);
int GetObjectName(HANDLE hObject, std::wstring& name);


int wmain(int argc, wchar_t* argv[]) {
	UNREFERENCED_PARAMETER(argc);
	ForceDelete(argv[1]);
	printf("done\n");
	return 0;
}

int ForceDelete(std::wstring path)
{
	int ret = 0;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HANDLE hProcess = NULL;
	NTSTATUS ntStatus = 1;
	IO_STATUS_BLOCK ioStatusBlock = {};
	PFILE_PROCESS_IDS_USING_FILE_INFORMATION pFileProcessInfo = NULL;
	ULONG ulFileProcessInfoSize = sizeof(FILE_PROCESS_IDS_USING_FILE_INFORMATION);

	hFile = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("%d Error %d\n",__LINE__, GetLastError());
		return GetLastError();
	}

	pFileProcessInfo = (PFILE_PROCESS_IDS_USING_FILE_INFORMATION)malloc(ulFileProcessInfoSize);
	while ((ntStatus = NtQueryInformationFile(hFile, &ioStatusBlock, pFileProcessInfo, ulFileProcessInfoSize, FileProcessIdsUsingFileInformation)) == STATUS_INFO_LENGTH_MISMATCH) {
		ulFileProcessInfoSize *= 2;
		auto buffer = realloc(pFileProcessInfo, ulFileProcessInfoSize);
		if (!buffer) {
			printf("%d realloc failed\n", __LINE__);
			goto Cleanup;
		}

		pFileProcessInfo = (PFILE_PROCESS_IDS_USING_FILE_INFORMATION)buffer;
	}
	if (ntStatus != 0) {
		printf("%d Error %x\n",__LINE__, ntStatus);
		goto Cleanup;
	}

	if (pFileProcessInfo == NULL)
		goto Cleanup;

	printf("%d process is holding file\n", pFileProcessInfo->NumberOfProcessIdsInList);

	for (ULONG i = 0; i < pFileProcessInfo->NumberOfProcessIdsInList; i++) {

		printf("pid %llu\n", pFileProcessInfo->ProcessIdList[i]);

		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pFileProcessInfo->ProcessIdList[i]);
		if (!hProcess) {
			printf("%d Error %d\n", __LINE__, GetLastError());
			continue;
		}


		std::list<ULONG> ulHandleList;
		if ((ntStatus = GetProcessHandles(hProcess, ulHandleList)) != 0) {
			printf("%d Error %x\n", __LINE__, ntStatus);
			continue;
		}

		for (auto j = ulHandleList.begin(); j != ulHandleList.end(); j++){
			HANDLE hDup;
			if (!DuplicateHandle(hProcess, (HANDLE)*j, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
				continue;
			}

			// get type
			std::wstring type;
			ntStatus = GetObjectType(hDup, type);
			if (ntStatus != 0 || type != L"File") {
				CloseHandle(hDup);
				continue;
			}

			// get name
			std::wstring name;
			if ((ntStatus = GetObjectName(hDup, name)) != 0)
			{
				CloseHandle(hDup);
				continue;
			}
			printf("%ws\n", name.c_str());
		}

		CloseHandle(hProcess);
		hProcess = NULL;

	}


Cleanup:
	if (hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);
	if (hProcess != NULL)
		CloseHandle(hProcess);
	FREE(pFileProcessInfo);
	return ret;
}

int GetProcessHandles(HANDLE hProcess, std::list<ULONG>& handleList)
{
	NTSTATUS ntStatus;
	ULONG ulHandleCount = 0;
	ULONG ulRetLength = 0;
	ULONG* pHandles = NULL;


	ntStatus = NtQueryInformationProcess(hProcess, ProcessHandleCount, &ulHandleCount, sizeof(ULONG), &ulRetLength);
	if (ntStatus != 0)
		return ntStatus;

	ulRetLength = ulHandleCount * sizeof(ULONG);
	pHandles = (ULONG*)malloc(ulRetLength);
	ntStatus = NtQueryInformationProcess(hProcess, ProcessHandleTable, pHandles, ulRetLength, &ulRetLength);
	if (ntStatus != 0) {
		free(pHandles);
		return ntStatus;
	}

	if (pHandles) {
		for (ULONG i = 0; i < ulRetLength / sizeof(ULONG); i++) {
			handleList.push_back(pHandles[i]);
		}
		free(pHandles);
	}

	return 0;
}

int GetObjectType(HANDLE hObject, std::wstring& type)
{
	NTSTATUS ntStatus;
	std::unique_ptr<PUBLIC_OBJECT_TYPE_INFORMATION> pObjectType;
	ULONG ulSize = 0;

	while ((ntStatus = NtQueryObject(hObject, ObjectTypeInformation, pObjectType.get(), ulSize, &ulSize)) == STATUS_INFO_LENGTH_MISMATCH) {
		auto buffer = realloc(pObjectType.get(), ulSize);
		if (!buffer) {
			printf("%d realloc failed\n", __LINE__);
			return 1;
		}
		pObjectType.release();
		pObjectType.reset((PPUBLIC_OBJECT_TYPE_INFORMATION)buffer);
	}
	if (ntStatus != 0) {
		return ntStatus;
	}

	type = std::wstring(pObjectType->TypeName.Buffer, pObjectType->TypeName.Length / sizeof(WCHAR));
	return 0;
}

int GetObjectName(HANDLE hObject, std::wstring& name)
{
	NTSTATUS ntStatus;
	std::unique_ptr<OBJECT_NAME_INFORMATION> pObjectName;
	PUBLIC_OBJECT_BASIC_INFORMATION ObjectInfo = {};
	ULONG ulSize = 0;

	ulSize = sizeof(PUBLIC_OBJECT_BASIC_INFORMATION);
	ntStatus = NtQueryObject(hObject, ObjectBasicInformation, &ObjectInfo, ulSize, &ulSize);
	if (ntStatus != 0) {
		return ntStatus;
	}

	if (ObjectInfo.GrantedAccess == 0x0012019f) {
		return 1;
	}

	ulSize = 0;
	while ((ntStatus = NtQueryObject(hObject, ObjectNameInformation, pObjectName.get(), ulSize, &ulSize)) == STATUS_INFO_LENGTH_MISMATCH) {
		auto buffer = realloc(pObjectName.get(), ulSize);
		if (!buffer) {
			printf("%d realloc failed\n", __LINE__);
			return 1;
		}
		pObjectName.release();
		pObjectName.reset((POBJECT_NAME_INFORMATION)buffer);

	}
	if (ntStatus != 0) {
		return ntStatus;
	}

	name = std::wstring(pObjectName->Name.Buffer, pObjectName->Name.Length / sizeof(WCHAR));
	return 0;
}
