#include "Utils.h"

BOOLEAN CheckMask(CHAR8* base, CHAR8* pattern, CHAR8* mask)
{
	for (; *mask; ++base, ++pattern, ++mask)
		if (*mask == 'x' && *base != *pattern)
			return FALSE;

	return TRUE;
}

VOID* FindPattern(CHAR8* base, UINTN size, CHAR8* pattern, CHAR8* mask)
{
	size -= AsciiStrLen(mask);
	for (UINTN i = 0; i <= size; ++i)
	{
		VOID* addr = &base[i];
		if (CheckMask(addr, pattern, mask))
			return addr;
	}
	return NULL;
}

VOID* GetExport(UINT8* ModuleBase, CHAR8* export)
{
	EFI_IMAGE_DOS_HEADER* dosHeaders = (EFI_IMAGE_DOS_HEADER*)ModuleBase;
	if (dosHeaders->e_magic != EFI_IMAGE_DOS_SIGNATURE)
		return NULL;

	EFI_IMAGE_NT_HEADERS64* ntHeaders = (EFI_IMAGE_NT_HEADERS64*)(ModuleBase + dosHeaders->e_lfanew);
	UINT32 exportsRva = ntHeaders->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	EFI_IMAGE_EXPORT_DIRECTORY* exports = (EFI_IMAGE_EXPORT_DIRECTORY*)(ModuleBase + exportsRva);
	UINT32* nameRva = (UINT32*)(ModuleBase + exports->AddressOfNames);

	for (UINT32 i = 0; i < exports->NumberOfNames; ++i)
	{
		CHAR8* func = (CHAR8*)(ModuleBase + nameRva[i]);
		if (AsciiStrCmp(func, export) == 0)
		{
			UINT32* funcRva = (UINT32*)(ModuleBase + exports->AddressOfFunctions);
			UINT16* ordinalRva = (UINT16*)(ModuleBase + exports->AddressOfNameOrdinals);
			return (VOID*)(((UINT64)ModuleBase) + funcRva[ordinalRva[i]]);
		}
	}
	return NULL;
}

VOID MemCopy(VOID* dest, VOID* src, UINTN size) 
{
	for (UINT8* d = dest, *s = src; size--; *d++ = *s++);
}

EFI_STATUS ReadFile(CHAR16* Path, UINT8** Buffer, UINTN* FileSize, BOOLEAN BootService)
{
	EFI_STATUS Status;
	UINTN HandleCount = 0;
	EFI_HANDLE* Handles = NULL;
	EFI_FILE_IO_INTERFACE* FileSystem;
	EFI_FILE_HANDLE VolumeHandle;
	EFI_FILE_HANDLE FileHandle;

	Status = gBS->LocateHandleBuffer(ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &HandleCount, &Handles);
	if (EFI_ERROR(Status))
		return Status;

	for (UINTN i = 0; i < HandleCount; i++)
	{
		Status = gBS->OpenProtocol(Handles[i], &gEfiSimpleFileSystemProtocolGuid, (VOID**)&FileSystem, gImageHandle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
		if (EFI_ERROR(Status))
			continue;

		Status = FileSystem->OpenVolume(FileSystem, &VolumeHandle);
		if (EFI_ERROR(Status))
			continue;

		Status = VolumeHandle->Open(VolumeHandle, &FileHandle, Path, EFI_FILE_MODE_READ, 0);
		if (EFI_ERROR(Status))
			continue;

		EFI_FILE_INFO* FileInfo;
		UINTN InfoSize = 0;
		Status = FileHandle->GetInfo(FileHandle, &gEfiFileInfoGuid, &InfoSize, NULL);
		if (Status == EFI_BUFFER_TOO_SMALL)
		{
			if (BootService)
				gBS->AllocatePool(EfiBootServicesData, InfoSize, (VOID**)&FileInfo);
			else
				gBS->AllocatePool(EfiRuntimeServicesData, InfoSize, (VOID**)&FileInfo);

			Status = FileHandle->GetInfo(FileHandle, &gEfiFileInfoGuid, &InfoSize, FileInfo);
			if (EFI_ERROR(Status))
			{
				gBS->FreePool(FileInfo);
				FileHandle->Close(FileHandle);
				continue;
			}
		}

		*FileSize = FileInfo->FileSize;
		if (BootService)
			gBS->AllocatePool(EfiBootServicesData, *FileSize, (VOID**)Buffer);
		else
			gBS->AllocatePool(EfiRuntimeServicesData, *FileSize, (VOID**)Buffer);

		Status = FileHandle->Read(FileHandle, FileSize, *Buffer);
		gBS->FreePool(FileInfo);
		FileHandle->Close(FileHandle);
		return Status;
	}

	return EFI_NOT_FOUND;
}