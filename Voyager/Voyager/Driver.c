#include "Driver.h"

STATIC VOID SpoofCert(WIN_CERTIFICATE* Certificate)
{
	wcscpy(Certificate->Subject, L"Microsoft Windows");
	wcscpy(Certificate->Issuer, L"Microsoft Windows Production PCA 2011");
	wcscpy(Certificate->ThumbPrint, L"50 e1 a6 2c 95 48 6c 2c 1a 45 33 21 8a 8a 77 02 44 b2 42 44");
}

STATIC VOID ErasePEHeaders(UINT64 ImageBase)
{
	const PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);
	const PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((UINT64)&NtHeader->OptionalHeader + NtHeader->FileHeader.SizeOfOptionalHeader);

	// erase dos header...
	for (UINT32 i = 0; i < ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew + sizeof(IMAGE_DOS_HEADER); i++)
		((UINT8*)ImageBase)[i] = 0;

	// erase section headers...
	for (UINT32 i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
		for (UINT32 j = 0; j < sizeof(IMAGE_SECTION_HEADER); j++)
			((UINT8*)&SectionHeader[i])[j] = 0;

	// erase nt headers...
	for (UINT32 i = 0; i < sizeof(IMAGE_NT_HEADERS); i++)
		((UINT8*)NtHeader)[i] = 0;
}

STATIC EFI_STATUS FindPiDDB(
	UINT64 ImageBase,
	UINT32 ImageSize,
	EFI_IMAGE_DATA_DIRECTORY** PiDDBCloak,
	WIN_CERTIFICATE** WinCertificate
)
{
	const PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);
	const PIMAGE_DATA_DIRECTORY PiDDB = &NtHeader->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];
	const PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((UINT64)&NtHeader->OptionalHeader + NtHeader->FileHeader.SizeOfOptionalHeader);

	if (!PiDDB->VirtualAddress)
		return EFI_NOT_FOUND;

	for (UINT32 i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
	if (SectionHeader[i].VirtualAddress <= PiDDB->VirtualAddress && SectionHeader[i].VirtualAddress + SectionHeader[i].Misc.VirtualSize >= PiDDB->VirtualAddress)
	{
		*PiDDBCloak = (EFI_IMAGE_DATA_DIRECTORY*)(ImageBase + SectionHeader[i].PointerToRawData + (PiDDB->VirtualAddress - SectionHeader[i].VirtualAddress));
		*WinCertificate = (WIN_CERTIFICATE*)(ImageBase + SectionHeader[i].PointerToRawData + (PiDDB->VirtualAddress - SectionHeader[i].VirtualAddress));
		return EFI_SUCCESS;
	}

	return EFI_NOT_FOUND;
}

EFI_STATUS LoadDriver(CHAR16* DriverPath, CHAR16* DriverName, UINT64* ImageBase, UINT32* ImageSize)
{
	EFI_STATUS Status;
	EFI_HANDLE DriverHandle;

	// load the driver into memory so we can fuck with it...
	Status = gBS->LoadImage(FALSE, gImageHandle, DriverPath, NULL, NULL, &DriverHandle);
	if (EFI_ERROR(Status))
		return Status;

	// write the name of the driver to the image handle...
	IMAGE_DOS_HEADER* DosHeader;
	gBS->HandleProtocol(DriverHandle, &gEfiLoadedImageProtocolGuid, &DosHeader);
	gBS->UnloadImage(DriverHandle);

	// read the file into a buffer...
	UINT8* Buffer;
	UINTN FileSize;
	ReadFile(DriverPath, &Buffer, &FileSize, FALSE);

	// copy the driver into a new buffer...
	gBS->AllocatePool(EfiBootServicesData, FileSize, ImageBase);
	gBS->CopyMem((VOID*)*ImageBase, Buffer, FileSize);
	*ImageSize = FileSize;

	// get the location of the PiDDB...
	EFI_IMAGE_DATA_DIRECTORY* PiDDB;
	WIN_CERTIFICATE* WinCertificate;
	FindPiDDB(*ImageBase, *ImageSize, &PiDDB, &WinCertificate);

	// erase the PE headers, then spoof the certificate...
	ErasePEHeaders(*ImageBase);
	SpoofCert(WinCertificate);
	return EFI_SUCCESS;
}
