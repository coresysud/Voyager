#pragma once
#include "UefiMain.h"

//
// load a driver into memory and spoof the certificate...
//
EFI_STATUS LoadDriver(CHAR16* DriverPath, CHAR16* DriverName, UINT64* ImageBase, UINT32* ImageSize);
