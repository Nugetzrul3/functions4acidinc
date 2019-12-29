#ifndef __FUNCTIONS_H
#define __FUNCTIONS_H

#include <iostream>
#include <fstream>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>

#include "openssl/aes.h"

// PE
int RunPortableExecutable(void* Image);

// AES
std::string DecryptStringAES(char *Key, std::string HEX_Message, int size);

#endif // !__FUNCTIONS_H
