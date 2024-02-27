#include <Windows.h>
#include <iostream>

#include "../driver_test1/common.h"

#define DRIVER_PATH  L"\\\\.\\MyDriver1"

bool request_driver_action(kloader_input *inp)
{
	HANDLE hDevice = CreateFileW(DRIVER_PATH, GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to open device" << std::endl;
		return 1;
	}

	const size_t out_size = 1024;
	DWORD out_buffer[out_size] = { 0 };

	size_t data_size = sizeof(kloader_input) + inp->payl_size;

	BOOL success = FALSE;
	DWORD returned = 0;
	std::cout << "Trying to send IOCTL\n";
	success = DeviceIoControl(hDevice, IOCTL_PASS_PAYLOAD, inp, data_size, nullptr, 0, &returned, nullptr);
	if (success) {
		std::cout << "[OK] The action completed successfuly" << std::endl;
	}
	else {
		std::cout << "The action failed! " << std::endl;
	}

	CloseHandle(hDevice);
	return success == TRUE ? true : false;
}

inline BYTE* load_file(const char* filename, size_t& buf_size)
{
	FILE* fp = nullptr;
	fopen_s(&fp, filename, "rb");
	if (!fp) return nullptr;

	fseek(fp, 0, SEEK_END);
	long size = ftell(fp);

	fseek(fp, 0, SEEK_SET);

	BYTE* buf = (BYTE*)::calloc(size, 1);
	if (!buf) return nullptr;

	buf_size = fread(buf, 1, size, fp);
	fclose(fp);
	std::cout << "Loaded: " << buf_size << " bytes\n";
	return buf;
}

kloader_input* fill_structure(const char* name, const char* filename)
{
	size_t size = 0;
	BYTE* payl_buf = load_file(filename, size);
	if (!payl_buf || !size) {
		std::cerr << "Failed to load the file: " << filename << std::endl;
		return nullptr;
	}
	kloader_input *inp = (kloader_input*)::calloc(size + sizeof(kloader_input), 1);
	if (!inp) {
		free(payl_buf);
		return nullptr;
	}

	inp->magic = KL_MAGIC;

	size_t name_len = strlen(name);
	const size_t max_name_len = (name_len > sizeof(inp->file_name)) ? sizeof(inp->file_name) : name_len;
	::memcpy(inp->file_name, name, max_name_len);
	inp->file_name[sizeof(inp->file_name) - 1] = 0; // ensure the string is terminated

	std::cout << "Filling in the buffer with: " << size << std::endl;
	::memcpy(&inp->payl_buf, payl_buf, size);
	inp->payl_size = size;

	free(payl_buf);
	return inp;
}

int main(int argc, const char* argv[]) {
	if (argc < 3) {
		std::cout << "Usage: KernelLoad <payload_file> <name>\n";
		return 0;
	}
	const char* filename = argv[1];
	const char* name = argv[2];

	kloader_input *inp = fill_structure(name, filename);
	if (!inp) {
		std::cerr << "Failed to load the structure!\n";
		return 0;
	}
	bool isOK = request_driver_action(inp);
	free(inp);

	if (isOK) {
		return 0;
	}
	return (-1);
}

