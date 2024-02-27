#pragma once

#define MY_DEVICE L"\\Device\\MyDriver1"
#define MY_DRIVER_LINK L"\\??\\MyDriver1"
#define DRIVER_PREFIX "[MyDriver1]"

struct kloader_input
{
	USHORT magic;
	char file_name[16];
	SIZE_T payl_size;
	UCHAR payl_buf;
};

#define KL_MAGIC 'KL'

#define PROCESS_WATCHER_DEVICE 0x8000

#define IOCTL_PASS_PAYLOAD CTL_CODE(PROCESS_WATCHER_DEVICE, \
	0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
