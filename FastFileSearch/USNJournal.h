#pragma once

#include <Windows.h>
#include <vector>

std::vector<std::wstring> &GetFileList(LPCWSTR volume, LPCWSTR extName);
