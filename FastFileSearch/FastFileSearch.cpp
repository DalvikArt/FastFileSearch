// FastFileSearch.cpp: 定义控制台应用程序的入口点。
//

#include "stdafx.h"

#include <string>
#include <vector>

#include "USNJournal.h"

using namespace std;

#include <windows.h>

using namespace std;

int wmain(int argc, WCHAR *argv[])
{
	DWORD err = ERROR_SUCCESS;

	vector<wstring> fileList = GetFileList(L"D", L".xml");

	if (fileList.size() != 0)
	{
		
	}
	else
	{
		err = GetLastError();
		cerr << "Get file list failed! Error: " << err << endl;
	}

	return err;
}