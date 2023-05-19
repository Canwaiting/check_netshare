/*********************************************************
*
* 项目背景：共享文件夹、盘会导致系统安全性下降，故IT部门
* 需要搜集公司中每台电脑的共享情况，并且进行上报
*
*********************************************************/

#include <fstream>
#include <iostream>
#include "mongoose.h"
#define _WIN32_DCOM
#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>
#include <string>
#include <time.h>
#include <sstream>
#include <iomanip> 
#pragma comment(lib, "wbemuuid.lib")
//#pragma comment( linker, "/subsystem:windows /entry:mainCRTStartup") //静默运行
using namespace std;

string wstring2string(wstring wstr, UINT nCode);
wstring string2wstring(string str);
LPCWSTR string2LPCWSTR(string str);
string WMIQuery(string table, string key);
string GetData();
string UploadData(string data);
string GetDateTime();
static void fn(struct mg_connection* c, int ev, void* ev_data, void* fn_data);
bool IsDefaultShare(string share_name, string share_path);
inline char* ConvertBSTRToString(BSTR pSrc);

//退出标志 用于控制关闭事件循环
static int exit_flag = 0; 
//APP版本信息 
static const string app = "versionV0.1";
//白名单
static const string white_lists[] =
{
	"IPC$",
	"ADMIN$",
	//"print$" 打印机，暂时不需要
};
//上传数据的地址前缀
static string url = "http://prefix.com/api/upload?"; //需要自己重新替换，这个是前缀，后续和data进行参数拼接

int main(int argc, char** argv)
{
    string data; 
    data = GetData(); 

    //拼接数据，并转成UTF-8
    url += data; 
    wstring wstr = string2wstring(url);
    url = wstring2string(wstr, CP_UTF8); 

    cout << url << endl;
    UploadData(url); 
    getchar();
 
    return 0; 
}

string GetData() 
{
    stringstream ss;
    string date_time = "";
    string host_name = "";
    string machine_code= "";
    string share_lists = "";
    string data = "";

    date_time = GetDateTime();
    host_name = WMIQuery("Win32_ComputerSystem", "Name"); 
	machine_code= WMIQuery("Win32_BIOS","SerialNumber"); 
	share_lists = WMIQuery("win32_share",""); //这个特殊处理


    ss << "&APP=" << app
	   << "&DateTime=" << date_time
	   << "&HostName=" << host_name
	   << "&MachineCode=" << machine_code
	   << "&ShareLists=" << share_lists;
    data = ss.str();


    /*
    cout << "**********" << endl;
    cout << "APP: " << app << endl;
    cout << "DateTime: " << date_time << endl;
    cout << "HostName: " << host_name << endl;
    cout << "MachineCode: " << machine_code<< endl;
    cout << "ShareLists: " << share_lists<< endl;
    cout << "**********" << endl;
    cout << "data: " << data << endl;;
    */

    return data;
}

string UploadData(string data)
{
    char* s_url = new char[strlen(url.c_str()) + 1];
    strcpy(s_url,url.c_str());

    struct mg_mgr mgr;
    mg_mgr_init(&mgr);                        // Init manager
    mg_http_connect(&mgr, s_url, fn, NULL);   // Create client connection 
    while (exit_flag == 0) {
        mg_mgr_poll(&mgr, 1000); 
    }
    mg_mgr_free(&mgr);                        // Cleanup

    string response = ""; //TODO 暂时没有什么要求
    return response; 
}

string WMIQuery(string table, string key) {
    HRESULT hres;
    string result = "";
    string empty_result = "";
    stringstream ss;

    // Step 1: --------------------------------------------------
    // Initialize COM. ------------------------------------------

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        cout << "Failed to initialize COM library. Error code = 0x"
            << hex << hres << endl;
         return empty_result;                  // Program has failed.
    }

    // Step 2: --------------------------------------------------
    // Set general COM security levels --------------------------

    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
    );


    if (FAILED(hres))
    {

        CoUninitialize();
        return empty_result;                  // Program has failed.
    }

    // Step 3: ---------------------------------------------------
    // Obtain the initial locator to WMI -------------------------

    IWbemLocator* pLoc = NULL;

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres))
    {
        CoUninitialize();
        return empty_result;                  // Program has failed.
    }

    // Step 4: -----------------------------------------------------
    // Connect to WMI through the IWbemLocator::ConnectServer method

    IWbemServices* pSvc = NULL;

    // Connect to the root\cimv2 namespace with
    // the current user and obtain pointer pSvc
    // to make IWbemServices calls.
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
        NULL,                    // User name. NULL = current user
        NULL,                    // User password. NULL = current
        0,                       // Locale. NULL indicates current
        NULL,                    // Security flags.
        0,                       // Authority (for example, Kerberos)
        0,                       // Context object 
        &pSvc                    // pointer to IWbemServices proxy
    );

    if (FAILED(hres))
    {
        cout << "Could not connect. Error code = 0x"
            << hex << hres << endl;
        pLoc->Release();
        CoUninitialize();
        return empty_result;                  // Program has failed.
    }

    //cout << "Connected to ROOT\\CIMV2 WMI namespace" << endl;


    // Step 5: --------------------------------------------------
    // Set security levels on the proxy -------------------------

    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hres))
    {
        cout << "Could not set proxy blanket. Error code = 0x"
            << hex << hres << endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return empty_result;                  // Program has failed.
    }

    // Step 6: --------------------------------------------------
    // Use the IWbemServices pointer to make requests of WMI ----

    // For example, get the name of the operating system
    IEnumWbemClassObject* pEnumerator = NULL;
    string sql = "SELECT * FROM " + table;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t((wchar_t*) (_bstr_t(sql.c_str()))),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres))
    {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return empty_result;                  // Program has failed.
    }

    // Step 7: -------------------------------------------------
    // Get the data from the query in step 6 -------------------

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator)
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
            &pclsObj, &uReturn);

        if (0 == uReturn)
        {
            break;
        }

        VARIANT vtProp;

        VariantInit(&vtProp);

        // Get the value of the Name property 
        if (key == "") {
			hr =  pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
            string share_name = _com_util::ConvertBSTRToString(vtProp.bstrVal);
			hr =  pclsObj->Get(L"Path", 0, &vtProp, 0, 0); 
            string share_path = _com_util::ConvertBSTRToString(vtProp.bstrVal);
            if (!IsDefaultShare(share_name, share_path))
            {
				ss << "\"" << share_name << "\"";
				ss << ":";
				ss << "\"" << share_path << "\"";
				ss << ","; 
            }
        }
        else {
			hr = pclsObj->Get(string2LPCWSTR(key), 0, &vtProp, 0, 0);
			ss << ConvertBSTRToString(vtProp.bstrVal); 
			//ss << _com_util::ConvertBSTRToString(vtProp.bstrVal); 
        }
        VariantClear(&vtProp);

        pclsObj->Release();
    }

    // Cleanup
    // ========

    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();

    result = ss.str();
    if (key == "") {
        result = result.substr(0, result.length() - 1);
    }
    return result; 
}

LPCWSTR string2LPCWSTR(string str)
{
    size_t size = str.length();
    int wLen = ::MultiByteToWideChar(CP_UTF8,
        0,
        str.c_str(),
        -1,
        NULL,
        0);
    wchar_t* buffer = new wchar_t[wLen + 1];
    memset(buffer, 0, (wLen + 1) * sizeof(wchar_t));
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), size, (LPWSTR)buffer, wLen);
    return buffer;
}
 
string GetDateTime()
{

    string date_time = "";
	time_t nowtime;
	time(&nowtime); //获取1970年1月1日0点0分0秒到现在经过的秒数
	tm tm_t;
	localtime_s(&tm_t, &nowtime); //将秒数转换为本地时间,年从1900算起,需要+1900,月为0-11,所以要+1
    stringstream ss;
    ss << tm_t.tm_year + 1900
       << setw(2) << setfill('0') << tm_t.tm_mon + 1
       << setw(2) << setfill('0') << tm_t.tm_mday
	   << " "
       << setw(2) << setfill('0') << tm_t.tm_hour 
       << ":" 
       << setw(2) << setfill('0') << tm_t.tm_min 
       << ":" 
       << setw(2) << setfill('0') << tm_t.tm_sec;
    date_time = ss.str();
    return date_time; 
}
 
//不上报默认的、在白名单内的共享盘
bool IsDefaultShare(string share_name, string share_path)
{
    //1、系统默认共享盘
    if (!share_name.empty() && !share_path.empty() &&  // 非空
        share_name[share_name.length() - 1] == '$' &&  // 共享名最后一个字符一定是$
        share_path.length() == 3 &&  // 资源必须为 X:\ 的格式
        share_name.substr(0,share_name.length() - 1) == share_path.substr(0,share_path.length() - 2))  // 盘符名一定要对得上 
    {
        return true;
    }
    //2、白名单
    for (string white_list_item : white_lists)
    {
        if (share_name == white_list_item)
        {
            return true;
        } 
    } 
    return false; 
}
 
static void fn(struct mg_connection* c, int ev, void* ev_data, void* fn_data)
{
    char* s_url = new char[strlen(url.c_str()) + 1];
    strcpy(s_url,url.c_str());
    if (ev == MG_EV_CONNECT) { 
        struct mg_str host = mg_url_host(s_url);
        // Send request
        mg_printf(c,
            "GET %s HTTP/1.0\r\n"
            "Host: %.*s\r\n"
            "\r\n",
            mg_url_uri(s_url), (int)host.len, host.ptr);
    } if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message* hm = (struct mg_http_message*)ev_data;
        exit_flag = 1;
    }
}

//重新实现_com_util的ConvertBSTRToString
inline char* ConvertBSTRToString(BSTR pSrc)
{
    //if (!pSrc) return NULL;  原本返回空会导致空指针异常
    if (!pSrc)
    {
        char* szOut = new char[1];
        szOut[0] = '\0';
        return szOut;
    }

    DWORD cb, cwch = ::SysStringLen(pSrc);

    char* szOut = NULL;

    if (cb = ::WideCharToMultiByte(CP_ACP, 0,
        pSrc, cwch + 1, NULL, 0, 0, 0))
    {
        szOut = new char[cb];
        if (szOut)
        {
            szOut[cb - 1] = '\0';

            if (!::WideCharToMultiByte(CP_ACP, 0,
                pSrc, cwch + 1, szOut, cb, 0, 0))
            {
                delete[]szOut;//clean up if failed;
                szOut = NULL;
            }
        }
    } 
    return szOut;
};

 wstring string2wstring(string str)
{
    wstring result;
    //获取缓冲区大小，并申请空间，缓冲区大小按字符计算  
    int len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.size(), NULL, 0);
    TCHAR* buffer = new TCHAR[len + 1];
    //多字节编码转换成宽字节编码  
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.size(), buffer, len);
    buffer[len] = '\0';             //添加字符串结尾  
    //删除缓冲区并返回值  
    result.append(buffer);
    delete[] buffer;
    return result;
}

string wstring2string(wstring wstr, UINT nCode)
{
    string result;
    //获取缓冲区大小，并申请空间，缓冲区大小事按字节计算的  
    int len = WideCharToMultiByte(nCode, 0, wstr.c_str(), wstr.size(), NULL, 0, NULL, NULL);
    char* buffer = new char[len + 1];
    //宽字节编码转换成多字节编码  
    WideCharToMultiByte(nCode, 0, wstr.c_str(), wstr.size(), buffer, len, NULL, NULL);
    buffer[len] = '\0';
    //删除缓冲区并返回值  
    result.append(buffer);
    delete[] buffer;
    return result;
}






