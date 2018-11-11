#include "main.h"

const char* CIpChanger::CONFIG_FILENAME = "samp-ip-changer.ini";
const char* CIpChanger::LOCAL_IP_ADDRESS = "127.0.0.1";

const CIpChanger::pattern_info CIpChanger::RAKPEER_INIT_PATTERN =
{
    "\x6A\x00\x50\x51\x6A\x01\x8B\xCB\xE8\x44\xE6\x00\x00",
    "xxxxxxxxx????",
    9
};

CIpChanger& CIpChanger::GetInstance()
{
    static CIpChanger s_Instance;
    return s_Instance;
}

void CIpChanger::Initialize()
{
    m_szNewIpAddress = GetNewIpAddress();
    CreateThread(NULL, 0, CIpChanger::Thread, NULL, 0, NULL);
}

void CIpChanger::SetHook(const urmem::address_t addr)
{
    m_ptrRakPeerInitHook = new rakpeer_init_hook_t(addr);

    m_ptrRakPeerInitHook->attach([](void* _this, unsigned short maxConnections, int localPort, int _threadSleepTimer, const char *forceHostAddress)
    {
        auto ip = CIpChanger::GetInstance().GetIP();
        return CIpChanger::GetInstance().GetHook()->call(_this, maxConnections, localPort, _threadSleepTimer, ip);
    }
    );
}

CIpChanger::rakpeer_init_hook_t* CIpChanger::GetHook() const
{
    return m_ptrRakPeerInitHook;
}

DWORD WINAPI CIpChanger::Thread(LPVOID lpParam)
{
    HMODULE hSampDll = NULL;
    while ((hSampDll = GetModuleHandle("samp.dll")) == NULL)
    {
        Sleep(50);
    }

    urmem::sig_scanner sc;
    sc.init(hSampDll);

    urmem::address_t addr;
    if (sc.find(RAKPEER_INIT_PATTERN.pattern, RAKPEER_INIT_PATTERN.mask, addr))
    {
        addr += RAKPEER_INIT_PATTERN.offset;
        urmem::address_t hook_addr = addr + (*(urmem::address_t*)(addr)) + sizeof(urmem::address_t);
        CIpChanger::GetInstance().SetHook(hook_addr);
        return S_OK;
    }
    return S_FALSE;
}

const char* CIpChanger::ReadIpAddress(const char* filename) const
{
    static CSimpleIniA ini;
    ini.LoadFile(filename);
    return ini.GetValue("Settings", "ip", CIpChanger::LOCAL_IP_ADDRESS);
}

const char* CIpChanger::GetNewIpAddress() const
{
    static std::string s_strIpAddress = ReadIpAddress(CIpChanger::CONFIG_FILENAME);
    if (s_strIpAddress != CIpChanger::LOCAL_IP_ADDRESS)
    {
        return s_strIpAddress.c_str();
    }
    return nullptr;
}

const char* CIpChanger::GetIP()
{
    return m_szNewIpAddress;
}

CIpChanger::~CIpChanger()
{
    delete m_ptrRakPeerInitHook;
}