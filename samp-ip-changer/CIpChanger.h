#pragma once
class CIpChanger
{
public:
    using rakpeer_init_hook_t = urmem::smart_hook<0, urmem::calling_convention::thiscall, bool(void*, unsigned short, int, int, const char*)>;

    static CIpChanger& GetInstance();

    void Initialize();
    void SetHook(const urmem::address_t addr);
    CIpChanger::rakpeer_init_hook_t* CIpChanger::GetHook() const;
    const char* GetIP();

private:
    CIpChanger() = default;
    ~CIpChanger();

    struct pattern_info
    {
        const char* pattern;
        const char* mask;
        unsigned int offset;
    };

    static DWORD WINAPI Thread(LPVOID lpParam);

    const char* ReadIpAddress(const char* filename) const;
    const char* GetNewIpAddress() const;

    static const char* CONFIG_FILENAME;
    static const char* LOCAL_IP_ADDRESS;
    static const pattern_info RAKPEER_INIT_PATTERN;

    const char* m_szNewIpAddress;
    rakpeer_init_hook_t* m_ptrRakPeerInitHook;
};
