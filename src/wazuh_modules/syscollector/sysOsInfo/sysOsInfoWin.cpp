/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2020, Wazuh Inc.
 * November 3, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <windows.h>
#include <versionhelpers.h>
#include <sysinfoapi.h>
#include <map>
#include "sysOsInfoWin.h"
#include "sysOsInfoWin.h"
#include "stringHelper.h"
#include "registryHelper.h"

static std::string getVersion(const bool isMinor = false)
{
    std::string version;
    if(IsWindowsVistaOrGreater())
    {
        Utils::Registry currentVersion{HKEY_LOCAL_MACHINE, R"(SOFTWARE\Microsoft\Windows NT\CurrentVersion)"};
        if (IsWindows8OrGreater())
        {
            const auto versionNumber{currentVersion.dword(isMinor ? "CurrentMinorVersionNumber" : "CurrentMajorVersionNumber")};
            version = std::to_string(versionNumber);
        }
        else
        {
            enum OS_VERSION
            {
                MAJOR_VERSION,
                MINOR_VERSION,
                MAX_VERSION
            };
            const auto fullVersion{currentVersion.string("CurrentVersion")};
            const auto majorAndMinor{Utils::split(fullVersion, '.')};
            if (majorAndMinor.size() == MAX_VERSION)
            {
                version = isMinor ? majorAndMinor[MINOR_VERSION] : majorAndMinor[MAJOR_VERSION];
            }
        }
    }
    else
    {
        OSVERSIONINFOEX osvi{};
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
        if (GetVersionEx (reinterpret_cast<OSVERSIONINFO*>(&osvi)))
        {
            version = std::to_string(isMinor ? osvi.dwMinorVersion : osvi.dwMajorVersion);
        }
        else
        {
            osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
            if (GetVersionEx (reinterpret_cast<OSVERSIONINFO*>(&osvi)))
            {
                version = std::to_string(isMinor ? osvi.dwMinorVersion : osvi.dwMajorVersion);
            }
        }
    }
    return version;
}

static std::string getBuild()
{
    std::string build;
    if(IsWindowsVistaOrGreater())
    {
        Utils::Registry currentVersion{HKEY_LOCAL_MACHINE, R"(SOFTWARE\Microsoft\Windows NT\CurrentVersion)"};
        build = currentVersion.string("CurrentBuildNumber");
    }
    else
    {
        OSVERSIONINFOEX osvi{};
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
        if (GetVersionEx (reinterpret_cast<OSVERSIONINFO*>(&osvi)))
        {
            build = std::to_string(osvi.dwBuildNumber & 0xFFFF);
        }
        else
        {
            osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
            if (GetVersionEx (reinterpret_cast<OSVERSIONINFO*>(&osvi)))
            {
                build = std::to_string(osvi.dwBuildNumber & 0xFFFF);
            }
        }
    }
    return build;
}

static std::string getRelease(const std::string& build)
{
    static const std::string SERVICE_PACK_PREFIX{"Service Pack"};
    static const std::map<std::string, std::string> BUILD_RELEASE_MAP
    {
        {"10240", "1507"},
        {"10586", "1511"},
        {"14393", "1607"},
        {"15063", "1709"},
        {"17134", "1803"},
        {"17763", "1809"},
        {"18362", "1903"},
        {"18363", "1909"},
    };
    std::string release;
    Utils::Registry currentVersion{HKEY_LOCAL_MACHINE, R"(SOFTWARE\Microsoft\Windows NT\CurrentVersion)"};
    if(IsWindows8OrGreater())
    {
        if(!currentVersion.string("ReleaseId", release))
        {
            const auto it{BUILD_RELEASE_MAP.find(build)};
            if (it != BUILD_RELEASE_MAP.end())
            {
                release = it->second;
            }
        }
    }
    if (release.empty())
    {
        std::string sp;
        if (currentVersion.string("CSDVersion", sp))
        {
            if (Utils::startsWith(sp, SERVICE_PACK_PREFIX))
            {
                release = "sp" + Utils::trim(sp.substr(SERVICE_PACK_PREFIX.size()));
            }
        }
        else
        {
            Utils::Registry currentVersion64{HKEY_LOCAL_MACHINE, R"(SOFTWARE\Microsoft\Windows NT\CurrentVersion)", KEY_READ | KEY_WOW64_64KEY};
            if (currentVersion64.string("CSDVersion", sp))
            {
                if (Utils::startsWith(sp, SERVICE_PACK_PREFIX))
                {
                    release = "sp" + Utils::trim(sp.substr(SERVICE_PACK_PREFIX.size()));
                }
            }
        }
    }
    return release;
}

static std::string getName()
{
    std::string name;
    static const std::string MSFT_PREFIX{"Microsoft"};
    constexpr auto SM_SERVER32_VALUE{89};//www.docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getsystemmetrics
    Utils::Registry currentVersion{HKEY_LOCAL_MACHINE, R"(SOFTWARE\Microsoft\Windows NT\CurrentVersion)"};
    if (currentVersion.string("ProductName", name))
    {
        name = Utils::startsWith(name, MSFT_PREFIX) ? name : MSFT_PREFIX + " " + name;
    }
    else if(IsWindowsVistaOrGreater())
    {
        name = "Windows undefined version";
    }
    else
    {
        OSVERSIONINFOEX osvi{};
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
        auto result{GetVersionEx (reinterpret_cast<OSVERSIONINFO*>(&osvi))};
        if (!result)
        {
            osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
            result = GetVersionEx (reinterpret_cast<OSVERSIONINFO*>(&osvi));
        }
        if (result)
        {
            if (osvi.dwMajorVersion == 5)
            {
                if (osvi.dwMajorVersion <= 1)
                {
                    name = osvi.dwMajorVersion == 0 ? "Microsoft Windows 2000" : "Microsoft Windows XP";
                }
                else
                {
                    SYSTEM_INFO si{};
                    GetNativeSystemInfo(&si);
                    if (osvi.wProductType == VER_NT_WORKSTATION && si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
                    {
                        name = "Microsoft Windows XP Professional x64 Edition";
                    }
                    else if (GetSystemMetrics(SM_SERVER32_VALUE))
                    {
                        name = "Microsoft Windows Server 2003 R2";
                    }
                    else
                    {
                        name = "Microsoft Windows Server 2003";
                    }
                }
            }
        }
    }
    return name.empty() ? "Microsoft Windows" : name;
}

static std::string getMachine()
{
    static const std::map<std::string, std::string> ARCH_MAP
    {
        {"AMD64",   "x86_64"},
        {"IA64",    "x86_64"},
        {"ARM64",   "x86_64"},
        {"x86",     "i686"},
    };
    std::string machine{"unknown"};
    Utils::Registry environment{HKEY_LOCAL_MACHINE, R"(System\CurrentControlSet\Control\Session Manager\Environment)"};
    const auto arch{environment.string("PROCESSOR_ARCHITECTURE")};
    const auto it{ARCH_MAP.find(arch)};
    if (it != ARCH_MAP.end())
    {
        machine = it->second;
    }
    return machine;
}

static std::string getNodeName()
{
    std::string nodeName;
    Utils::Registry activeComputerName{HKEY_LOCAL_MACHINE, R"(System\CurrentControlSet\Control\ComputerName\ActiveComputerName)"};
    if (!activeComputerName.string("ComputerName", nodeName))
    {
        nodeName = "unknown";
    }
    return nodeName;
}

SysOsInfoProviderWindows::SysOsInfoProviderWindows()
: m_majorVersion{getVersion()}
, m_minorVersion{getVersion(true)}
, m_build{getBuild()}
, m_version{m_majorVersion + "." + m_minorVersion + "." + m_build}
, m_release{getRelease(m_build)}
, m_name{getName()}
, m_machine{getMachine()}
, m_nodeName{getNodeName()}
{ 
}
std::string SysOsInfoProviderWindows::name() const
{
    return m_name;
}
std::string SysOsInfoProviderWindows::version() const
{
    return m_version;
}
std::string SysOsInfoProviderWindows::majorVersion() const
{
    return m_majorVersion;
}
std::string SysOsInfoProviderWindows::minorVersion() const
{
    return m_minorVersion;
}
std::string SysOsInfoProviderWindows::build() const
{
    return m_build;
}
std::string SysOsInfoProviderWindows::release() const
{
    return m_release;
}
std::string SysOsInfoProviderWindows::machine() const
{
    return m_machine;
}
std::string SysOsInfoProviderWindows::nodeName() const
{
    return m_nodeName;
}