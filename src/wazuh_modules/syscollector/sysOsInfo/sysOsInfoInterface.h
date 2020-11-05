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

#ifndef _SYS_OS_INFO_INTERFACE_H
#define _SYS_OS_INFO_INTERFACE_H

#include <string>
#include <memory>
#include "json.hpp"

class ISysOsInfoProvider
{
public:
    virtual ~ISysOsInfoProvider() = default;
    virtual std::string name() const = 0;
    virtual std::string version() const = 0;
    virtual std::string majorVersion() const = 0;
    virtual std::string minorVersion() const = 0;
    virtual std::string build() const = 0;
    virtual std::string release() const = 0;
    virtual std::string machine() const = 0;
    virtual std::string nodeName() const = 0;
};


class SysOsInfo
{
public:
    SysOsInfo() =  default;
    ~SysOsInfo() = default;
    static void setOsInfo(const std::shared_ptr<ISysOsInfoProvider>& osInfoProvider,
                          nlohmann::json& output)
    {
        output["os_name"] = osInfoProvider->name();
        output["os_major"] = osInfoProvider->majorVersion();
        output["os_minor"] = osInfoProvider->minorVersion();
        output["os_build"] = osInfoProvider->build();
        output["os_version"] = osInfoProvider->version();
        output["hostname"] = osInfoProvider->nodeName();
        output["os_release"] = osInfoProvider->release();
        output["architecture"] = osInfoProvider->machine();
    }
};

#endif //_SYS_OS_INFO_INTERFACE_H