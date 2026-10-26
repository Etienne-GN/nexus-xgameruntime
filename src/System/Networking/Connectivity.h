// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <xnetworking.h>
#include <vector>
#include <new>

namespace nexus::networking
{
inline bool IsUsableAddress( const SOCKET_ADDRESS &socket ) noexcept
{
    if ( !socket.lpSockaddr || socket.iSockaddrLength < static_cast<int>( sizeof( ADDRESS_FAMILY ) ) ) return false;
    if ( socket.lpSockaddr->sa_family == AF_INET &&
         socket.iSockaddrLength >= static_cast<int>( sizeof( sockaddr_in ) ) )
    {
        auto address = reinterpret_cast<const sockaddr_in *>( socket.lpSockaddr );
        auto value = ntohl( address->sin_addr.s_addr );
        return value && ( value >> 24 ) != 127 && ( value >> 28 ) != 14 && value != 0xffffffff;
    }
    if ( socket.lpSockaddr->sa_family == AF_INET6 &&
         socket.iSockaddrLength >= static_cast<int>( sizeof( sockaddr_in6 ) ) )
    {
        auto address = reinterpret_cast<const sockaddr_in6 *>( socket.lpSockaddr );
        return !IN6_IS_ADDR_UNSPECIFIED( &address->sin6_addr ) && !IN6_IS_ADDR_LOOPBACK( &address->sin6_addr ) &&
               !IN6_IS_ADDR_MULTICAST( &address->sin6_addr );
    }
    return false;
}

inline HRESULT MapConnectivity( const IP_ADAPTER_ADDRESSES *adapters, XNetworkingConnectivityHint *hint ) noexcept
{
    if ( !hint ) return E_POINTER;
    *hint = {};
    XNetworkingConnectivityHint result{};
    result.networkInitialized = TRUE;
    result.connectivityLevel = XNetworkingConnectivityLevelHint::None;
    result.connectivityCost = XNetworkingConnectivityCostHint::Unknown;
    unsigned count = 0;
    for ( auto adapter = adapters; adapter; adapter = adapter->Next )
    {
        if ( ++count > 1024 ) return HRESULT_FROM_WIN32( ERROR_INVALID_DATA );
        if ( adapter->OperStatus != IfOperStatusUp || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK ) continue;
        bool address = false, gateway = false;
        unsigned addresses = 0, gateways = 0;
        for ( auto item = adapter->FirstUnicastAddress; item; item = item->Next )
        {
            if ( ++addresses > 1024 ) return HRESULT_FROM_WIN32( ERROR_INVALID_DATA );
            address = address || IsUsableAddress( item->Address );
        }
        if ( !address ) continue;
        for ( auto item = adapter->FirstGatewayAddress; item; item = item->Next )
        {
            if ( ++gateways > 1024 ) return HRESULT_FROM_WIN32( ERROR_INVALID_DATA );
            gateway = gateway || IsUsableAddress( item->Address );
        }
        auto level =
            gateway ? XNetworkingConnectivityLevelHint::InternetAccess : XNetworkingConnectivityLevelHint::LocalAccess;
        if ( static_cast<unsigned>( level ) > static_cast<unsigned>( result.connectivityLevel ) )
        {
            result.connectivityLevel = level;
            result.ianaInterfaceType = adapter->IfType;
        }
    }
    // A gateway is only a connectivity hint. It is not evidence of reachable
    // game services, an authenticated account, or unrestricted/metered cost.
    *hint = result;
    return S_OK;
}

// A session signed in from the cached offline identity has no internet as far
// as titles are concerned, whatever the adapters report.
inline void CapForOfflineIdentity( XNetworkingConnectivityHint *hint, bool offlineIdentity ) noexcept
{
    if ( hint && offlineIdentity && hint->connectivityLevel == XNetworkingConnectivityLevelHint::InternetAccess )
        hint->connectivityLevel = XNetworkingConnectivityLevelHint::LocalAccess;
}

inline HRESULT ReadConnectivity( XNetworkingConnectivityHint *hint ) noexcept
{
    if ( !hint ) return E_POINTER;
    *hint = {};
    try
    {
        std::vector<BYTE> bytes;
        ULONG size = 0;
        for ( unsigned retry = 0; retry < 5; ++retry )
        {
            constexpr ULONG flags =
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_INCLUDE_GATEWAYS;
            auto status = GetAdaptersAddresses(
                AF_UNSPEC, flags, nullptr,
                bytes.empty() ? nullptr : reinterpret_cast<IP_ADAPTER_ADDRESSES *>( bytes.data() ), &size );
            if ( status == NO_ERROR )
                return MapConnectivity(
                    bytes.empty() ? nullptr : reinterpret_cast<IP_ADAPTER_ADDRESSES *>( bytes.data() ), hint );
            if ( status == ERROR_NO_DATA ) return MapConnectivity( nullptr, hint );
            if ( status != ERROR_BUFFER_OVERFLOW ) return HRESULT_FROM_WIN32( status );
            if ( !size || size > 16 * 1024 * 1024 ) return HRESULT_FROM_WIN32( ERROR_INVALID_DATA );
            bytes.resize( size );
        }
        return HRESULT_FROM_WIN32( ERROR_RETRY );
    }
    catch ( const std::bad_alloc & )
    {
        return E_OUTOFMEMORY;
    }
}
}
