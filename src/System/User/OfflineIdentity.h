// SPDX-License-Identifier: LGPL-2.1-or-later
// Offline identity for XUser sign-in on the account's designated offline PC.
//
// Windows keeps the last signed-in Xbox identity on the device, so a title's
// XUserAddAsync(AddDefaultUserSilently) can complete without a network while
// token requests fail until connectivity returns. This mirrors that for one
// prefix, but never on its own authority: the Nexus backend decides per
// launch, after its license decision, through XODUS_OFFLINE_IDENTITY:
//
//   use    The launch runs on a stored offline license that passed its lease
//          checks. When Microsoft is unreachable the cached identity may
//          complete the sign-in.
//   store  Microsoft issued this device an offline lease on this launch (it
//          is the designated offline device). A complete network sign-in may
//          refresh the cached identity.
//   unset  Neither. The cached identity is never read, and a complete network
//          sign-in removes it, so offline sign-in ends with offline licensing.
//
// Only what a title can observe is stored (XUID, gamertags, age group) plus
// the endpoint tables; never a token, ticket or key. The launcher names the
// account with an opaque XODUS_ACCOUNT_HASH; each account has its own
// directory and the launcher removes them all on sign-out, account change and
// every designation change. XODUS_FORCE_OFFLINE=1 makes the network sign-in
// fail as unreachable at once (the launcher already found Microsoft
// unreachable).
#pragma once
#include "../../private.h"
#include <winhttp.h>
#include <atomic>
#include <charconv>
#include <optional>
#include <string>
#include <string_view>

namespace nexus::user
{
enum class OfflineIdentityMode
{
    None,
    Store,
    Use,
};

inline constexpr unsigned OfflineIdentitySchema = 1;
// 30 days in 100 ns ticks: never longer than an offline content lease.
inline constexpr UINT64 OfflineIdentityMaxAge = 30ull * 24 * 3600 * 10000000ull;
inline constexpr SIZE_T OfflineIdentityMaxEndpoints = 1u << 20;

// Set once a user signed in from the cached identity; there is no internet
// for that session as far as titles are concerned.
inline std::atomic<bool> offlineIdentityInUse{ false };

inline OfflineIdentityMode ParseOfflineIdentityMode( std::string_view value ) noexcept
{
    if ( value == "use" ) return OfflineIdentityMode::Use;
    if ( value == "store" ) return OfflineIdentityMode::Store;
    return OfflineIdentityMode::None;
}

inline OfflineIdentityMode ReadOfflineIdentityMode() noexcept
{
    char value[8];
    DWORD length = GetEnvironmentVariableA( "XODUS_OFFLINE_IDENTITY", value, sizeof( value ) );
    if ( !length || length >= sizeof( value ) ) return OfflineIdentityMode::None;
    return ParseOfflineIdentityMode( std::string_view( value, length ) );
}

inline bool ForcedOffline() noexcept
{
    char value[4];
    DWORD length = GetEnvironmentVariableA( "XODUS_FORCE_OFFLINE", value, sizeof( value ) );
    return length == 1 && value[0] == '1';
}

// Name resolution, connect, timeout and connection errors: Microsoft could
// not be reached. Any other failure (a refusal, a malformed answer) is never
// replaced by the cached identity.
inline bool IsConnectivityFailure( HRESULT hr ) noexcept
{
    return hr == HRESULT_FROM_WIN32( ERROR_WINHTTP_TIMEOUT ) || hr == HRESULT_FROM_WIN32( ERROR_WINHTTP_NAME_NOT_RESOLVED ) ||
           hr == HRESULT_FROM_WIN32( ERROR_WINHTTP_CANNOT_CONNECT ) ||
           hr == HRESULT_FROM_WIN32( ERROR_WINHTTP_CONNECTION_ERROR );
}

inline UINT64 FileTimeNow() noexcept
{
    FILETIME time;
    GetSystemTimeAsFileTime( &time );
    return ( static_cast<UINT64>( time.dwHighDateTime ) << 32 ) | time.dwLowDateTime;
}

struct OfflineIdentity
{
    UINT64 xuid{};
    unsigned ageGroup{};
    UINT64 savedAt{};
    std::string gamertag, modernGamertag, modernGamertagSuffix, uniqueModernGamertag;
};

inline bool PrintableText( std::string_view text ) noexcept
{
    for ( unsigned char c : text )
        if ( c < 0x20 || c == 0x7f ) return false;
    return true;
}

inline std::optional<std::string> FormatOfflineIdentity( const OfflineIdentity &identity )
{
    if ( !identity.xuid || identity.gamertag.empty() || identity.gamertag.size() >= 16 ||
         identity.modernGamertag.size() >= 97 || identity.modernGamertagSuffix.size() >= 15 ||
         identity.uniqueModernGamertag.size() >= 101 )
        return std::nullopt;
    for ( auto text : { &identity.gamertag, &identity.modernGamertag, &identity.modernGamertagSuffix,
                        &identity.uniqueModernGamertag } )
        if ( !PrintableText( *text ) ) return std::nullopt;
    return "schema=" + std::to_string( OfflineIdentitySchema ) + "\nxuid=" + std::to_string( identity.xuid ) +
           "\nageGroup=" + std::to_string( identity.ageGroup ) + "\nsavedAt=" + std::to_string( identity.savedAt ) +
           "\ngamertag=" + identity.gamertag + "\nmodernGamertag=" + identity.modernGamertag +
           "\nmodernGamertagSuffix=" + identity.modernGamertagSuffix +
           "\nuniqueModernGamertag=" + identity.uniqueModernGamertag + "\n";
}

// Parses a stored identity and accepts it only while it is younger than the
// offline window and not dated in the future.
inline std::optional<OfflineIdentity> ParseOfflineIdentity( std::string_view text, UINT64 now )
{
    if ( text.size() > 4096 ) return std::nullopt;
    OfflineIdentity identity;
    UINT64 schema = 0;
    auto number = []( std::string_view value, UINT64 &out ) {
        auto [end, error] = std::from_chars( value.data(), value.data() + value.size(), out );
        return error == std::errc() && end == value.data() + value.size();
    };
    while ( !text.empty() )
    {
        auto newline = text.find( '\n' );
        auto line = text.substr( 0, newline );
        text = newline == std::string_view::npos ? std::string_view() : text.substr( newline + 1 );
        auto equals = line.find( '=' );
        if ( equals == std::string_view::npos ) continue;
        auto key = line.substr( 0, equals ), value = line.substr( equals + 1 );
        if ( !PrintableText( value ) ) return std::nullopt;
        UINT64 parsed = 0;
        if ( key == "schema" && !number( value, schema ) ) return std::nullopt;
        if ( key == "xuid" && !number( value, identity.xuid ) ) return std::nullopt;
        if ( key == "savedAt" && !number( value, identity.savedAt ) ) return std::nullopt;
        if ( key == "ageGroup" )
        {
            if ( !number( value, parsed ) ) return std::nullopt;
            identity.ageGroup = parsed <= static_cast<unsigned>( XUserAgeGroup::Adult ) ? static_cast<unsigned>( parsed ) : 0;
        }
        if ( key == "gamertag" ) identity.gamertag = value;
        if ( key == "modernGamertag" ) identity.modernGamertag = value;
        if ( key == "modernGamertagSuffix" ) identity.modernGamertagSuffix = value;
        if ( key == "uniqueModernGamertag" ) identity.uniqueModernGamertag = value;
    }
    if ( schema != OfflineIdentitySchema || !identity.xuid || identity.gamertag.empty() ||
         identity.gamertag.size() >= 16 || identity.modernGamertag.size() >= 97 ||
         identity.modernGamertagSuffix.size() >= 15 || identity.uniqueModernGamertag.size() >= 101 )
        return std::nullopt;
    if ( !identity.savedAt || now < identity.savedAt || now - identity.savedAt > OfflineIdentityMaxAge )
        return std::nullopt;
    return identity;
}

// The cached identity of one account in this prefix:
// %LOCALAPPDATA%\Xodus Nexus\offline-identity\<XODUS_ACCOUNT_HASH>.
class OfflineIdentityStore
{
public:
    static std::optional<OfflineIdentityStore> ForAccount()
    {
        WCHAR account[66], base[MAX_PATH];
        DWORD used = GetEnvironmentVariableW( L"XODUS_ACCOUNT_HASH", account, ARRAYSIZE( account ) );
        if ( used < 8 || used > 64 ) return std::nullopt;
        for ( DWORD i = 0; i < used; ++i )
            if ( !( ( account[i] >= '0' && account[i] <= '9' ) || ( account[i] >= 'a' && account[i] <= 'f' ) ) )
                return std::nullopt;
        DWORD length = GetEnvironmentVariableW( L"LOCALAPPDATA", base, ARRAYSIZE( base ) );
        if ( !length || length >= ARRAYSIZE( base ) ) return std::nullopt;
        std::wstring root( base, length );
        return OfflineIdentityStore( root + L"\\Xodus Nexus\\offline-identity\\" + std::wstring( account, used ) );
    }

    explicit OfflineIdentityStore( std::wstring directory ) : directory( std::move( directory ) ) {}

    const std::wstring &Directory() const noexcept
    {
        return directory;
    }

    bool Save( const OfflineIdentity &identity, std::string_view defaults, std::string_view current ) const
    {
        auto text = FormatOfflineIdentity( identity );
        if ( !text || defaults.empty() || current.empty() || defaults.size() > OfflineIdentityMaxEndpoints ||
             current.size() > OfflineIdentityMaxEndpoints || !CreateDirectories() )
            return false;
        // The identity is written last: without it the endpoint files are never read.
        return Write( L"endpoints-default.json", defaults ) && Write( L"endpoints-current.json", current ) &&
               Write( L"identity.txt", *text );
    }

    bool Load( UINT64 now, OfflineIdentity &identity, std::string &defaults, std::string &current ) const
    {
        std::string text;
        if ( !Read( L"identity.txt", 4096, text ) ) return false;
        auto parsed = ParseOfflineIdentity( text, now );
        if ( !parsed || !Read( L"endpoints-default.json", OfflineIdentityMaxEndpoints, defaults ) ||
             !Read( L"endpoints-current.json", OfflineIdentityMaxEndpoints, current ) )
            return false;
        identity = *parsed;
        return true;
    }

    void Remove() const noexcept
    {
        for ( auto name : { L"identity.txt", L"endpoints-default.json", L"endpoints-current.json" } )
        {
            DeleteFileW( Path( name ).c_str() );
            DeleteFileW( ( Path( name ) + L".tmp" ).c_str() );
        }
        RemoveDirectoryW( directory.c_str() );
    }

private:
    std::wstring directory;

    std::wstring Path( const WCHAR *name ) const
    {
        return directory + L"\\" + name;
    }

    bool CreateDirectories() const
    {
        for ( size_t at = directory.find( L'\\', 3 ); at != std::wstring::npos; at = directory.find( L'\\', at + 1 ) )
            CreateDirectoryW( directory.substr( 0, at ).c_str(), nullptr );
        return CreateDirectoryW( directory.c_str(), nullptr ) || GetLastError() == ERROR_ALREADY_EXISTS;
    }

    bool Write( const WCHAR *name, std::string_view data ) const
    {
        auto path = Path( name ), temporary = path + L".tmp";
        HANDLE file = CreateFileW( temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                                   nullptr );
        if ( file == INVALID_HANDLE_VALUE ) return false;
        DWORD written = 0;
        bool ok = WriteFile( file, data.data(), static_cast<DWORD>( data.size() ), &written, nullptr ) &&
                  written == data.size();
        CloseHandle( file );
        if ( ok && MoveFileExW( temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING ) ) return true;
        DeleteFileW( temporary.c_str() );
        return false;
    }

    bool Read( const WCHAR *name, SIZE_T limit, std::string &out ) const
    {
        HANDLE file = CreateFileW( Path( name ).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL, nullptr );
        if ( file == INVALID_HANDLE_VALUE ) return false;
        LARGE_INTEGER size{};
        bool ok = GetFileSizeEx( file, &size ) && size.QuadPart > 0 && static_cast<UINT64>( size.QuadPart ) <= limit;
        if ( ok )
        {
            out.assign( static_cast<size_t>( size.QuadPart ), '\0' );
            DWORD read = 0;
            ok = ReadFile( file, out.data(), static_cast<DWORD>( out.size() ), &read, nullptr ) && read == out.size();
        }
        CloseHandle( file );
        if ( !ok ) out.clear();
        return ok;
    }
};
}
