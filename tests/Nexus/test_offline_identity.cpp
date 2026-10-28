// SPDX-License-Identifier: MIT
#include <gtest/gtest.h>
#include "../../src/System/User/OfflineIdentity.h"
#include "../../src/System/Networking/Connectivity.h"
#include <string>

using namespace nexus::user;

namespace
{
constexpr UINT64 Day = 24ull * 3600 * 10000000ull;
constexpr UINT64 Now = 134000000000000000ull;

OfflineIdentity Sample()
{
    return { 1234567890123456ull, static_cast<unsigned>( XUserAgeGroup::Adult ), Now, "Synthetic", "Synthetic", "", "Synthetic" };
}

class TemporaryDirectory
{
public:
    TemporaryDirectory()
    {
        WCHAR base[MAX_PATH], name[MAX_PATH];
        GetTempPathW( MAX_PATH, base );
        GetTempFileNameW( base, L"oid", 0, name );
        DeleteFileW( name );
        path = name;
    }
    ~TemporaryDirectory()
    {
        OfflineIdentityStore( path + L"\\Xodus Nexus\\offline-identity\\0123456789abcdef" ).Remove();
        RemoveDirectoryW( ( path + L"\\Xodus Nexus\\offline-identity" ).c_str() );
        RemoveDirectoryW( ( path + L"\\Xodus Nexus" ).c_str() );
        RemoveDirectoryW( path.c_str() );
    }
    std::wstring path;
};

class Environment
{
public:
    Environment( const WCHAR *name, const WCHAR *value ) : name( name )
    {
        SetEnvironmentVariableW( name, value );
    }
    ~Environment()
    {
        SetEnvironmentVariableW( name, nullptr );
    }

private:
    const WCHAR *name;
};
}

TEST( NexusOfflineIdentity, TheBackendDecidesWhetherTheCacheIsUsedKeptOrNeither )
{
    EXPECT_EQ( ParseOfflineIdentityMode( "use" ), OfflineIdentityMode::Use );
    EXPECT_EQ( ParseOfflineIdentityMode( "store" ), OfflineIdentityMode::Store );
    for ( auto value : { "", "1", "USE", "use ", "true", "storeuse" } )
        EXPECT_EQ( ParseOfflineIdentityMode( value ), OfflineIdentityMode::None ) << value;
    SetEnvironmentVariableA( "XODUS_OFFLINE_IDENTITY", nullptr );
    EXPECT_EQ( ReadOfflineIdentityMode(), OfflineIdentityMode::None );
    {
        Environment use( L"XODUS_OFFLINE_IDENTITY", L"use" );
        EXPECT_EQ( ReadOfflineIdentityMode(), OfflineIdentityMode::Use );
    }
    {
        Environment longer( L"XODUS_OFFLINE_IDENTITY", L"use-and-more" );
        EXPECT_EQ( ReadOfflineIdentityMode(), OfflineIdentityMode::None );
    }
}

TEST( NexusOfflineIdentity, OnlyUnreachableNetworkFailuresQualify )
{
    for ( DWORD error : { ERROR_WINHTTP_TIMEOUT, ERROR_WINHTTP_NAME_NOT_RESOLVED, ERROR_WINHTTP_CANNOT_CONNECT,
                          ERROR_WINHTTP_CONNECTION_ERROR } )
        EXPECT_TRUE( IsConnectivityFailure( HRESULT_FROM_WIN32( error ) ) ) << error;
    for ( HRESULT hr : { E_FAIL, E_ACCESSDENIED, E_ABORT, HRESULT_FROM_WIN32( ERROR_WINHTTP_SECURE_FAILURE ), S_OK } )
        EXPECT_FALSE( IsConnectivityFailure( hr ) ) << hr;
}

TEST( NexusOfflineIdentity, StoredIdentityExpiresWithTheOfflineWindowAndRejectsAClockBehindIt )
{
    auto text = FormatOfflineIdentity( Sample() );
    ASSERT_TRUE( text );
    EXPECT_EQ( text->find( "token" ), std::string::npos );
    auto parsed = ParseOfflineIdentity( *text, Now + Day );
    ASSERT_TRUE( parsed );
    EXPECT_EQ( parsed->xuid, 1234567890123456ull );
    EXPECT_EQ( parsed->gamertag, "Synthetic" );
    EXPECT_EQ( parsed->ageGroup, static_cast<unsigned>( XUserAgeGroup::Adult ) );
    EXPECT_TRUE( ParseOfflineIdentity( *text, Now + 30 * Day ) );
    EXPECT_FALSE( ParseOfflineIdentity( *text, Now + 30 * Day + 1 ) );
    EXPECT_FALSE( ParseOfflineIdentity( *text, Now - 1 ) );
    auto other = *text;
    other.replace( other.find( "schema=1" ), 8, "schema=2" );
    EXPECT_FALSE( ParseOfflineIdentity( other, Now ) );
    EXPECT_FALSE( ParseOfflineIdentity( "schema=1\nxuid=x\n", Now ) );
    EXPECT_FALSE( ParseOfflineIdentity( std::string( 5000, 'a' ), Now ) );
    auto control = Sample();
    control.gamertag = "Bad\x01Tag";
    EXPECT_FALSE( FormatOfflineIdentity( control ) );
    auto anonymous = Sample();
    anonymous.xuid = 0;
    EXPECT_FALSE( FormatOfflineIdentity( anonymous ) );
}

TEST( NexusOfflineIdentity, EachAccountHasItsOwnDirectoryAndRemovalLeavesNothing )
{
    TemporaryDirectory root;
    Environment local( L"LOCALAPPDATA", root.path.c_str() );
    {
        Environment account( L"XODUS_ACCOUNT_HASH", L"not-hex" );
        EXPECT_FALSE( OfflineIdentityStore::ForAccount() );
    }
    {
        Environment account( L"XODUS_ACCOUNT_HASH", L"0123456" );
        EXPECT_FALSE( OfflineIdentityStore::ForAccount() );
    }
    SetEnvironmentVariableW( L"XODUS_ACCOUNT_HASH", nullptr );
    EXPECT_FALSE( OfflineIdentityStore::ForAccount() );
    Environment account( L"XODUS_ACCOUNT_HASH", L"0123456789abcdef" );
    auto store = OfflineIdentityStore::ForAccount();
    ASSERT_TRUE( store );
    EXPECT_EQ( store->Directory(), root.path + L"\\Xodus Nexus\\offline-identity\\0123456789abcdef" );
    auto identity = Sample();
    identity.savedAt = FileTimeNow();
    ASSERT_TRUE( store->Save( identity, R"({"EndPoints":[]})", R"({"EndPoints":[]})" ) );
    OfflineIdentity loaded;
    std::string defaults, current;
    ASSERT_TRUE( store->Load( FileTimeNow(), loaded, defaults, current ) );
    EXPECT_EQ( loaded.xuid, identity.xuid );
    EXPECT_EQ( defaults, R"({"EndPoints":[]})" );
    store->Remove();
    EXPECT_FALSE( store->Load( FileTimeNow(), loaded, defaults, current ) );
    EXPECT_EQ( GetFileAttributesW( store->Directory().c_str() ), INVALID_FILE_ATTRIBUTES );
}

TEST( NexusOfflineIdentity, AnOfflineSessionNeverReportsInternetAccess )
{
    XNetworkingConnectivityHint hint{};
    hint.connectivityLevel = XNetworkingConnectivityLevelHint::InternetAccess;
    nexus::networking::CapForOfflineIdentity( &hint, false );
    EXPECT_EQ( hint.connectivityLevel, XNetworkingConnectivityLevelHint::InternetAccess );
    nexus::networking::CapForOfflineIdentity( &hint, true );
    EXPECT_EQ( hint.connectivityLevel, XNetworkingConnectivityLevelHint::LocalAccess );
    hint.connectivityLevel = XNetworkingConnectivityLevelHint::None;
    nexus::networking::CapForOfflineIdentity( &hint, true );
    EXPECT_EQ( hint.connectivityLevel, XNetworkingConnectivityLevelHint::None );
    nexus::networking::CapForOfflineIdentity( nullptr, true );
}
