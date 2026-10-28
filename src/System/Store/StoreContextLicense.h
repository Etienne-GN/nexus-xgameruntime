// SPDX-License-Identifier: LGPL-2.1-or-later
// Production receipt transport, separate from the account-free WinRT ABI tests.
namespace nexus_store_context
{
static HRESULT query_game_license( XStoreGameLicense *out, const std::atomic<bool> &canceled )
{
    XStoreContextHandle store = nullptr;
    XTaskQueueHandle queue = nullptr;
    IXThreadingImpl *threading = nullptr;
    XAsyncBlock block = {};
    *out = {};
    for ( int i = 0; i < 300 && !canceled && !nexus::GetGameConfiguration(); ++i ) Sleep( 100 );
    if ( canceled ) return E_ABORT;
    if ( !GetStoreProductId() ) return E_GAME_MISSING_GAME_CONFIG;
    HRESULT hr = entitled_store_create( nullptr, &store );
    if ( FAILED( hr ) ) return hr;
    if ( SUCCEEDED( hr = QueryApiImpl( CLSID_XThreadingImpl, IID_IXThreadingImpl, (void **)&threading ) ) &&
         SUCCEEDED( hr = threading->XTaskQueueCreate( XTaskQueueDispatchMode::ThreadPool,
                                                      XTaskQueueDispatchMode::ThreadPool, &queue ) ) )
    {
        block.queue = queue;
        hr = entitled_begin( store, static_cast<UINT32>( XStoreProductKind::Game ), ENTITLED_MAX_PRODUCTS, &block, TRUE, TRUE );
        if ( SUCCEEDED( hr ) ) hr = threading->XAsyncGetStatus( &block, TRUE );
        if ( SUCCEEDED( hr ) ) hr = threading->XAsyncGetResult( &block, &entitled_game_identity, sizeof( *out ), out, nullptr );
        threading->XTaskQueueCloseHandle( queue );
    }
    if ( threading ) threading->Release();
    entitled_store_close( store );
    if ( SUCCEEDED( hr ) && !out->isActive ) hr = E_ACCESSDENIED;
    return hr;
}
}
