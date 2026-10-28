// SPDX-License-Identifier: LGPL-2.1-or-later
// Independent WinRT ABI/registration probe. Never requests an account license.
#define INITGUID
#include <windows.h>
#include <inspectable.h>
#include <roapi.h>
#include <winstring.h>
#include <cstdio>
struct StoreContext : IInspectable
{
    virtual HRESULT STDMETHODCALLTYPE User(IInspectable **)=0;
    virtual HRESULT STDMETHODCALLTYPE Add(IUnknown *,INT64 *)=0;
    virtual HRESULT STDMETHODCALLTYPE Remove(INT64)=0;
    virtual HRESULT STDMETHODCALLTYPE Purchase(HSTRING,HSTRING,IInspectable **)=0;
    virtual HRESULT STDMETHODCALLTYPE Collections(HSTRING,HSTRING,IInspectable **)=0;
    virtual HRESULT STDMETHODCALLTYPE AppLicense(IInspectable **)=0;
};
struct Statics : IInspectable
{
    virtual HRESULT STDMETHODCALLTYPE Default(StoreContext **)=0;
    virtual HRESULT STDMETHODCALLTYPE ForUser(IInspectable *,StoreContext **)=0;
};
static const GUID staticsId={0x9c06ee5f,0x15c0,0x4e72,{0x93,0x30,0xd6,0x19,0x1c,0xeb,0xd1,0x9c}};
static unsigned checks,failures;
#define CHECK(expr) do {++checks;if(!(expr)){++failures;printf("FAIL line=%d\n",__LINE__);}}while(0)
int main()
{
    HRESULT init=RoInitialize(RO_INIT_MULTITHREADED);
    CHECK(SUCCEEDED(init));
    HSTRING name=nullptr;
    const WCHAR *text=L"Windows.Services.Store.StoreContext";
    CHECK(WindowsCreateString(text,wcslen(text),&name)==S_OK);
    Statics *factory=nullptr;
    CHECK(RoGetActivationFactory(name,staticsId,(void **)&factory)==S_OK && factory);
    WindowsDeleteString(name);
    if(factory)
    {
        CHECK(factory->Default(nullptr)==E_POINTER);
        StoreContext *context=nullptr;
        CHECK(factory->Default(&context)==S_OK && context);
        if(context)
        {
            CHECK(context->AppLicense(nullptr)==E_POINTER);
            CHECK(context->User(nullptr)==E_POINTER);
            IInspectable *user=reinterpret_cast<IInspectable *>(1);
            CHECK(context->User(&user)==S_OK && !user);
            CHECK(context->QueryInterface(IID_IUnknown,nullptr)==E_POINTER);
            StoreContext *other=nullptr;
            CHECK(factory->ForUser(context,&other)==E_NOTIMPL && !other);
            CHECK(factory->ForUser(nullptr,&other)==S_OK && other==context);
            if(other)other->Release();
            context->Release();
        }
        factory->Release();
    }
    if(SUCCEEDED(init))RoUninitialize();
    printf("CHECKS %u FAILURES %u\n",checks,failures);
    return failures?1:0;
}
