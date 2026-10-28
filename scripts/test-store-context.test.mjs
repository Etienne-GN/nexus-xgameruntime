// SPDX-License-Identifier: MIT
import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {fileURLToPath} from 'node:url';
const root=new URL('../',import.meta.url);
const read=name=>fs.readFileSync(new URL(name,root),'utf8');
test('StoreContext and its standalone receipt fixture declare their own clock dependency',()=>{
 for(const file of ['src/System/Store/StoreContext.h','tests/Nexus/store-context.cpp']){
  const source=read(file);
  assert.match(source,/#include <ctime>/);
  assert.match(source,/std::time\(/);
  assert.doesNotMatch(source,/(?<!std::)\btime\(/);
 }
});
test('StoreContext uses the existing receipt transport without a stale global license cache',()=>{
 const objects=read('src/System/Store/StoreContext.h');
 const transport=read('src/System/Store/StoreContextLicense.h');
 assert.doesNotMatch(objects,/license_cached|LICENSE_REUSE_MS/);
 assert.match(objects,/query_game_license\( &license, operation->canceled \)/);
 assert.match(transport,/entitled_begin\([\s\S]*TRUE, TRUE \)/);
 assert.match(transport,/XAsyncGetResult\( &block, &entitled_game_identity/);
 assert.doesNotMatch(transport,/https?:\/\//);
 assert.match(objects,/if \( user \) return E_NOTIMPL/);
});
test('current-game query omits related product hints and keeps verified enumeration',()=>{
 const query=read('src/System/XStore.cpp').split('XStoreQueryProductForCurrentGameAsync')[1].split('XStoreQueryProductForCurrentGameResult')[0];
 assert.match(query,/entitled_begin\([^;]*FALSE, TRUE \)/);
 assert.match(read('src/System/Store/Entitled.h'),/!current_only && i < entitled_related_count/);
});
test('both ABI export lists and account-free native gates include StoreContext',()=>{
 for(const name of ['src/xgameruntime.def','src/xgameruntime-x86.def']){
  assert.match(read(name),/DllGetActivationFactory/);assert.match(read(name),/DllCanUnloadNow/);
 }
 const probe=read('tests/Nexus/store-context-raw.cpp');
 assert.match(probe,/RoGetActivationFactory/);
 assert.match(probe,/AppLicense\(nullptr\)/);
 assert.doesNotMatch(probe,/AppLicense\(&/);
 assert.match(read('scripts/test-component.mjs'),/\['nexus_store-context', 61\]/);
 assert.match(read('scripts/test-store.mjs'),/\['store-context-raw',11\]/);
});
