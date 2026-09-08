"""実際の画面JSでQR読取の成功・失敗・競合とスキャン前検証を実行する。"""
import shutil
import subprocess
from pathlib import Path

import pytest


def test_totp_preview_browser_state():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js が必要")
    html = Path("templates/dashboard.html").read_text()
    logic = html[html.index("let totpPreviewVersion = 0;"):html.index("async function uploadFile(file)")]
    script = r'''
const assert = require('assert');
const nodes = {};
for (const id of ['upMfaTotpQr','upMfaTotpQrStatus','cfgMfaTotpUri','cfgMfaTotpSecret',
                  'cfgMfaTotpQr','cfgMfaTotpDigits','cfgMfaTotpPeriod','cfgMfaTotpAlgorithm','cfgMfaType']) {
  nodes[id] = {value:'', textContent:'', files:[{}], handlers:{}, addEventListener(type, fn){this.handlers[type]=fn;}};
}
global.document = {getElementById:id => nodes[id]};
global.FormData = class {append(){}};
let alerts = 0;
global.alert = () => { alerts++; };
let resolve;
global.fetch = () => new Promise(r => { resolve = r; });
''' + logic + r'''
(async () => {
  wireTotpQrPreview();
  nodes.cfgMfaTotpSecret.value = 'OLD_SECRET';
  const first = nodes.upMfaTotpQr.handlers.change();
  assert.equal(nodes.cfgMfaTotpSecret.value, '');
  assert.equal(validateTotpReadiness(), false);
  resolve({ok:true,json:async()=>({secret:'NEW_SECRET',issuer:'<script>unsafe</script>',label:'alice',digits:8,period:45,algorithm:'SHA256'})});
  await first;
  assert.equal(nodes.cfgMfaTotpSecret.value, 'NEW_SECRET');
  assert.equal(nodes.cfgMfaTotpDigits.value, 8);
  assert.equal(nodes.cfgMfaTotpPeriod.value, 45);
  assert.equal(nodes.cfgMfaType.value, 'totp');
  assert(nodes.upMfaTotpQrStatus.textContent.includes('TOTPとして読取済み'));
  assert(!nodes.upMfaTotpQrStatus.textContent.includes('NEW_SECRET'));
  assert.equal(validateTotpReadiness(), true);
  const failed = nodes.upMfaTotpQr.handlers.change();
  resolve({ok:false,json:async()=>({error:'画像を確認してください'})});
  await failed;
  assert.equal(nodes.cfgMfaTotpSecret.value, '');
  assert.equal(validateTotpReadiness(), false);
  assert(nodes.upMfaTotpQrStatus.textContent.includes('画像を確認してください'));
  nodes.cfgMfaType.value = '';
  nodes.cfgMfaType.handlers.input();
  assert.equal(validateTotpReadiness(), true);
  nodes.cfgMfaType.value = 'totp';
  assert.equal(validateTotpReadiness(), false);

  const stale = nodes.upMfaTotpQr.handlers.change();
  nodes.cfgMfaTotpSecret.value = 'MANUAL_SECRET';
  nodes.cfgMfaTotpSecret.handlers.input();
  resolve({ok:true,json:async()=>({secret:'STALE_SECRET'})});
  await stale;
  assert.equal(nodes.cfgMfaTotpSecret.value, 'MANUAL_SECRET');
  assert.equal(validateTotpReadiness(), true);
  const older = nodes.upMfaTotpQr.handlers.change();
  const resolveOlder = resolve;
  const newer = nodes.upMfaTotpQr.handlers.change();
  resolve({ok:true,json:async()=>({secret:'LATEST',digits:6,period:30,algorithm:'SHA1'})});
  await newer;
  resolveOlder({ok:false,json:async()=>({error:'古いエラー'})});
  await older;
  assert.equal(nodes.cfgMfaTotpSecret.value,'LATEST');
  assert(!nodes.upMfaTotpQrStatus.textContent.includes('古いエラー'));
})().catch(error => {console.error(error);process.exit(1);});
'''
    completed = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=10)
    assert completed.returncode == 0, completed.stderr
