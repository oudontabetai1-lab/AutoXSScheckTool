"""
WScan Report Generator
Generates a self-contained HTML security assessment report.
"""
import datetime
import json
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from .scanners.base import Finding

if TYPE_CHECKING:
    from .attack_planner import PageAttackPlan

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"

# Plain JS for the offline report's screen-transition map (compact / shots / explorer
# modes). Kept as a normal string (single braces) so it can sit inside an f-string
# without brace-escaping. Reads the global `RPT_SM_NODES` injected before it.
_RPT_SITEMAP_JS = r"""
(function() {
  var NS = 'http://www.w3.org/2000/svg';
  var svg = document.getElementById('rpt-sm-svg');
  var explorer = document.getElementById('rpt-sm-explorer');
  var wrap = document.getElementById('rpt-sm-wrap');
  var pop = document.getElementById('rpt-sm-pop');
  var tip = document.getElementById('rpt-sm-tip');
  if (!svg || !wrap) return;

  var all = {}, children = {}, desc = {};
  RPT_SM_NODES.forEach(function(n) { all[n.url] = n; });
  Object.keys(all).forEach(function(u) {
    var p = all[u].parent;
    if (p && all[p]) (children[p] = children[p] || []).push(u);
  });
  function count(u) { if (desc[u] != null) return desc[u]; var c = 0; (children[u] || []).forEach(function(k){ c += 1 + count(k); }); desc[u] = c; return c; }
  Object.keys(all).forEach(count);

  var st = { mode: 'compact', collapsed: {}, search: '', view: { scale: 1, tx: 0, ty: 0 }, selected: null, autoCollapsed: false };
  if (Object.keys(all).length > 12) {
    Object.keys(all).forEach(function(u) { if ((children[u] || []).length >= 6) st.collapsed[u] = true; });
  }

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function(c){ return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]; }); }
  function color(n) { if (n.status === 'vuln') return '#f85149'; if (n.status === 'scanning') return '#f0883e'; if (n.status === 'done') return '#388bfd'; return '#3a3f4a'; }
  function short(url) { try { var p = new URL(url).pathname || '/'; return p.length > 22 ? '…' + p.slice(-20) : p; } catch(e) { return (url || '').slice(-20); } }
  function norm(via) {
    if (!via || !via.rect || !via.viewport || !via.viewport.w || !via.viewport.h) return null;
    var r = via.rect, v = via.viewport;
    // クランプ前の端点。スクショ範囲外（下方向にスクロールした要素等）だと 0..1 を外れる。
    var x1 = r.x/v.w, y1 = r.y/v.h, x2 = (r.x+r.w)/v.w, y2 = (r.y+r.h)/v.h;
    var offscreen = x1 < 0 || y1 < 0 || x2 > 1 || y2 > 1;
    var cl = function(x){ return Math.max(0, Math.min(1, x)); };
    var cx1 = cl(x1), cy1 = cl(y1), cx2 = cl(x2), cy2 = cl(y2), MIN = 0.05;
    // クランプで潰れる軸は最も近い端に最小サイズで固定し、範囲外でも赤い囲みが必ず見えるようにする。
    if (cx2 - cx1 < MIN) { if (x2 <= 0) { cx1 = 0; cx2 = MIN; } else if (x1 >= 1) { cx2 = 1; cx1 = 1 - MIN; } else { var xc = cl((cx1+cx2)/2); cx1 = Math.max(0, Math.min(1-MIN, xc-MIN/2)); cx2 = cx1+MIN; } }
    if (cy2 - cy1 < MIN) { if (y2 <= 0) { cy1 = 0; cy2 = MIN; } else if (y1 >= 1) { cy2 = 1; cy1 = 1 - MIN; } else { var yc = cl((cy1+cy2)/2); cy1 = Math.max(0, Math.min(1-MIN, yc-MIN/2)); cy2 = cy1+MIN; } }
    return { x: cx1, y: cy1, w: cx2 - cx1, h: cy2 - cy1, offscreen: offscreen };
  }
  function mk(tag, a) { var e = document.createElementNS(NS, tag); if (a) for (var k in a) e.setAttribute(k, a[k]); return e; }
  function hashId(s) { var h = 0; for (var i = 0; i < s.length; i++) { h = (h << 5) - h + s.charCodeAt(i); h |= 0; } return Math.abs(h); }

  function model() {
    var q = (st.search || '').trim().toLowerCase();
    var matches = function(u) { return !q || u.toLowerCase().indexOf(q) >= 0 || ((all[u].via && all[u].via.text) || '').toLowerCase().indexOf(q) >= 0; };
    var hidden = function(u) { var p = all[u].parent; while (p && all[p]) { if (st.collapsed[p]) return true; p = all[p].parent; } return false; };
    var ids = Object.keys(all), vis;
    if (q) {
      var show = {}; ids.forEach(function(u){ if (matches(u)) { show[u] = 1; var p = all[u].parent; while (p && all[p]) { show[p] = 1; p = all[p].parent; } } });
      vis = ids.filter(function(u){ return show[u]; });
    } else { vis = ids.filter(function(u){ return !hidden(u); }); }
    return vis.map(function(u){ return all[u]; });
  }

  function arrowDefs() { return '<defs><marker id="rpt-arr" viewBox="0 -5 10 10" refX="9" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,-5L10,0L0,5" fill="#4a5568"/></marker></defs>'; }
  function applyView() { var g = document.getElementById('rpt-sm-vp'); if (g) g.setAttribute('transform', 'translate(' + st.view.tx + ',' + st.view.ty + ') scale(' + st.view.scale + ')'); }

  function edgeLabel(vp, txt, lx, ly) {
    if (!txt) return;
    var tw = Math.min(txt.length, 14) * 7 + 12;
    vp.appendChild(mk('rect', { x: lx - tw/2, y: ly - 8, width: tw, height: 16, rx: 4, fill: '#0d1117', stroke: '#21262d' }));
    var t = mk('text', { x: lx, y: ly + 3, 'text-anchor': 'middle', 'font-size': '10px', fill: '#c9d1d9' });
    t.textContent = txt.length > 14 ? txt.slice(0, 13) + '…' : txt; vp.appendChild(t);
  }

  function renderCompact(vis) {
    svg.innerHTML = arrowDefs();
    var vp = mk('g', { id: 'rpt-sm-vp' }); svg.appendChild(vp);
    var W = 220, RH = 60, BW = 156, BH = 38, byId = {};
    vis.forEach(function(n){ byId[n.url] = n; });
    var byDepth = {}; vis.forEach(function(n){ (byDepth[n.depth||0] = byDepth[n.depth||0] || []).push(n); });
    Object.keys(byDepth).map(Number).sort(function(a,b){return a-b;}).forEach(function(d){
      byDepth[d].sort(function(a,b){return a.url.localeCompare(b.url);}).forEach(function(n,i){ n._x = 40 + d*W; n._y = 40 + i*RH; });
    });
    vis.forEach(function(n){
      var p = n.parent && byId[n.parent]; if (!p) return;
      var x1 = p._x + BW, y1 = p._y + BH/2, x2 = n._x, y2 = n._y + BH/2, mx = (x1+x2)/2;
      vp.appendChild(mk('path', { d: 'M'+x1+','+y1+' C'+mx+','+y1+' '+mx+','+y2+' '+x2+','+y2, fill: 'none', stroke: '#4a5568', 'stroke-width': 1.5, 'marker-end': 'url(#rpt-arr)' }));
      vp.appendChild(mk('circle', { cx: x1, cy: y1, r: 3.2, fill: '#f85149', stroke: '#fff', 'stroke-width': 1 }));
      edgeLabel(vp, (n.via && n.via.text) || '', mx, (y1+y2)/2);
    });
    vis.forEach(function(n){
      var hasKids = (children[n.url] || []).length > 0;
      var g = mk('g', { transform: 'translate(' + n._x + ',' + n._y + ')' }); g.style.cursor = 'pointer';
      g.appendChild(mk('rect', { width: BW, height: BH, rx: 8, fill: '#11151b', stroke: color(n), 'stroke-width': 2 }));
      var tx = 12;
      if (hasKids) {
        var car = mk('text', { x: 10, y: BH/2 + 4, 'font-size': '10px', fill: '#8b949e' });
        car.textContent = st.collapsed[n.url] ? '▶' : '▼'; car.style.cursor = 'pointer';
        car.addEventListener('click', function(ev){ ev.stopPropagation(); st.collapsed[n.url] = !st.collapsed[n.url]; render(); });
        g.appendChild(car); tx = 24;
      }
      g.appendChild(mk('circle', { cx: tx + 4, cy: BH/2, r: 4.5, fill: color(n) }));
      var title = mk('text', { x: tx + 14, y: BH/2 - 2, 'font-size': '10.5px', fill: '#e6edf3' }); title.textContent = short(n.url); g.appendChild(title);
      var sub = mk('text', { x: tx + 14, y: BH/2 + 11, 'font-size': '9px', fill: '#8b949e' });
      sub.textContent = (st.collapsed[n.url] && desc[n.url]) ? (desc[n.url] + ' ページ') : ((n.forms||0) + 'f / ' + (n.inputs||0) + 'i');
      g.appendChild(sub);
      g.addEventListener('click', function(ev){ showPop(ev, n); });
      g.addEventListener('mousemove', function(ev){ showTip(ev, n); });
      g.addEventListener('mouseleave', hideTip);
      vp.appendChild(g);
    });
    applyView();
  }

  function renderShots(vis) {
    svg.innerHTML = arrowDefs();
    var vp = mk('g', { id: 'rpt-sm-vp' }); svg.appendChild(vp);
    var W = 290, RH = 168, CW = 210, CH = 132, IMGH = 96, byId = {};
    vis.forEach(function(n){ byId[n.url] = n; });
    var byDepth = {}; vis.forEach(function(n){ (byDepth[n.depth||0] = byDepth[n.depth||0] || []).push(n); });
    Object.keys(byDepth).map(Number).sort(function(a,b){return a-b;}).forEach(function(d){
      byDepth[d].sort(function(a,b){return a.url.localeCompare(b.url);}).forEach(function(n,i){ n._x = 30 + d*W; n._y = 30 + i*RH; });
    });
    vis.forEach(function(n){
      var p = n.parent && byId[n.parent]; if (!p) return;
      var x1 = p._x + CW, y1 = p._y + CH/2, x2 = n._x, y2 = n._y + CH/2, mx = (x1+x2)/2;
      vp.appendChild(mk('path', { d: 'M'+x1+','+y1+' C'+mx+','+y1+' '+mx+','+y2+' '+x2+','+y2, fill: 'none', stroke: '#4a5568', 'stroke-width': 1.5, 'marker-end': 'url(#rpt-arr)' }));
      edgeLabel(vp, (n.via && n.via.text) || '', mx, (y1+y2)/2);
    });
    vis.forEach(function(n){
      var g = mk('g', { transform: 'translate(' + n._x + ',' + n._y + ')' }); g.style.cursor = 'pointer';
      g.appendChild(mk('rect', { width: CW, height: CH, rx: 8, fill: '#11151b', stroke: color(n), 'stroke-width': 2 }));
      var clip = 'rptclip-' + hashId(n.url);
      var defs = mk('defs'); defs.innerHTML = '<clipPath id="' + clip + '"><rect x="6" y="6" width="' + (CW-12) + '" height="' + IMGH + '" rx="4"/></clipPath>'; g.appendChild(defs);
      if (n.shot) {
        // 'none' fills the box exactly so the click-rect overlays stay aligned.
        var img = mk('image', { x: 6, y: 6, width: CW-12, height: IMGH, preserveAspectRatio: 'none', 'clip-path': 'url(#' + clip + ')' });
        img.setAttributeNS('http://www.w3.org/1999/xlink', 'href', 'data:image/jpeg;base64,' + n.shot);
        img.setAttribute('href', 'data:image/jpeg;base64,' + n.shot);
        g.appendChild(img);
      } else {
        g.appendChild(mk('rect', { x: 6, y: 6, width: CW-12, height: IMGH, rx: 4, fill: '#0e1420' }));
        [22,32,42].forEach(function(yy,i){ g.appendChild(mk('rect', { x: 12, y: yy, width: (CW-24)*(i%2?0.6:0.85), height: 4, rx: 2, fill: '#2a3344' })); });
      }
      (children[n.url] || []).forEach(function(ku){
        var k = byId[ku]; if (!k) return; var nr = norm(k.via); if (!nr) return;
        g.appendChild(mk('rect', { x: 6 + (CW-12)*nr.x, y: 6 + IMGH*nr.y, width: Math.max(8, (CW-12)*nr.w), height: Math.max(7, IMGH*nr.h), rx: 3, fill: 'rgba(248,81,73,.18)', stroke: '#f85149', 'stroke-width': 1.5, 'stroke-dasharray': nr.offscreen ? '3 2' : 'none' }));
      });
      var title = mk('text', { x: 8, y: CH-11, 'font-size': '10.5px', fill: '#e6edf3' }); title.textContent = short(n.url); g.appendChild(title);
      var sub = mk('text', { x: 8, y: CH-2, 'font-size': '9px', fill: '#8b949e' }); sub.textContent = (n.forms||0)+'f / '+(n.inputs||0)+'i / '+(n.params||0)+'p'; g.appendChild(sub);
      g.appendChild(mk('circle', { cx: CW-12, cy: CH-9, r: 5, fill: color(n) }));
      g.addEventListener('click', function(ev){ showPop(ev, n); });
      g.addEventListener('mousemove', function(ev){ showTip(ev, n); });
      g.addEventListener('mouseleave', hideTip);
      vp.appendChild(g);
    });
    applyView();
  }

  function detailHtml(n) {
    var p = n.parent && all[n.parent], nr = norm(n.via), shot = (p && p.shot) || n.shot;
    var h = '<h4 style="margin:0 0 10px;color:#58a6ff;font-size:.86rem">' + (n.via ? ('クリック箇所： ' + esc(short(p ? p.url : '')) + ' → ' + esc(short(n.url))) : (esc(n.url) + '（起点）')) + '</h4>';
    if (shot) {
      h += '<div style="position:relative;border:1px solid #30363d;border-radius:8px;overflow:hidden;max-width:560px"><img style="display:block;width:100%" src="data:image/jpeg;base64,' + shot + '">';
      if (nr && p && p.shot) h += '<div title="' + (nr.offscreen ? 'クリック箇所はスクショ範囲外（端に表示）' : 'クリック箇所') + '" style="position:absolute;border:2px ' + (nr.offscreen ? 'dashed' : 'solid') + ' #f85149;border-radius:4px;box-shadow:0 0 0 3px rgba(248,81,73,.25);left:' + (nr.x*100) + '%;top:' + (nr.y*100) + '%;width:' + (nr.w*100) + '%;height:' + (nr.h*100) + '%"></div>';
      h += '</div>';
    }
    h += '<div style="margin-top:12px;font-size:.78rem;color:#8b949e;line-height:1.8">';
    if (n.via) h += '押した要素：<b style="color:#e6edf3">「' + esc(n.via.text || '(テキスト無し)') + '」</b><br>セレクタ：<code style="color:#79c0ff">' + esc(n.via.selector || '-') + '</code><br>';
    h += 'URL：<code style="color:#79c0ff">' + esc(n.url) + '</code><br>状態：<b style="color:#e6edf3">' + n.status + '</b> ／ ' + (n.forms||0) + ' forms / ' + (n.inputs||0) + ' inputs / ' + (n.params||0) + ' params';
    if (n.findings > 0) h += '<br><span style="color:#f85149">' + n.findings + ' finding' + (n.findings>1?'s':'') + '</span>';
    h += '<br><a href="' + esc(n.url) + '" target="_blank" style="color:#58a6ff">このページを開く ↗</a></div>';
    return h;
  }

  function renderExplorer() {
    hideTip(); hidePop();
    if (!st.selected || !all[st.selected]) {
      var fv = Object.keys(all).filter(function(u){ return all[u].status === 'vuln'; })[0];
      st.selected = fv || Object.keys(all)[0] || null;
    }
    var roots = Object.keys(all).filter(function(u){ return !all[u].parent || !all[all[u].parent]; });
    // URLs go into HTML-escaped data attributes (never a JS-string handler) and are
    // dispatched via one delegated listener, so untrusted URLs cannot inject script.
    function row(u, ind) {
      var n = all[u], kids = children[u] || [], c = color(n);
      var caret = kids.length ? '<span class="rsm-caret" data-act="toggle" data-u="' + esc(u) + '">' + (st.collapsed[u] ? '▶' : '▼') + '</span>' : '<span class="rsm-caret"></span>';
      var label = short(u).replace(/^…?\/?/, '') || '/';
      var html = '<div class="rsm-trow ' + (u === st.selected ? 'sel' : '') + '" style="padding-left:' + (ind*14+4) + 'px" data-act="sel" data-u="' + esc(u) + '">' + caret + '<span class="sm-dot" style="width:8px;height:8px;border-radius:50%;display:inline-block;background:' + c + '"></span><span>' + esc(label) + '</span>' + (kids.length ? '<span class="rsm-cnt">' + desc[u] + '</span>' : '') + '</div>';
      if (!st.collapsed[u]) kids.sort(function(a,b){return a.localeCompare(b);}).forEach(function(k){ html += row(k, ind+1); });
      return html;
    }
    var treeHtml = '<div style="width:280px;flex-shrink:0;overflow:auto;background:rgba(13,17,23,.7);border:1px solid #21262d;border-radius:8px;padding:6px">' + (roots.map(function(r){ return row(r, 0); }).join('') || '') + '</div>';
    var n = all[st.selected];
    var detail = '<div style="flex:1;overflow:auto;background:rgba(13,17,23,.7);border:1px solid #21262d;border-radius:8px;padding:14px">' + (n ? detailHtml(n) : '') + '</div>';
    explorer.innerHTML = treeHtml + detail;
    explorer.onclick = function(ev) {
      var t = ev.target.closest('[data-act]'); if (!t) return;
      var u = t.getAttribute('data-u'); if (u == null) return;
      if (t.getAttribute('data-act') === 'toggle') { ev.stopPropagation(); st.collapsed[u] = !st.collapsed[u]; }
      else { st.selected = u; }
      render();
    };
  }

  function render() {
    var mode = st.mode;
    svg.style.display = (mode === 'explorer') ? 'none' : '';
    explorer.style.display = (mode === 'explorer') ? 'flex' : 'none';
    var vis = model();
    if (mode === 'explorer') { renderExplorer(); return; }
    if (mode === 'shots') renderShots(vis); else renderCompact(vis);
  }

  function showTip(ev, n) {
    var rect = wrap.getBoundingClientRect();
    tip.innerHTML = '<strong>Depth ' + n.depth + '</strong><br>' + esc(n.url) + '<br><span style="color:#8b949e">' + (n.forms||0) + ' forms / ' + (n.inputs||0) + ' inputs</span>' + (n.findings>0 ? '<br><span style="color:#f85149">' + n.findings + ' findings</span>' : '');
    tip.style.display = 'block';
    var x = ev.clientX - rect.left + 12, y = ev.clientY - rect.top + 12;
    if (x + 340 > rect.width) x = rect.width - 340;
    tip.style.left = x + 'px'; tip.style.top = y + 'px';
  }
  function hideTip() { tip.style.display = 'none'; }

  function showPop(ev, n) {
    var p = n.parent && all[n.parent], nr = norm(n.via), shot = (p && p.shot) || n.shot;
    // 閉じるボタン（一度開くと閉じられない問題の対策）。背景クリック / Esc でも閉じる。
    var h = '<span onclick="rptSmClosePop()" title="閉じる" style="position:absolute;top:6px;right:8px;width:20px;height:20px;line-height:18px;text-align:center;border:1px solid #30363d;border-radius:5px;background:#161b22;color:#8b949e;cursor:pointer">×</span>';
    h += '<h4 style="margin:0 20px 6px 0;color:#58a6ff;font-size:.78rem">' + (n.via ? ('クリック箇所： ' + esc(short(p ? p.url : '')) + ' → ' + esc(short(n.url))) : (esc(short(n.url)) + '（起点）')) + '</h4>';
    if (shot) {
      h += '<div style="position:relative;border:1px solid #30363d;border-radius:8px;overflow:hidden"><img style="display:block;width:100%" src="data:image/jpeg;base64,' + shot + '">';
      if (nr && p && p.shot) h += '<div title="' + (nr.offscreen ? 'クリック箇所はスクショ範囲外（端に表示）' : 'クリック箇所') + '" style="position:absolute;border:2px ' + (nr.offscreen ? 'dashed' : 'solid') + ' #f85149;border-radius:4px;box-shadow:0 0 0 3px rgba(248,81,73,.25);left:' + (nr.x*100) + '%;top:' + (nr.y*100) + '%;width:' + (nr.w*100) + '%;height:' + (nr.h*100) + '%"></div>';
      h += '</div>';
    }
    h += '<div style="margin-top:8px;font-size:.74rem;color:#8b949e;line-height:1.7">';
    if (n.via) h += '押した要素：<b style="color:#e6edf3">「' + esc(n.via.text || '(テキスト無し)') + '」</b><br>セレクタ：<code style="color:#79c0ff">' + esc(n.via.selector || '-') + '</code><br>';
    h += '<a href="' + esc(n.url) + '" target="_blank" style="color:#58a6ff">ページを開く ↗</a></div>';
    pop.innerHTML = h; pop.style.display = 'block';
    var rect = wrap.getBoundingClientRect();
    var x = ev.clientX - rect.left + 14, y = ev.clientY - rect.top + 8;
    if (x + 350 > rect.width) x = rect.width - 350;
    if (y + 250 > rect.height) y = Math.max(8, rect.height - 250);
    pop.style.left = x + 'px'; pop.style.top = y + 'px';
  }
  function hidePop() { pop.style.display = 'none'; }

  // Global handlers (toolbar)
  window.rptSmMode = function(m) { st.mode = m; ['compact','shots','explorer'].forEach(function(k){ var b = document.getElementById('rpt-sm-m-' + k); if (b) b.classList.toggle('active', k === m); }); hidePop(); render(); };
  window.rptSmSearch = function(v) { st.search = v || ''; hidePop(); render(); };
  window.rptSmExpand = function(open) { Object.keys(all).forEach(function(u){ st.collapsed[u] = !open; }); render(); };
  window.rptSmZoom = function(f) { st.view.scale = Math.max(0.2, Math.min(4, st.view.scale * f)); applyView(); };
  window.rptSmReset = function() { st.view = { scale: 1, tx: 0, ty: 0 }; applyView(); };
  window.rptSmClosePop = function() { hidePop(); };
  // Esc でも遷移元ポップオーバーを閉じられるようにする。
  document.addEventListener('keydown', function(ev) { if (ev.key === 'Escape') hidePop(); });

  // Pan & zoom
  var drag = false, lx = 0, ly = 0;
  wrap.addEventListener('mousedown', function(ev) {
    if (st.mode === 'explorer') return;
    if (ev.target.closest('#rpt-sm-pop')) return;
    // ノード以外（背景）をクリックしたら遷移元ポップオーバーを閉じる。
    var onNode = ev.target.closest('g[transform]') && ev.target.tagName !== 'svg';
    if (!onNode) hidePop();
    drag = true; lx = ev.clientX; ly = ev.clientY;
  });
  window.addEventListener('mousemove', function(ev) { if (!drag) return; st.view.tx += ev.clientX - lx; st.view.ty += ev.clientY - ly; lx = ev.clientX; ly = ev.clientY; applyView(); });
  window.addEventListener('mouseup', function() { drag = false; });
  wrap.addEventListener('wheel', function(ev) {
    if (st.mode === 'explorer') return;
    ev.preventDefault();
    var rect = wrap.getBoundingClientRect(), cx = ev.clientX - rect.left, cy = ev.clientY - rect.top, f = ev.deltaY < 0 ? 1.1 : 0.9;
    st.view.tx = cx - (cx - st.view.tx) * f; st.view.ty = cy - (cy - st.view.ty) * f;
    st.view.scale = Math.max(0.2, Math.min(4, st.view.scale * f)); applyView();
  }, { passive: false });

  render();
})();
"""

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLORS = {
    "critical": "#e53e3e",
    "high": "#dd6b20",
    "medium": "#d69e2e",
    "low": "#38a169",
    "info": "#4299e1",
}

# Risk score → colour
def _risk_color(score: int) -> str:
    if score >= 8:
        return "#e53e3e"
    if score >= 6:
        return "#dd6b20"
    if score >= 4:
        return "#d69e2e"
    return "#38a169"


class ReportGenerator:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    def generate(
        self,
        target: str,
        findings: list[Finding],
        visited_urls: list[str],
        checks: list[str],
        attack_plans: "Optional[list[PageAttackPlan]]" = None,
        ctf_flags: "Optional[list]" = None,
        page_graph: "Optional[dict]" = None,
        scan_matrix: "Optional[list[dict]]" = None,
        llm_summary: "Optional[dict]" = None,
        template: str = "audit",
        diff_result=None,
        observability: "Optional[dict]" = None,
        coverage: "Optional[dict]" = None,
    ):
        """
        Generate HTML report and save to output directory.

        Parameters
        ----------
        template  : "audit" (default/full detail) | "executive" | "developer"
        diff_result : DiffResult or None
        """
        sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

        if template == "executive":
            html = self._build_executive_html(target, sorted_findings, visited_urls, checks,
                                               attack_plans or [], ctf_flags or [], page_graph or {},
                                               diff_result, scan_matrix or [], observability or {},
                                               coverage or {})
            report_path = self.output_dir / "report_executive.html"
        elif template == "developer":
            html = self._build_developer_html(target, sorted_findings, visited_urls, checks,
                                               attack_plans or [], ctf_flags or [], page_graph or {},
                                               diff_result, scan_matrix or [], observability or {},
                                               coverage or {})
            report_path = self.output_dir / "report_developer.html"
        else:
            html = self._build_html(target, sorted_findings, visited_urls, checks,
                                    attack_plans or [], ctf_flags or [], page_graph or {},
                                    diff_result, scan_matrix or [], llm_summary or {},
                                    observability or {}, coverage or {})
            report_path = self.output_dir / "report.html"

        report_path.write_text(html, encoding="utf-8")
        return report_path

    def _build_html(
        self,
        target: str,
        findings: list[Finding],
        visited_urls: list[str],
        checks: list[str],
        attack_plans: "list[PageAttackPlan]" = None,
        ctf_flags: list = None,
        page_graph: dict = None,
        diff_result=None,
        scan_matrix: list = None,
        llm_summary: dict = None,
        observability: dict = None,
        coverage: dict = None,
    ) -> str:
        attack_plans = attack_plans or []
        ctf_flags = ctf_flags or []
        page_graph = page_graph or {}
        scan_matrix = scan_matrix or []
        llm_summary = llm_summary or {}
        observability = observability or {}
        coverage = coverage or {}
        scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total = len(findings)
        counts = {}
        for sev in ["critical", "high", "medium", "low"]:
            counts[sev] = sum(1 for f in findings if f.severity == sev)

        findings_html = ""
        for i, f in enumerate(findings):
            color = SEVERITY_COLORS.get(f.severity, "#718096")
            is_agent = getattr(f, "source", "scanner") == "agent"
            source_class = " finding-card-agent" if is_agent else ""
            screenshot_html = ""
            if f.screenshot_b64:
                screenshot_html = f"""
                <div class="screenshot-container">
                    <h4>Screenshot</h4>
                    <img src="data:image/jpeg;base64,{f.screenshot_b64}" alt="Evidence screenshot" class="evidence-screenshot">
                </div>"""

            req = f.request or {}
            resp = f.response or {}
            req_html = self._format_request(req)
            resp_html = self._format_response(resp, f)
            structured_evidence_html = self._format_structured_evidence(f)

            extra_badges = self._agent_badges_html(f)
            if "[ChainDetect]" in f.evidence:
                extra_badges += '<span class="badge-chain">🔗 Chain</span>'
            if "[MultiParam]" in f.evidence:
                extra_badges += '<span class="badge-multi">⚡ MultiParam</span>'
            if "[AdaptiveAI]" in f.evidence:
                extra_badges += '<span class="badge-ai">🧠 AdaptiveAI</span>'
            # assumed は推定バッジに加え、未再検証であることを ⚠要確認でも明示する。
            # unreproduced/skipped と state 空の旧 Finding は従来どおり ⚠要確認にする。
            f_state = getattr(f, "verification_state", "")
            if f_state == "assumed":
                extra_badges += '<span class="badge-assumed">〜 推定（再検証未実行）</span>'
                if not getattr(f, "verified", True):
                    extra_badges += '<span class="badge-unconfirmed">⚠ 要確認</span>'
            elif f_state in ("unreproduced", "skipped") or not getattr(f, "verified", True):
                note = self._escape(getattr(f, "verification_note", ""))
                extra_badges += f'<span class="badge-unconfirmed" title="{note}">⚠ 要確認</span>'
            # E: 信頼度バッジ
            conf = getattr(f, "confidence", "tentative")
            conf_labels = {"confirmed": ("✔ 確認済", "#276749"), "likely": ("〜 可能性高", "#744210"), "tentative": ("? 暫定", "#4a5568")}
            conf_label, conf_color = conf_labels.get(conf, conf_labels["tentative"])
            extra_badges += f'<span class="badge-confidence" style="background:{conf_color}">{conf_label}</span>'
            # I: 差分バッジ
            diff_status = getattr(f, "_diff_status", "") or f.__dict__.get("_diff_status", "")
            if diff_status == "new":
                extra_badges += '<span class="badge-diff-new">🆕 新規</span>'
            elif diff_status == "persistent":
                extra_badges += '<span class="badge-diff-persist">🔄 継続</span>'

            cvss_score = getattr(f, "cvss_score", 0.0)
            cvss_vector = getattr(f, "cvss_vector", "")
            cvss_html = ""
            if cvss_score > 0:
                sc = cvss_score
                sc_color = "#e53e3e" if sc >= 9 else ("#dd6b20" if sc >= 7 else ("#d69e2e" if sc >= 4 else "#38a169"))
                cvss_html = (
                    f'<span class="cvss-badge" style="background:{sc_color}" '
                    f'title="{self._escape(cvss_vector)}">CVSS {sc:.1f}</span>'
                )

            # ⑨ 修正ガイダンス。engine が付与した ai_fix を表示するが、実際に LLM で
            # 生成したものだけを "AI 推奨修正" と表示する。LLM 未使用（静的テンプレート）
            # のときは "AI" と偽らず「推奨修正（静的ガイダンス）」として出す。
            ai_fix_text = f.__dict__.get("ai_fix", "")
            ai_fix_is_ai = bool(f.__dict__.get("ai_fix_is_ai", False))
            ai_fix_html = ""
            if ai_fix_text:
                ai_fix_safe = self._escape(ai_fix_text).replace("\n", "<br>")
                if ai_fix_is_ai:
                    fix_heading = "🤖 AI 推奨修正 (AI Fix Suggestion)"
                else:
                    fix_heading = "🛠️ 推奨修正 (静的ガイダンス)"
                ai_fix_html = f"""
                    <div class="finding-detail ai-fix-section">
                        <h4>{fix_heading}</h4>
                        <div class="ai-fix-body">{ai_fix_safe}</div>
                    </div>"""

            findings_html += f"""
            <div class="finding-card{source_class}" id="finding-{i}"
                 data-severity="{f.severity}" data-check="{f.check_type}"
                 data-source="{self._escape(getattr(f, 'source', 'scanner'))}"
                 data-url="{self._escape(f.url)}" data-field="{self._escape(f.field_name)}">
                <div class="finding-header" style="border-left: 4px solid {color}">
                    <div class="finding-title">
                        <span class="badge" style="background:{color}">{f.severity.upper()}</span>
                        <span class="check-type">{f.check_type.upper()}</span>
                        <span class="field-name">Field: {self._escape(f.field_name)}</span>
                        {cvss_html}
                        {extra_badges}
                    </div>
                    <div class="finding-url">{self._escape(f.url)}</div>
                </div>
                <div class="finding-body">
                    <div class="finding-detail">
                        <h4>Evidence</h4>
                        <p class="evidence-text">{self._escape(f.evidence)}</p>
                    </div>
                    {structured_evidence_html}
                    <div class="finding-detail">
                        <h4>Payload Used</h4>
                        <code class="payload-code">{self._escape(f.payload)}</code>
                    </div>
                    {screenshot_html}
                    <div class="network-grid">
                        {req_html}
                        {resp_html}
                    </div>
                    {ai_fix_html}
                </div>
            </div>"""

        # Map URL → finding counts so the URL list can show vuln/done status,
        # mirroring the dashboard's URL panel.
        url_finding_counts: dict[str, int] = {}
        for f in findings:
            if not f.url:
                continue
            url_finding_counts[f.url] = url_finding_counts.get(f.url, 0) + 1

        url_status_labels = {
            "vuln": "発見あり",
            "done": "完了",
        }
        url_items_parts = []
        for u in visited_urls:
            n = url_finding_counts.get(u, 0)
            status = "vuln" if n > 0 else "done"
            label = url_status_labels[status]
            if status == "vuln":
                label = f"{label} ({n})"
            url_items_parts.append(
                f'<div class="url-item" data-status="{status}" title="{self._escape(u)}">'
                f'<span class="url-text">{self._escape(u)}</span>'
                f'<span class="url-badge url-badge-{status}">{label}</span>'
                f'</div>'
            )
        urls_html = "".join(url_items_parts)
        url_total = len(visited_urls)
        url_vuln_total = sum(1 for u in visited_urls if url_finding_counts.get(u, 0) > 0)
        url_done_total = url_total - url_vuln_total

        no_findings_html = ""
        if not findings:
            no_findings_html = """
            <div class="no-findings">
                <div class="no-findings-icon">✓</div>
                <p>No vulnerabilities detected in scanned scope.</p>
                <p class="note">This does not guarantee security. The tool tests known patterns only.</p>
            </div>"""

        # ── Attack Plan section ──────────────────────────────────────────
        attack_plan_html = self._build_attack_plan_html(attack_plans)

        # ── CTF Flags section ────────────────────────────────────────────
        ctf_flags_html = self._build_ctf_flags_html(ctf_flags)

        # ── Page flow diagram section ─────────────────────────────────────
        page_flow_html = self._build_page_flow_html(page_graph, url_finding_counts)

        # ⑧ Attack chain / AI analysis section (reads ai_analysis.md if present)
        ai_analysis_html = self._build_ai_analysis_html()

        checklist_html = self._build_scan_checklist_html(scan_matrix)
        remediation_summary_html = self._build_remediation_summary_html(findings)
        llm_summary_html = self._build_llm_summary_html(llm_summary)
        observability_html = self._build_observability_html(observability)
        coverage_html = self._build_coverage_html(coverage)

        return f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WScan Security Report — {self._escape(target)}</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Crect width='16' height='16' rx='3' fill='%231a202c'/%3E%3Cpath d='M4 4h8v2H6v2h5v2H6v2h6v2H4z' fill='%2363b3ed'/%3E%3C/svg%3E">
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #f7f8fa; color: #1a202c; line-height: 1.6; }}
.header {{ background: linear-gradient(135deg, #1a202c 0%, #2d3748 100%); color: white; padding: 40px; }}
.header h1 {{ font-size: 2rem; font-weight: 700; margin-bottom: 8px; }}
.header .subtitle {{ color: #a0aec0; font-size: 0.95rem; }}
.header .target {{ color: #63b3ed; font-size: 1.1rem; margin-top: 12px; word-break: break-all; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 32px 24px; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 32px; }}
.summary-card {{ background: white; border-radius: 12px; padding: 20px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
.summary-card .count {{ font-size: 2.5rem; font-weight: 800; }}
.summary-card .label {{ font-size: 0.85rem; color: #718096; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.05em; }}
.critical-count {{ color: #e53e3e; }}
.high-count {{ color: #dd6b20; }}
.medium-count {{ color: #d69e2e; }}
.low-count {{ color: #38a169; }}
.total-count {{ color: #4299e1; }}
.section {{ background: white; border-radius: 12px; padding: 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
.section h2 {{ font-size: 1.25rem; font-weight: 700; margin-bottom: 20px; padding-bottom: 12px; border-bottom: 2px solid #e2e8f0; }}
.finding-card {{ border: 1px solid #e2e8f0; border-radius: 10px; margin-bottom: 20px; overflow: hidden; }}
.finding-card-agent {{ border-color:#b794f4; box-shadow:0 0 0 2px rgba(107,70,193,.12); }}
.finding-card-agent .finding-header {{ background:#faf5ff; }}
.finding-header {{ padding: 16px 20px; background: #f8fafc; display: flex; flex-direction: column; gap: 8px; }}
.finding-title {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
.badge {{ color: white; padding: 3px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.05em; }}
.badge-chain {{ background:#744210; color:#fefcbf; padding:2px 8px; border-radius:10px; font-size:0.72rem; font-weight:700; }}
.badge-multi {{ background:#1a365d; color:#bee3f8; padding:2px 8px; border-radius:10px; font-size:0.72rem; font-weight:700; }}
.badge-ai {{ background:#44337a; color:#e9d8fd; padding:2px 8px; border-radius:10px; font-size:0.72rem; font-weight:700; }}
.badge-agent {{ background:#6b46c1; color:#faf5ff; padding:2px 8px; border-radius:10px; font-size:0.72rem; font-weight:700; }}
.badge-agent-verified {{ background:#276749; color:#f0fff4; padding:2px 8px; border-radius:10px; font-size:0.72rem; font-weight:700; }}
.badge-unconfirmed {{ background:#d97706; color:#fff; padding:2px 8px; border-radius:10px; font-size:0.72rem; font-weight:700; cursor:help; }}
.badge-assumed {{ background:#854d0e; color:#fef9c3; padding:2px 8px; border-radius:10px; font-size:0.72rem; font-weight:700; }}
.badge-confidence {{ color:#fff; padding:2px 8px; border-radius:10px; font-size:0.72rem; font-weight:700; }}
.badge-diff-new {{ background:#276749; color:#f0fff4; padding:2px 8px; border-radius:10px; font-size:0.72rem; font-weight:700; }}
.badge-diff-persist {{ background:#2b6cb0; color:#ebf8ff; padding:2px 8px; border-radius:10px; font-size:0.72rem; font-weight:700; }}
.cvss-badge {{ color:white; padding:2px 8px; border-radius:10px; font-size:0.72rem; font-weight:700; cursor:help; }}
.filter-bar {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px; align-items:center; }}
.filter-bar label {{ font-size:0.85rem; color:#4a5568; font-weight:600; }}
.filter-bar select, .filter-bar input {{ border:1px solid #e2e8f0; border-radius:6px; padding:6px 10px; font-size:0.85rem; background:white; }}
.filter-bar input {{ min-width:200px; }}
.check-type {{ font-weight: 700; font-size: 1rem; }}
.field-name {{ color: #4a5568; font-size: 0.9rem; }}
.finding-url {{ font-size: 0.85rem; color: #718096; word-break: break-all; }}
.finding-body {{ padding: 20px; display: flex; flex-direction: column; gap: 16px; }}
.finding-detail h4 {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.08em; color: #718096; margin-bottom: 8px; }}
.evidence-text {{ background: #fff8f0; border: 1px solid #fbd38d; border-radius: 6px; padding: 10px 14px; font-size: 0.9rem; color: #744210; }}
.evidence-grid {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap:10px; margin-top:8px; }}
.evidence-cell {{ border:1px solid #e2e8f0; border-radius:8px; padding:10px; background:#f8fafc; }}
.evidence-cell .k {{ font-size:.7rem; color:#718096; text-transform:uppercase; letter-spacing:.05em; margin-bottom:4px; }}
.evidence-cell .v {{ font-size:.85rem; color:#1a202c; word-break:break-word; }}
.repro-list {{ margin:8px 0 0 18px; color:#2d3748; font-size:.9rem; }}
.payload-code {{ display: block; background: #1a202c; color: #68d391; padding: 10px 14px; border-radius: 6px; font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 0.85rem; word-break: break-all; white-space: pre-wrap; }}
.network-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
@media (max-width: 768px) {{ .network-grid {{ grid-template-columns: 1fr; }} }}
.network-box h4 {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.08em; color: #718096; margin-bottom: 8px; }}
.network-content {{ background: #f7f8fa; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px 14px; font-family: monospace; font-size: 0.8rem; max-height: 200px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; }}
.screenshot-container h4 {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.08em; color: #718096; margin-bottom: 8px; }}
.evidence-screenshot {{ width: 100%; border: 1px solid #e2e8f0; border-radius: 6px; cursor: pointer; transition: transform 0.2s; }}
.evidence-screenshot:hover {{ transform: scale(1.01); }}
.no-findings {{ text-align: center; padding: 48px; color: #718096; }}
.no-findings-icon {{ font-size: 4rem; color: #68d391; margin-bottom: 16px; }}
.no-findings p {{ font-size: 1.1rem; margin-bottom: 8px; }}
.no-findings .note {{ font-size: 0.85rem; color: #a0aec0; }}
/* ── Dashboard-style URL panel ── */
.url-panel-section {{ background:#0d1117; color:#cdd9e5; border:1px solid #1e293b; }}
.url-panel-section h2 {{ color:#e6edf3; border-bottom-color:#1e293b; }}
.url-panel-header {{ display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; margin-bottom:14px; }}
.url-panel-header h2 {{ margin:0; padding:0; border-bottom:none; }}
.url-panel-summary {{ display:flex; gap:6px; flex-wrap:wrap; }}
.url-panel-toolbar {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:10px; }}
.url-filter-input {{ flex:1; min-width:220px; background:#161b22; border:1px solid #30363d; color:#cdd9e5; border-radius:6px; padding:6px 10px; font-size:.8rem; }}
.url-filter-input:focus {{ outline:none; border-color:#388bfd; }}
.url-filter-tabs {{ display:flex; gap:4px; }}
.url-filter-tab {{ background:#161b22; border:1px solid #30363d; color:#8b949e; border-radius:999px; padding:4px 12px; font-size:.72rem; font-weight:700; cursor:pointer; }}
.url-filter-tab:hover {{ color:#cdd9e5; border-color:#388bfd; }}
.url-filter-tab.active {{ background:#1f6feb22; color:#79c0ff; border-color:#388bfd; }}
.url-list {{ list-style:none; max-height:360px; overflow-y:auto; border:1px solid #1e293b; border-radius:8px; background:#0a0c0f; padding:4px 0; }}
.url-item {{ display:flex; align-items:center; gap:10px; padding:6px 12px; font-family:'Cascadia Code','Consolas',monospace; font-size:.8rem; border-bottom:1px solid #1e293b; }}
.url-item:last-child {{ border-bottom:none; }}
.url-item .url-text {{ flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:#8b949e; }}
.url-item[data-status="vuln"] .url-text {{ color:#fca5a5; }}
.url-badge {{ flex-shrink:0; padding:2px 9px; border-radius:999px; font-size:.68rem; font-weight:700; letter-spacing:.03em; }}
.url-badge-done {{ background:#14532d; color:#86efac; }}
.url-badge-vuln {{ background:#7f1d1d; color:#fca5a5; }}
.url-list::-webkit-scrollbar {{ width:8px; }}
.url-list::-webkit-scrollbar-thumb {{ background:#30363d; border-radius:4px; }}
.scan-meta {{ display: flex; gap: 24px; flex-wrap: wrap; }}
.meta-item {{ display: flex; flex-direction: column; gap: 2px; }}
.meta-label {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; color: #718096; }}
.meta-value {{ font-weight: 600; }}
.footer {{ text-align: center; color: #a0aec0; font-size: 0.8rem; padding: 32px; }}
.lightbox {{ display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.85); z-index: 1000; justify-content: center; align-items: center; }}
.lightbox.active {{ display: flex; }}
.lightbox img {{ max-width: 95%; max-height: 95vh; border-radius: 8px; }}
.lightbox-close {{ position: fixed; top: 20px; right: 20px; color: white; font-size: 2rem; cursor: pointer; background: rgba(0,0,0,0.5); width: 44px; height: 44px; border-radius: 50%; display: flex; align-items: center; justify-content: center; }}
/* ── Attack Plan styles ── */
.plan-section-meta {{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px; }}
.plan-stat-card {{ background:#ebf8ff; border:1px solid #bee3f8; border-radius:8px; padding:12px 20px; text-align:center; min-width:100px; }}
.plan-stat-card .ps-count {{ font-size:1.8rem; font-weight:800; }}
.plan-stat-card .ps-label {{ font-size:0.75rem; color:#2b6cb0; text-transform:uppercase; letter-spacing:.05em; }}
.ps-high {{ background:#fff5f5; border-color:#fed7d7; }} .ps-high .ps-count {{ color:#e53e3e; }}
.ps-mid  {{ background:#fffaf0; border-color:#fbd38d; }} .ps-mid  .ps-count {{ color:#dd6b20; }}
.ps-low  {{ background:#f0fff4; border-color:#9ae6b4; }} .ps-low  .ps-count {{ color:#276749; }}
.plan-card {{ border:1px solid #bee3f8; border-radius:10px; margin-bottom:20px; overflow:hidden; }}
.plan-card-header {{ background:#ebf8ff; padding:14px 20px; border-bottom:1px solid #bee3f8; display:flex; justify-content:space-between; align-items:start; cursor:pointer; user-select:none; }}
.plan-card-header:hover {{ background:#dbeafe; }}
.plan-header-left {{ display:flex; flex-direction:column; gap:4px; }}
.plan-url {{ font-family:monospace; font-size:.85rem; color:#2b6cb0; word-break:break-all; }}
.plan-purpose {{ font-size:.9rem; color:#1a365d; font-weight:600; }}
.plan-by {{ font-size:.75rem; color:#718096; }}
.plan-by.llm {{ color:#6b46c1; font-weight:600; }}
.plan-toggle {{ font-size:1.2rem; color:#4299e1; transition:transform .2s; padding-left:12px; }}
.plan-card.collapsed .plan-toggle {{ transform:rotate(-90deg); }}
.plan-card.collapsed .plan-fields {{ display:none; }}
.plan-fields {{ padding:16px 20px; display:flex; flex-direction:column; gap:10px; }}
.plan-cols-header {{ display:grid; grid-template-columns:160px 56px 1fr 1.6fr; gap:12px; padding:0 0 6px; font-size:.72rem; font-weight:700; text-transform:uppercase; letter-spacing:.06em; color:#a0aec0; border-bottom:2px solid #e2e8f0; margin-bottom:6px; }}
.plan-field-row {{ display:grid; grid-template-columns:160px 56px 1fr 1.6fr; gap:12px; align-items:start; font-size:.85rem; border-bottom:1px solid #f0f4f8; padding-bottom:10px; }}
.plan-field-row:last-child {{ border-bottom:none; padding-bottom:0; }}
.plan-field-name {{ font-family:monospace; font-weight:600; color:#2d3748; word-break:break-all; }}
.plan-risk-badge {{ width:44px; height:44px; border-radius:50%; display:flex; align-items:center; justify-content:center; color:white; font-size:1.05rem; font-weight:800; flex-shrink:0; }}
.plan-checks {{ display:flex; flex-wrap:wrap; gap:4px; align-content:start; }}
.plan-check-badge {{ background:#e2e8f0; color:#4a5568; border-radius:4px; padding:2px 7px; font-size:.75rem; font-weight:600; }}
.plan-check-badge.priority-0 {{ background:#fed7d7; color:#742a2a; }}
.plan-check-badge.priority-1 {{ background:#feebc8; color:#7b341e; }}
.plan-rationale-col {{ display:flex; flex-direction:column; gap:6px; }}
.plan-rationale {{ color:#718096; font-size:.82rem; font-style:italic; }}
.cross-page-tag {{ display:inline-block; background:#e9d8fd; color:#553c9a; border-radius:4px; padding:1px 6px; font-size:.72rem; font-weight:700; font-style:normal; }}
.plan-payloads-toggle {{ font-size:.75rem; color:#4299e1; cursor:pointer; text-decoration:underline; margin-top:4px; }}
.plan-payload-list {{ display:none; margin-top:6px; background:#1a202c; border-radius:6px; padding:8px 12px; }}
.plan-payload-list.open {{ display:block; }}
.plan-payload-list code {{ display:block; color:#68d391; font-family:monospace; font-size:.78rem; padding:2px 0; word-break:break-all; }}
.plan-payload-type {{ color:#a0aec0; font-size:.7rem; margin-bottom:4px; }}
.no-plans {{ color:#a0aec0; font-size:.9rem; padding:16px 0; }}
@media (max-width:768px) {{ .plan-cols-header,.plan-field-row {{ grid-template-columns:1fr 44px 1fr; }} .plan-rationale-col {{ display:none; }} }}
/* ── Page Flow Diagram styles ── */
.page-flow-wrapper {{ overflow-x: auto; max-width:100%; }}
.page-flow-svg {{ width:100%; max-width:100%; min-width:0; }}
#site-map-graph svg {{ display:block; width:100% !important; max-width:100%; }}
.page-node {{ cursor: pointer; }}
.page-node rect {{ fill: #ebf8ff; stroke: #4299e1; stroke-width: 1.5; rx: 6; }}
.page-node.root rect {{ fill: #fefcbf; stroke: #d69e2e; stroke-width: 2; }}
.page-node text {{ font-size: 11px; fill: #1a365d; font-family: monospace; }}
.page-edge {{ stroke: #a0aec0; stroke-width: 1.5; fill: none; marker-end: url(#arrow); }}
.page-thumb {{ border: 1px solid #e2e8f0; border-radius: 4px; }}
/* ── CTF Flags styles ── */
.ctf-section {{ background: linear-gradient(135deg,#1a202c 0%,#2d3748 100%); border-radius:12px; padding:24px; margin-bottom:24px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }}
.ctf-section h2 {{ color:#ffd700; font-size:1.3rem; font-weight:800; margin-bottom:16px; padding-bottom:10px; border-bottom:2px solid #4a5568; letter-spacing:.03em; }}
.ctf-flag-list {{ display:flex; flex-direction:column; gap:10px; }}
.ctf-flag-item {{ background:#2d3748; border:1px solid #4a5568; border-radius:8px; padding:14px 18px; display:flex; flex-direction:column; gap:4px; }}
.ctf-flag-value {{ font-family:'Cascadia Code','Consolas',monospace; font-size:1.05rem; font-weight:700; color:#ffd700; letter-spacing:.04em; word-break:break-all; }}
.ctf-flag-source {{ font-size:.78rem; color:#a0aec0; }}
.ctf-flag-copy {{ display:inline-block; margin-top:4px; font-size:.75rem; color:#68d391; cursor:pointer; text-decoration:underline; }}
.ctf-no-flags {{ color:#a0aec0; font-style:italic; }}
/* ── AI Analysis / Attack Chains (⑧ ⑨) ── */
.ai-analysis-section {{ background: linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);
    border-radius:12px; padding:24px; margin-bottom:24px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.25); color:#e2e8f0; }}
.ai-analysis-section h2 {{ color:#90cdf4; font-size:1.25rem; font-weight:800;
    margin-bottom:16px; padding-bottom:10px; border-bottom:1px solid #2d3748; }}
.ai-analysis-body {{ font-size:.9rem; line-height:1.8; white-space:pre-wrap;
    word-break:break-word; color:#e2e8f0; }}
.ai-fix-section {{ background:#f0fff4; border:1px solid #9ae6b4;
    border-radius:8px; padding:14px 18px; }}
.ai-fix-section h4 {{ color:#276749; font-size:.8rem; text-transform:uppercase;
    letter-spacing:.08em; margin-bottom:8px; }}
.ai-fix-body {{ font-size:.88rem; color:#1c4532; line-height:1.7; }}
.table-scroll {{ max-width:100%; overflow-x:auto; }}
.checklist-table {{ width:100%; border-collapse:collapse; font-size:.85rem; }}
.checklist-table th {{ text-align:left; background:#f8fafc; color:#4a5568; padding:8px 10px; border-bottom:1px solid #e2e8f0; }}
.checklist-table td {{ padding:8px 10px; border-bottom:1px solid #edf2f7; vertical-align:top; }}
.status-pill {{ display:inline-block; padding:2px 8px; border-radius:999px; font-weight:700; font-size:.72rem; }}
.status-tested {{ background:#ebf8ff; color:#2b6cb0; }}
.status-finding {{ background:#fed7d7; color:#c53030; }}
.status-error {{ background:#fff5f5; color:#9b2c2c; }}
.status-skipped {{ background:#edf2f7; color:#4a5568; }}
.remediation-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:14px; }}
.remediation-card {{ border:1px solid #e2e8f0; border-radius:10px; padding:16px; background:#f8fafc; }}
.remediation-card.p0 {{ border-color:#feb2b2; background:#fff5f5; }}
.remediation-card.p1 {{ border-color:#fbd38d; background:#fffaf0; }}
.remediation-card.p2 {{ border-color:#bee3f8; background:#ebf8ff; }}
.remediation-card.p3 {{ border-color:#c6f6d5; background:#f0fff4; }}
.remediation-head {{ display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:8px; }}
.priority-pill {{ color:white; background:#4a5568; border-radius:999px; padding:2px 9px; font-size:.72rem; font-weight:800; }}
.priority-pill.p0 {{ background:#c53030; }} .priority-pill.p1 {{ background:#dd6b20; }} .priority-pill.p2 {{ background:#2b6cb0; }} .priority-pill.p3 {{ background:#2f855a; }}
.remediation-title {{ font-weight:800; color:#1a202c; }}
.remediation-meta {{ display:flex; flex-wrap:wrap; gap:6px; margin:8px 0; }}
.remediation-meta span {{ background:white; border:1px solid #e2e8f0; border-radius:999px; padding:2px 8px; font-size:.72rem; color:#4a5568; }}
.remediation-evidence {{ font-size:.82rem; color:#4a5568; margin-top:8px; }}
.remediation-related {{ margin-top:8px; font-size:.78rem; color:#718096; }}
.review-list {{ margin-top:18px; border-top:1px solid #e2e8f0; padding-top:14px; }}
.review-item {{ padding:10px 12px; border:1px dashed #cbd5e0; border-radius:8px; margin-top:8px; background:#fff; font-size:.85rem; }}
@media (max-width:640px) {{
  .header {{ padding:32px 24px; }}
  .header h1 {{ font-size:2rem; }}
  .container {{ padding:24px 12px; }}
  .section {{ padding:24px 16px; }}
  .stats-grid {{ grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px; }}
  .stat-card {{ padding:22px 12px; }}
  .remediation-grid {{ grid-template-columns:1fr; }}
  .evidence-grid {{ grid-template-columns:1fr; }}
  .network-grid {{ grid-template-columns:1fr; }}
  .checklist-table {{ min-width:640px; }}
  #site-map-graph {{ height:320px !important; }}
}}
</style>
</head>
<body>
<div class="header">
    <h1>WScan Security Report</h1>
    <div class="subtitle">Automated Web Security Assessment</div>
    <div class="target">🎯 {self._escape(target)}</div>
</div>

<div class="container">
    <!-- Summary Cards -->
    <div class="summary-grid">
        <div class="summary-card">
            <div class="count total-count">{total}</div>
            <div class="label">Total Findings</div>
        </div>
        <div class="summary-card">
            <div class="count critical-count">{counts.get('critical', 0)}</div>
            <div class="label">Critical</div>
        </div>
        <div class="summary-card">
            <div class="count high-count">{counts.get('high', 0)}</div>
            <div class="label">High</div>
        </div>
        <div class="summary-card">
            <div class="count medium-count">{counts.get('medium', 0)}</div>
            <div class="label">Medium</div>
        </div>
        <div class="summary-card">
            <div class="count low-count">{counts.get('low', 0)}</div>
            <div class="label">Low</div>
        </div>
    </div>

    <!-- CTF Flags -->
    {ctf_flags_html}

    <!-- Scan Metadata -->
    <div class="section">
        <h2>Scan Information</h2>
        <div class="scan-meta">
            <div class="meta-item">
                <span class="meta-label">Target</span>
                <span class="meta-value">{self._escape(target)}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Scan Date</span>
                <span class="meta-value">{scan_date}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Checks Performed</span>
                <span class="meta-value">{', '.join(c.upper() for c in checks)}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Pages Scanned</span>
                <span class="meta-value">{len(visited_urls)}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Tool</span>
                <span class="meta-value">WScan v1.0</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Reproduction Package</span>
                <span class="meta-value"><a href="reproduction.json">reproduction.json</a> / <a href="reproduce.sh">reproduce.sh</a></span>
            </div>
            <div class="meta-item">
                <span class="meta-label">Remediation Plan</span>
                <span class="meta-value"><a href="remediation_plan.md">remediation_plan.md</a> / <a href="remediation_tasks.json">remediation_tasks.json</a></span>
            </div>
        </div>
    </div>

    <!-- AI Analysis / Attack Chains (⑧ ⑨) -->
    {ai_analysis_html}

    <!-- LLM Runtime Summary -->
    {llm_summary_html}

    <!-- Observability -->
    {observability_html}

    <!-- Coverage -->
    {coverage_html}

    <!-- Attack Plans -->
    {attack_plan_html}

    <!-- Remediation Summary -->
    {remediation_summary_html}

    <!-- Scan Checklist -->
    {checklist_html}

    <!-- Findings -->
    <div class="section">
        <h2>Vulnerability Findings ({total})</h2>
        <div class="filter-bar" id="finding-filters">
            <label>Filter:</label>
            <select id="filter-severity" onchange="applyFilters()">
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
            </select>
            <select id="filter-check" onchange="applyFilters()">
                <option value="">All Check Types</option>
                {' '.join(f'<option value="{c}">{c.upper()}</option>' for c in sorted(set(f.check_type for f in findings)))}
            </select>
            <input type="text" id="filter-search" placeholder="Search URL or field…" oninput="applyFilters()">
            <button onclick="document.getElementById('filter-severity').value='';document.getElementById('filter-check').value='';document.getElementById('filter-search').value='';applyFilters();" style="padding:6px 12px;border:1px solid #e2e8f0;border-radius:6px;cursor:pointer;font-size:0.85rem;">Reset</button>
        </div>
        {no_findings_html}
        <div id="findings-container">
        {findings_html}
        </div>
    </div>

    <!-- Page Flow Diagram -->
    {page_flow_html}

    <!-- Visited URLs (dashboard-style URL panel) -->
    <div class="section url-panel-section">
        <div class="url-panel-header">
            <h2>Scanned URLs ({url_total})</h2>
            <div class="url-panel-summary">
                <span class="url-badge url-badge-done">完了 {url_done_total}</span>
                <span class="url-badge url-badge-vuln">発見あり {url_vuln_total}</span>
            </div>
        </div>
        <div class="url-panel-toolbar">
            <input type="text" id="url-filter" class="url-filter-input" placeholder="URL でフィルタ…">
            <div class="url-filter-tabs">
                <button class="url-filter-tab active" data-filter="all">すべて</button>
                <button class="url-filter-tab" data-filter="vuln">発見あり</button>
                <button class="url-filter-tab" data-filter="done">完了</button>
            </div>
        </div>
        <div class="url-list" id="url-list">
            {urls_html}
        </div>
    </div>
</div>

<!-- Lightbox for screenshots -->
<div class="lightbox" id="lightbox" onclick="this.classList.remove('active')">
    <div class="lightbox-close">✕</div>
    <img id="lightbox-img" src="" alt="">
</div>

<div class="footer">
    Generated by WScan — Authorized Security Testing Only
</div>

<script>
// Screenshot lightbox
document.querySelectorAll('.evidence-screenshot').forEach(img => {{
    img.addEventListener('click', (e) => {{
        e.stopPropagation();
        document.getElementById('lightbox-img').src = img.src;
        document.getElementById('lightbox').classList.add('active');
    }});
}});
// Finding filter (U-2 equivalent in report)
function applyFilters() {{
    const sev = document.getElementById('filter-severity').value.toLowerCase();
    const chk = document.getElementById('filter-check').value.toLowerCase();
    const q   = document.getElementById('filter-search').value.toLowerCase();
    document.querySelectorAll('#findings-container .finding-card').forEach(card => {{
        const cardSev   = (card.dataset.severity || '').toLowerCase();
        const cardCheck = (card.dataset.check || '').toLowerCase();
        const cardUrl   = (card.dataset.url || '').toLowerCase();
        const cardField = (card.dataset.field || '').toLowerCase();
        const sevOk   = !sev || cardSev === sev;
        const chkOk   = !chk || cardCheck === chk;
        const searchOk = !q  || cardUrl.includes(q) || cardField.includes(q);
        card.style.display = (sevOk && chkOk && searchOk) ? '' : 'none';
    }});
}}
// Plan card collapse/expand
document.querySelectorAll('.plan-card-header').forEach(header => {{
    header.addEventListener('click', () => {{
        header.closest('.plan-card').classList.toggle('collapsed');
    }});
}});
// URL panel: filter + tab switching (dashboard-style)
(function() {{
    const list = document.getElementById('url-list');
    if (!list) return;
    const items = Array.from(list.querySelectorAll('.url-item'));
    const input = document.getElementById('url-filter');
    const tabs = document.querySelectorAll('.url-filter-tab');
    let activeFilter = 'all';
    function apply() {{
        const q = (input && input.value || '').toLowerCase();
        items.forEach(it => {{
            const status = it.dataset.status || 'done';
            const text = (it.querySelector('.url-text')?.textContent || '').toLowerCase();
            const statusOk = activeFilter === 'all' || status === activeFilter;
            const textOk = !q || text.includes(q);
            it.style.display = (statusOk && textOk) ? '' : 'none';
        }});
    }}
    if (input) input.addEventListener('input', apply);
    tabs.forEach(t => t.addEventListener('click', () => {{
        tabs.forEach(x => x.classList.remove('active'));
        t.classList.add('active');
        activeFilter = t.dataset.filter;
        apply();
    }}));
}})();
// Payload list expand
document.querySelectorAll('.plan-payloads-toggle').forEach(btn => {{
    btn.addEventListener('click', (e) => {{
        e.stopPropagation();
        const list = btn.nextElementSibling;
        list.classList.toggle('open');
        btn.textContent = list.classList.contains('open') ? '▲ ペイロードを隠す' : '▼ LLMペイロードを表示';
    }});
}});
</script>
</body>
</html>"""

    def _build_ai_analysis_html(self) -> str:
        """
        ⑧ Render the AI Analysis / Attack Chain section.
        Reads ai_analysis.md from the output directory (written by engine._ai_analysis_report).
        """
        analysis_path = self.output_dir / "ai_analysis.md"
        if not analysis_path.exists():
            return ""
        try:
            text = analysis_path.read_text(encoding="utf-8")
        except Exception:
            return ""
        if not text.strip():
            return ""

        safe_text = self._escape(text)
        return f"""
    <div class="ai-analysis-section">
        <h2>🤖 AI Security Analysis &amp; Attack Chains (⑧⑨)</h2>
        <div class="ai-analysis-body">{safe_text}</div>
    </div>"""

    def _build_ctf_flags_html(self, ctf_flags: list) -> str:
        """Render the CTF Flags section (only shown when CTF mode is active)."""
        if not ctf_flags:
            return ""

        items = ""
        for flag, source in ctf_flags:
            esc_flag = self._escape(flag)
            esc_src = self._escape(source)
            items += f"""
            <div class="ctf-flag-item">
                <div class="ctf-flag-value">{esc_flag}</div>
                <div class="ctf-flag-source">Found on: {esc_src}</div>
                <span class="ctf-flag-copy" data-flag="{esc_flag}" onclick="navigator.clipboard.writeText(this.dataset.flag).then(()=>this.textContent='Copied!')">📋 Copy to clipboard</span>
            </div>"""

        return f"""
    <div class="ctf-section">
        <h2>🚩 CTF Flags Captured ({len(ctf_flags)})</h2>
        <div class="ctf-flag-list">
            {items}
        </div>
    </div>"""

    def _build_attack_plan_html(self, attack_plans: list) -> str:
        """Render the Attack Planning section of the report (Phase 2 results)."""
        if not attack_plans:
            return ""

        # ── Risk distribution across all fields ─────────────────────
        all_fields = [fp for plan in attack_plans for fp in plan.fields]
        high_count = sum(1 for fp in all_fields if fp.risk_score >= 8)
        mid_count  = sum(1 for fp in all_fields if 5 <= fp.risk_score < 8)
        low_count  = sum(1 for fp in all_fields if fp.risk_score < 5)
        llm_pages  = sum(1 for p in attack_plans if p.planned_by == "llm")

        stat_html = f"""
        <div class="plan-section-meta">
            <div class="plan-stat-card">
                <div class="ps-count">{len(attack_plans)}</div>
                <div class="ps-label">Pages planned</div>
            </div>
            <div class="plan-stat-card">
                <div class="ps-count">{len(all_fields)}</div>
                <div class="ps-label">Fields analyzed</div>
            </div>
            <div class="plan-stat-card ps-high">
                <div class="ps-count">{high_count}</div>
                <div class="ps-label">High risk (8-10)</div>
            </div>
            <div class="plan-stat-card ps-mid">
                <div class="ps-count">{mid_count}</div>
                <div class="ps-label">Medium risk (5-7)</div>
            </div>
            <div class="plan-stat-card ps-low">
                <div class="ps-count">{low_count}</div>
                <div class="ps-label">Low risk (1-4)</div>
            </div>
            <div class="plan-stat-card" style="background:#faf5ff;border-color:#d6bcfa;">
                <div class="ps-count" style="color:#6b46c1;">{llm_pages}</div>
                <div class="ps-label" style="color:#6b46c1;">LLM planned</div>
            </div>
        </div>"""

        # ── Per-page plan cards ──────────────────────────────────────
        cards_html = ""
        for plan in attack_plans:
            sorted_fields = sorted(plan.fields, key=lambda f: f.risk_score, reverse=True)
            fields_rows = ""
            for fp in sorted_fields:
                color = _risk_color(fp.risk_score)
                checks_html = "".join(
                    f'<span class="plan-check-badge priority-{min(i, 2)}">{self._escape(c)}</span>'
                    for i, c in enumerate(fp.priority_checks)
                ) or '<span style="color:#a0aec0">—</span>'

                # Cross-page indicator
                rationale_text = fp.rationale or ""
                cross_tag = ""
                cross_keywords = ["cross-page", "stored", "second-order", "another page",
                                   "格納型", "別ページ", "クロスページ"]
                if any(kw.lower() in rationale_text.lower() for kw in cross_keywords):
                    cross_tag = '<span class="cross-page-tag">⚠ Cross-page</span> '

                # LLM-generated payloads
                payload_html = ""
                if fp.custom_payloads:
                    payload_items = ""
                    for check_type, payloads in fp.custom_payloads.items():
                        if not payloads:
                            continue
                        codes = "".join(
                            f'<code>{self._escape(p)}</code>' for p in payloads[:6]
                        )
                        payload_items += f'<div class="plan-payload-type">{self._escape(check_type)}</div>{codes}'
                    if payload_items:
                        payload_html = f"""
                        <span class="plan-payloads-toggle">▼ LLMペイロードを表示 ({sum(len(v) for v in fp.custom_payloads.values())}件)</span>
                        <div class="plan-payload-list">{payload_items}</div>"""

                fields_rows += f"""
                <div class="plan-field-row">
                    <div class="plan-field-name">{self._escape(fp.name)}</div>
                    <div><div class="plan-risk-badge" style="background:{color}">{fp.risk_score}</div></div>
                    <div class="plan-checks">{checks_html}</div>
                    <div class="plan-rationale-col">
                        <div class="plan-rationale">{cross_tag}{self._escape(rationale_text)}</div>
                        {payload_html}
                    </div>
                </div>"""

            planned_by_label = "🤖 AI (LLM)" if plan.planned_by == "llm" else "📐 Heuristic"
            by_class = "plan-by llm" if plan.planned_by == "llm" else "plan-by"
            cards_html += f"""
            <div class="plan-card">
                <div class="plan-card-header">
                    <div class="plan-header-left">
                        <div class="plan-url">{self._escape(plan.url)}</div>
                        <div class="plan-purpose">{self._escape(plan.page_purpose)}</div>
                        <div class="{by_class}">{planned_by_label} · {len(plan.fields)} fields</div>
                    </div>
                    <div class="plan-toggle">▾</div>
                </div>
                <div class="plan-fields">
                    <div class="plan-cols-header">
                        <span>Field / Parameter</span><span>Risk</span>
                        <span>Priority Checks</span><span>Rationale &amp; LLM Payloads</span>
                    </div>
                    {fields_rows or '<div class="no-plans">No testable fields found.</div>'}
                </div>
            </div>"""

        return f"""
    <div class="section">
        <h2>🗺 Attack Plan — Phase 2 ({len(attack_plans)} page{'s' if len(attack_plans) != 1 else ''})</h2>
        <p style="color:#718096;font-size:.9rem;margin-bottom:16px;">
            巡回完了後に LLM / ヒューリスティックが生成した攻撃プランです。
            リスクスコアが高いフィールドを優先的に攻撃しました。
            <strong style="color:#553c9a">⚠ Cross-page</strong> は格納型 XSS や別ページへの影響が疑われるフィールドを示します。
        </p>
        {stat_html}
        {cards_html}
    </div>"""

    def _build_page_flow_html(self, page_graph: dict, url_finding_counts: dict = None) -> str:
        """
        ビジュアルサイトマップ。3つの表示モード（コンパクト / スクショ / 一覧）を切り替えられる
        自己完結 (CDN なし) の SVG + JS として埋め込む。各遷移には「どの要素をクリックして
        そのページへ来たか」(via) を、ノードにはページのスクリーンショットを保持する。

        page_graph: {url: {"parent", "depth", "forms", "inputs", "params",
                            "via": {text,selector,rect,viewport}, "screenshot_b64": str}}
        url_finding_counts: {url: count}  検出ありは赤くマーキング
        """
        if not page_graph:
            return ""

        import json as _json
        url_finding_counts = url_finding_counts or {}

        nodes = []
        for url, info in page_graph.items():
            findings = int(url_finding_counts.get(url, 0))
            nodes.append({
                "url": url,
                "parent": info.get("parent") or "",
                "depth": int(info.get("depth", 0) or 0),
                "forms": int(info.get("forms", 0) or 0),
                "inputs": int(info.get("inputs", 0) or 0),
                "params": int(info.get("params", 0) or 0),
                "findings": findings,
                "status": "vuln" if findings > 0 else "done",
                "via": info.get("via") or None,
                "shot": info.get("screenshot_b64") or "",
            })
        vuln_count = sum(1 for n in nodes if n["status"] == "vuln")
        done_count = len(nodes) - vuln_count
        # Serialize for an HTML <script> context: escape characters that could break out
        # of the script tag (e.g. attacker-controlled link text containing "</script>").
        nodes_json = (
            _json.dumps(nodes)
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026")
        )

        # テキストフォールバック (ツリー)
        def _fb_row(url, info):
            n = url_finding_counts.get(url, 0)
            col = "#f85149" if n > 0 else "#8b949e"
            indent = "&nbsp;" * 3 * int(info.get("depth", 0) or 0)
            tail = f' <span style="color:#f85149">({n} findings)</span>' if n > 0 else ""
            return (
                f'<li style="padding:2px 0;font-family:monospace;font-size:.78rem;color:{col}">'
                f'{indent}↳ <a href="{self._escape(url)}" target="_blank" style="color:inherit">'
                f'{self._escape(url)}</a>{tail}</li>'
            )
        fallback_items = "".join(_fb_row(u, info) for u, info in page_graph.items())

        header = f"""
    <div class="section" id="site-map-section">
        <h2>🗺 Visual Site Map ({len(page_graph)} pages)</h2>
        <div class="sm-toolbar">
            <span class="sm-pill">画面遷移図 <strong>{len(page_graph)}</strong></span>
            <input id="rpt-sm-search" class="sm-search" placeholder="検索…" oninput="rptSmSearch(this.value)">
            <span class="sm-modes">
                <button class="sm-mode-btn active" id="rpt-sm-m-compact" type="button" onclick="rptSmMode('compact')">コンパクト</button>
                <button class="sm-mode-btn" id="rpt-sm-m-shots" type="button" onclick="rptSmMode('shots')">スクショ</button>
                <button class="sm-mode-btn" id="rpt-sm-m-explorer" type="button" onclick="rptSmMode('explorer')">一覧</button>
            </span>
            <button class="sm-pill sm-btn" type="button" onclick="rptSmExpand(true)">全展開</button>
            <button class="sm-pill sm-btn" type="button" onclick="rptSmExpand(false)">全折りたたみ</button>
            <button class="sm-pill sm-btn" type="button" onclick="rptSmZoom(0.8)">－</button>
            <button class="sm-pill sm-btn" type="button" onclick="rptSmZoom(1.25)">＋</button>
            <button class="sm-pill sm-btn" type="button" onclick="rptSmReset()">⟲</button>
            <span class="sm-pill sm-spacer"></span>
            <span class="sm-pill"><span class="sm-dot" style="background:#388bfd"></span>完了 {done_count}</span>
            <span class="sm-pill"><span class="sm-dot" style="background:#f85149"></span>検出 {vuln_count}</span>
        </div>
        <div id="rpt-sm-wrap" style="position:relative;height:560px;background:#0a0c0f;border:1px solid #21262d;border-radius:8px;overflow:hidden">
            <svg id="rpt-sm-svg" style="width:100%;height:100%;display:block"></svg>
            <div id="rpt-sm-explorer" style="position:absolute;inset:8px;display:none;gap:8px"></div>
            <div id="rpt-sm-tip" style="position:absolute;display:none;z-index:3;max-width:340px;background:rgba(13,17,23,.96);border:1px solid #30363d;color:#e6edf3;border-radius:6px;padding:6px 8px;font-size:.72rem;pointer-events:none;box-shadow:0 8px 24px rgba(0,0,0,.45)"></div>
            <div id="rpt-sm-pop" style="position:absolute;display:none;z-index:5;width:340px;background:rgba(13,17,23,.97);border:1px solid #58a6ff;border-radius:10px;padding:10px;font-size:.74rem;box-shadow:0 10px 30px rgba(0,0,0,.6)"></div>
            <div id="rpt-sm-fallback" style="display:none;position:absolute;inset:8px;overflow:auto;padding:8px;background:#0d1117;border-radius:6px">
                <ul style="list-style:none;padding:0;margin:0">{fallback_items}</ul>
            </div>
        </div>
        <p style="font-size:.75rem;color:#718096;margin-top:6px">
            コンパクト=ツリー / スクショ=画面サムネにクリック箇所を表示 / 一覧=ツリー+詳細
            · 矢印のラベル=クリックした要素 · ホイールでズーム / ドラッグでパン
        </p>
        <style>
            .sm-toolbar {{ display:flex; gap:6px; align-items:center; margin-bottom:8px; flex-wrap:wrap; }}
            .sm-pill {{ background:rgba(13,17,23,.82); border:1px solid #30363d; color:#8b949e;
                        border-radius:999px; padding:4px 10px; font-size:.72rem; font-weight:700; white-space:nowrap; }}
            .sm-pill .sm-dot {{ width:8px; height:8px; border-radius:50%; display:inline-block; margin-right:5px; vertical-align:middle; }}
            .sm-spacer {{ flex:1; background:transparent; border:0; padding:0; }}
            .sm-btn {{ cursor:pointer; }}
            .sm-btn:hover {{ color:#e6edf3; border-color:#58a6ff; }}
            .sm-search {{ background:#0d1117; border:1px solid #30363d; color:#e6edf3; border-radius:6px; padding:4px 9px; font-size:.72rem; width:140px; }}
            .sm-modes {{ display:inline-flex; border:1px solid #30363d; border-radius:6px; overflow:hidden; }}
            .sm-mode-btn {{ background:transparent; border:0; color:#8b949e; cursor:pointer; padding:4px 9px; font-size:.72rem; font-weight:700; }}
            .sm-mode-btn.active {{ background:#1f6feb; color:#fff; }}
            #rpt-sm-svg .sm-node-g {{ cursor:pointer; }}
            .rsm-trow {{ display:flex; align-items:center; gap:6px; padding:4px 6px; border-radius:6px; cursor:pointer; white-space:nowrap; font-size:.76rem; color:#c9d1d9; }}
            .rsm-trow:hover {{ background:#161b22; }}
            .rsm-trow.sel {{ background:rgba(56,139,253,.18); outline:1px solid #58a6ff; }}
            .rsm-caret {{ width:12px; color:#8b949e; text-align:center; flex-shrink:0; }}
            .rsm-cnt {{ margin-left:auto; color:#8b949e; font-size:.68rem; }}
        </style>
        <script>"""
        data_js = f"\nvar RPT_SM_NODES = {nodes_json};\n"
        return header + data_js + _RPT_SITEMAP_JS + "\n        </script>\n    </div>"

    def _format_request(self, req: dict) -> str:
        if not req:
            return '<div class="network-box"><h4>Request</h4><div class="network-content">N/A</div></div>'
        method = req.get("method", "GET")
        url = req.get("url", "")
        # Authorization/Cookie/X-Api-Key 等の認証ヘッダはレポート成果物へ平文で残さない
        # （request_logger と同じ _redact_headers を単一の真実として再利用）。
        from .request_logger import _redact_headers
        headers = _redact_headers(req.get("headers", {}))
        body = req.get("post_data", "") or ""
        headers_text = "\n".join(f"{k}: {v}" for k, v in list(headers.items())[:10])
        content = f"{method} {url}\n\n{headers_text}"
        if body:
            content += f"\n\n{body[:500]}"
        return f'<div class="network-box"><h4>HTTP Request</h4><div class="network-content">{self._escape(content)}</div></div>'

    def _format_response(self, resp: dict, finding: Finding) -> str:
        if not resp:
            return '<div class="network-box"><h4>Response</h4><div class="network-content">N/A</div></div>'
        status = resp.get("status", "")
        # Set-Cookie 等の機微な応答ヘッダも伏字化する。
        from .request_logger import _redact_headers
        headers = _redact_headers(resp.get("headers", {}))
        body = finding.response.get("body", "") or ""
        headers_text = "\n".join(f"{k}: {v}" for k, v in list(headers.items())[:10])
        content = f"HTTP {status}\n\n{headers_text}"
        if body:
            content += f"\n\n{body[:1000]}"
        return f'<div class="network-box"><h4>HTTP Response</h4><div class="network-content">{self._escape(content)}</div></div>'

    def _format_structured_evidence(self, finding: Finding) -> str:
        evidence_type = getattr(finding, "evidence_type", "") or finding.check_type
        details = getattr(finding, "evidence_details", {}) or {}
        steps = getattr(finding, "reproduction_steps", []) or []
        if not details and not steps and not evidence_type:
            return ""

        # 明示的な verification_state を legacy boolean より優先する。verified=False でも
        # state="assumed"（Agent 仮説など一度も retry していない finding）を "not reproduced"
        # ＝失敗した再現試行、と偽らないため。state 空（旧 Finding）だけ verified に fallback。
        state = getattr(finding, "verification_state", "")
        if state == "reproduced":
            v_label = "reproduced"
        elif state == "assumed":
            v_label = "assumed (not re-verified)"
        elif state == "unreproduced":
            v_label = "not reproduced"
        elif state == "skipped":
            v_label = "skipped (needs review)"
        elif not getattr(finding, "verified", True):
            v_label = "not reproduced"
        else:
            v_label = "reproduced/assumed"

        cells = [
            ("Evidence Type", evidence_type),
            ("Confidence", getattr(finding, "confidence", "tentative")),
            ("Verification", v_label),
        ]
        for key, value in list(details.items())[:8]:
            cells.append((str(key).replace("_", " ").title(), value))

        cells_html = "".join(
            '<div class="evidence-cell">'
            f'<div class="k">{self._escape(k)}</div>'
            f'<div class="v">{self._escape(self._short_value(v))}</div>'
            '</div>'
            for k, v in cells
        )
        steps_html = ""
        if steps:
            steps_html = "<ol class=\"repro-list\">" + "".join(
                f"<li>{self._escape(step)}</li>" for step in steps[:8]
            ) + "</ol>"
        return f"""
        <div class="finding-detail">
            <h4>Structured Evidence</h4>
            <div class="evidence-grid">{cells_html}</div>
            {steps_html}
        </div>"""

    def _short_value(self, value) -> str:
        if isinstance(value, (dict, list)):
            text = json.dumps(value, ensure_ascii=False)
        else:
            text = str(value)
        return text if len(text) <= 240 else text[:237] + "..."

    def _build_remediation_summary_html(self, findings: list[Finding]) -> str:
        if not findings:
            return ""
        try:
            from .action_plan import build_action_plan
            plan = build_action_plan(findings)
        except Exception:
            return ""

        tasks = plan.get("tasks", [])
        review_items = plan.get("review_items", [])
        if not tasks and not review_items:
            return ""

        task_cards = ""
        for task in tasks:
            priority = self._escape(task.get("priority", "P3"))
            priority_class = priority.lower()
            related = task.get("related_findings", [])
            related_html = ""
            if related:
                related_html = (
                    f'<div class="remediation-related">Related findings: '
                    f'{len(related)} additional path(s)</div>'
                )
            v_state = task.get("verification_state", "") or "reproduced/assumed"
            confirm_html = (
                '<span class="badge-unconfirmed" title="group 内に未再検証(assumed)の経路あり。'
                '修正前に再現を確認">⚠ 要手動確認</span>'
                if task.get("needs_confirmation")
                else ""
            )
            task_cards += f"""
            <div class="remediation-card {priority_class}">
                <div class="remediation-head">
                    <span class="priority-pill {priority_class}">{priority}</span>
                    <span class="remediation-title">{self._escape(task.get("title", ""))}</span>
                    {confirm_html}
                </div>
                <div class="remediation-meta">
                    <span>{self._escape(task.get("check_type", ""))}</span>
                    <span>{self._escape(task.get("severity", ""))}</span>
                    <span>{self._escape(task.get("confidence", ""))}</span>
                    <span>{self._escape(task.get("evidence_type", ""))}</span>
                    <span>verify: {self._escape(v_state)}</span>
                </div>
                <div><code>{self._escape(task.get("field_name", ""))}</code></div>
                <div class="remediation-evidence">{self._escape(task.get("evidence", ""))}</div>
                {related_html}
            </div>"""

        review_html = ""
        if review_items:
            rows = ""
            for item in review_items[:20]:
                rows += f"""
                <div class="review-item">
                    <b>{self._escape(item.get("id", ""))}</b>
                    {self._escape(item.get("check_type", ""))}
                    / <code>{self._escape(item.get("field_name", ""))}</code>
                    / {self._escape(item.get("confidence", ""))}
                    / verified={self._escape(str(item.get("verified", "")))}
                    / verify={self._escape(", ".join(item.get("verification_states") or [item.get("verification_state", "") or "unknown"]))}
                    / related={len(item.get("related_signals", []))}
                    <br>{self._escape(item.get("reason", ""))}
                </div>"""
            if len(review_items) > 20:
                rows += f'<div class="review-item">Showing first 20 of {len(review_items)} review-only signals.</div>'
            review_html = f"""
            <div class="review-list">
                <h3>Review-only Signals ({len(review_items)})</h3>
                {rows}
            </div>"""

        return f"""
        <div class="section">
            <h2>Remediation Summary ({len(tasks)} tasks)</h2>
            <p class="note" style="margin-bottom:14px">
                Confirmed or likely findings are grouped by fix target. Tentative or unreproduced signals are kept separate for manual review.
            </p>
            <div class="remediation-grid">
                {task_cards}
            </div>
            {review_html}
        </div>"""

    def _build_scan_checklist_html(self, scan_matrix: list[dict]) -> str:
        if not scan_matrix:
            return ""
        summary: dict[str, int] = {}
        for row in scan_matrix:
            status = row.get("status", "tested")
            summary[status] = summary.get(status, 0) + 1

        summary_html = " ".join(
            f'<span class="status-pill status-{self._escape(status)}">{self._escape(status)}: {count}</span>'
            for status, count in sorted(summary.items())
        )
        rows_html = ""
        for row in scan_matrix[:500]:
            status = row.get("status", "tested")
            rows_html += f"""
            <tr>
                <td><span class="status-pill status-{self._escape(status)}">{self._escape(status)}</span></td>
                <td>{self._escape(row.get("check", ""))}</td>
                <td>{self._escape(row.get("location", ""))}</td>
                <td><code>{self._escape(row.get("field_name", ""))}</code></td>
                <td>{self._escape(row.get("url", ""))}</td>
                <td>{self._escape(row.get("severity", "") or row.get("note", ""))}</td>
            </tr>"""

        truncated = ""
        if len(scan_matrix) > 500:
            truncated = f"<p class=\"note\">Showing first 500 of {len(scan_matrix)} checklist rows.</p>"

        return f"""
        <div class="section">
            <h2>Scan Checklist ({len(scan_matrix)} checks)</h2>
            <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">{summary_html}</div>
            <div class="table-scroll">
            <table class="checklist-table">
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>Check</th>
                        <th>Location</th>
                        <th>Field</th>
                        <th>URL</th>
                        <th>Severity / Note</th>
                    </tr>
                </thead>
                <tbody>{rows_html}</tbody>
            </table>
            </div>
            {truncated}
        </div>"""

    def _build_observability_html(self, observability: dict) -> str:
        """劣化・脱落した probe/wave を Finding と分離して明示する。"""
        total = int(observability.get("total", 0) or 0)
        categories = observability.get("by_category", {}) or {}
        samples = observability.get("samples", []) or []
        category_html = "".join(
            f"<li><code>{self._escape(category)}</code>: {count}</li>"
            for category, count in sorted(categories.items())
        ) or "<li>なし</li>"
        sample_html = "".join(
            f"<li><code>{self._escape(str(sample))}</code></li>"
            for sample in samples
        ) or "<li>なし</li>"
        warning = ""
        if total:
            warning = (
                '<p style="color:#975a16;font-weight:600;margin-top:10px">'
                '0 findings は「安全」を意味しない可能性があります。</p>'
            )
        return f"""
        <div class="section observability-section">
            <h2>Observability（観測性メトリクス）</h2>
            <p>劣化・脱落した probe/wave: <strong>{total}</strong> 件</p>
            {warning}
            <h3 style="margin-top:14px">by_category</h3>
            <ul>{category_html}</ul>
            <h3 style="margin-top:14px">代表サンプル</h3>
            <ul>{sample_html}</ul>
        </div>"""

    def _build_coverage_html(self, coverage: dict) -> str:
        """到達性、試行結果、HTTP status を Finding と分離して表示する。

        coverage 未提供（Agent モード等 metrics を渡さない caller）では None/空 dict に
        なる。矛盾した「Findings: 0」セクションを描画せず、セクションごと省略する（Codex #102）。
        """
        if not coverage:
            return ""
        http_status = coverage.get("http_status", {}) or {}
        reached_count = self._escape(coverage.get("reached_count", 0))
        attempts = self._escape(coverage.get("attempts", 0))
        findings_total = self._escape(coverage.get("findings_total", 0))
        http_total = self._escape(http_status.get("total", 0))
        blocked_raw = http_status.get("blocked", 0) or 0
        blocked = self._escape(blocked_raw)
        server_error = self._escape(http_status.get("server_error", 0))
        client_error = self._escape(http_status.get("client_error", 0))

        by_status = coverage.get("by_status", {}) or {}
        by_status_html = "".join(
            f"<li><code>{self._escape(status)}</code>: {self._escape(count)}</li>"
            for status, count in sorted(by_status.items(), key=lambda item: str(item[0]))
        ) or "<li>なし</li>"
        reached_rows = "".join(
            "<tr>" f"<td>{self._escape(url)}</td>" "</tr>"
            for url in (coverage.get("reached_urls", []) or [])
        ) or '<tr><td colspan="1">なし</td></tr>'
        unreached_rows = "".join(
            "<tr>"
            f"<td>{self._escape((row or {}).get('url', ''))}</td>"
            f"<td>{self._escape((row or {}).get('reason', ''))}</td>"
            "</tr>"
            for row in (coverage.get("unreached", []) or [])
            if isinstance(row, dict)
        ) or '<tr><td colspan="2">なし</td></tr>'
        blocked_warning = ""
        try:
            has_blocked = int(blocked_raw) > 0
        except (TypeError, ValueError):
            has_blocked = False
        if has_blocked:
            blocked_warning = (
                '<p style="color:#975a16;font-weight:600;margin-top:10px">'
                f"{blocked} 件が 403/429 でブロック＝WAF/レート制限により攻撃面を"
                "十分に検査できていない可能性があります</p>"
            )

        return f"""
        <div class="section coverage-section">
            <h2>Coverage（到達性カバレッジ）</h2>
            <p>到達 URL: <strong>{reached_count}</strong> 件 / 試行: <strong>{attempts}</strong> 件 /
            Findings: <strong>{findings_total}</strong> 件</p>
            <h3 style="margin-top:14px">試行結果（by_status）</h3>
            <ul>{by_status_html}</ul>
            <h3 style="margin-top:14px">HTTP status</h3>
            <p>total: <strong>{http_total}</strong> / blocked (403/429): <strong>{blocked}</strong> /
            client_error (4xx): <strong>{client_error}</strong> /
            server_error: <strong>{server_error}</strong></p>
            {blocked_warning}
            <h3 style="margin-top:14px">到達済み URL</h3>
            <div class="table-wrap"><table><thead><tr><th>URL</th></tr></thead>
            <tbody>{reached_rows}</tbody></table></div>
            <h3 style="margin-top:14px">未到達 URL</h3>
            <div class="table-wrap"><table><thead><tr><th>URL</th><th>Reason</th></tr></thead>
            <tbody>{unreached_rows}</tbody></table></div>
        </div>"""

    def _build_llm_summary_html(self, summary: dict) -> str:
        if not summary:
            return ""
        provider = summary.get("provider", "none")
        if provider == "none":
            return ""
        fields = [
            ("Provider", provider),
            ("Model", summary.get("model", "")),
            ("Plans", summary.get("total_plans", 0)),
            ("LLM Plans", summary.get("llm_plans", 0)),
            ("Fallback Plans", summary.get("heuristic_plans", 0)),
        ]
        cells = "".join(
            '<div class="meta-item">'
            f'<span class="meta-label">{self._escape(label)}</span>'
            f'<span class="meta-value">{self._escape(value)}</span>'
            '</div>'
            for label, value in fields
        )
        role_models = summary.get("role_models") or {}
        role_html = ""
        if role_models:
            role_cells = "".join(
                '<div class="meta-item">'
                f'<span class="meta-label">{self._escape(role.title())}</span>'
                f'<span class="meta-value">{self._escape(model)}</span>'
                '</div>'
                for role, model in sorted(role_models.items())
            )
            role_html = f"""
            <h3 style="margin:16px 0 8px;font-size:1rem;color:#2d3748">Role Models</h3>
            <div class="scan-meta">{role_cells}</div>"""
        note = summary.get("note", "")
        note_html = f'<p class="note" style="margin-top:12px">{self._escape(note)}</p>' if note else ""
        return f"""
        <div class="section">
            <h2>LLM Runtime Summary</h2>
            <div class="scan-meta">{cells}</div>
            {role_html}
            {note_html}
        </div>"""

    @staticmethod
    def _escape(text: str) -> str:
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )

    @staticmethod
    def _agent_badges_html(finding: Finding) -> str:
        """Agent由来の解釈と、任意の決定論再現結果を明示する。"""
        if getattr(finding, "source", "scanner") != "agent":
            return ""
        if getattr(finding, "agent_verified", False):
            return (
                '<span class="badge-agent">🤖 Agent発見（LLM独自解釈）</span>'
                '<span class="badge-agent-verified">✅ 決定論的にも再現確認済み</span>'
            )
        return '<span class="badge-agent">🤖 Agent発見（LLM独自解釈・未確証）</span>'

    # =========================================================================
    # F: Executive Report
    # =========================================================================

    def _build_executive_html(
        self, target, findings, visited_urls, checks,
        attack_plans, ctf_flags, page_graph, diff_result=None, scan_matrix=None,
        observability=None, coverage=None,
    ) -> str:
        """経営層向け: サマリーカード・リスク分布・コンプライアンス適合率・推奨事項。"""
        scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        counts = {sev: sum(1 for f in findings if f.severity == sev)
                  for sev in ["critical", "high", "medium", "low", "info"]}
        total = len(findings)
        agent_total = sum(
            1 for f in findings if getattr(f, "source", "scanner") == "agent"
        )
        agent_verified_total = sum(
            1 for f in findings
            if getattr(f, "source", "scanner") == "agent"
            and getattr(f, "agent_verified", False)
        )
        agent_summary_html = ""
        if agent_total:
            agent_summary_html = f"""
            <div class="exec-card" style="border-left:4px solid #6b46c1">
              <div class="exec-count" style="color:#6b46c1">{agent_total}</div>
              <div class="exec-label">🤖 Agent発見（LLM独自解釈）</div>
              <div style="font-size:.75rem;color:#718096;margin-top:6px">
                決定論的にも再現確認済み: {agent_verified_total} / 未確証: {agent_total - agent_verified_total}
              </div>
            </div>"""

        # リスクスコア (CVSS重み付き平均)
        cvss_scores = [getattr(f, "cvss_score", 0.0) for f in findings]
        avg_cvss = (sum(cvss_scores) / len(cvss_scores)) if cvss_scores else 0.0

        # コンプライアンス違反タイプ集計
        top10_violations: dict[str, int] = {}
        pci_violations: dict[str, int] = {}
        for f in findings:
            refs = getattr(f, "compliance_refs", None) or {}
            if callable(getattr(refs, "get", None)):
                for ref in refs.get("owasp_top10", []):
                    top10_violations[ref] = top10_violations.get(ref, 0) + 1
                for ref in refs.get("pci_dss", []):
                    pci_violations[ref] = pci_violations.get(ref, 0) + 1

        top10_html = "".join(
            f'<li>{self._escape(k)}: <b>{v}件</b></li>'
            for k, v in sorted(top10_violations.items(), key=lambda x: -x[1])[:5]
        ) or "<li>違反なし</li>"

        pci_html = "".join(
            f'<li>{self._escape(k)}: <b>{v}件</b></li>'
            for k, v in sorted(pci_violations.items(), key=lambda x: -x[1])[:5]
        ) or "<li>違反なし</li>"

        # 差分サマリー
        diff_html = ""
        if diff_result:
            diff_html = f"""
            <div class="exec-card" style="border-left:4px solid #4299e1">
                <div class="exec-label">差分スキャン結果</div>
                <div style="font-size:0.9rem;margin-top:8px">
                    🆕 新規: <b>{len(diff_result.new_findings)}</b> 件 /
                    ✅ 修正済: <b>{len(diff_result.fixed_findings)}</b> 件 /
                    🔄 継続: <b>{len(diff_result.persistent_findings)}</b> 件
                </div>
            </div>"""

        # 推奨事項 (重要度別)
        recs = []
        if counts.get("critical", 0) > 0:
            recs.append("【緊急】クリティカルな脆弱性が検出されました。即時修正が必要です。")
        if counts.get("high", 0) > 0:
            recs.append("【高】高リスクの脆弱性が検出されました。速やかな対応を推奨します。")
        if "security_headers" in checks:
            recs.append("セキュリティヘッダ (CSP, HSTS, X-Frame-Options) の設定を確認してください。")
        recs.append("定期的なペネトレーションテストの実施を推奨します。")
        rec_html = "".join(f"<li>{self._escape(r)}</li>" for r in recs)
        observability_html = self._build_observability_html(observability or {})
        coverage_html = self._build_coverage_html(coverage or {})

        return f"""<!DOCTYPE html>
<html lang="ja"><head><meta charset="UTF-8">
<title>Executive Report — {self._escape(target)}</title>
<style>
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f7f8fa;color:#1a202c;margin:0}}
.hdr{{background:linear-gradient(135deg,#1a202c,#2d3748);color:#fff;padding:40px}}
.hdr h1{{font-size:1.8rem;font-weight:700}} .hdr .sub{{color:#a0aec0;font-size:.9rem;margin-top:6px}}
.container{{max-width:1000px;margin:0 auto;padding:32px 24px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:24px}}
.exec-card{{background:#fff;border-radius:12px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
.exec-count{{font-size:2.5rem;font-weight:800}} .exec-label{{font-size:.8rem;color:#718096;text-transform:uppercase;letter-spacing:.05em}}
.critical{{color:#e53e3e}} .high{{color:#dd6b20}} .medium{{color:#d69e2e}} .low{{color:#38a169}}
.section{{background:#fff;border-radius:12px;padding:24px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
.section h2{{font-size:1.1rem;font-weight:700;margin-bottom:16px;border-bottom:2px solid #e2e8f0;padding-bottom:8px}}
ul li{{margin:4px 0;font-size:.9rem}} .footer{{text-align:center;color:#a0aec0;font-size:.75rem;padding:24px}}
</style></head><body>
<div class="hdr">
  <h1>Executive Security Report</h1>
  <div class="sub">{self._escape(target)} &nbsp;|&nbsp; {scan_date} &nbsp;|&nbsp; 検査項目: {len(checks)} 種</div>
</div>
<div class="container">
  <div class="grid">
    <div class="exec-card" style="border-left:4px solid #e53e3e">
      <div class="exec-count critical">{counts.get("critical",0)}</div>
      <div class="exec-label">Critical</div>
    </div>
    <div class="exec-card" style="border-left:4px solid #dd6b20">
      <div class="exec-count high">{counts.get("high",0)}</div>
      <div class="exec-label">High</div>
    </div>
    <div class="exec-card" style="border-left:4px solid #d69e2e">
      <div class="exec-count medium">{counts.get("medium",0)}</div>
      <div class="exec-label">Medium</div>
    </div>
    <div class="exec-card" style="border-left:4px solid #38a169">
      <div class="exec-count low">{counts.get("low",0)}</div>
      <div class="exec-label">Low</div>
    </div>
    <div class="exec-card">
      <div class="exec-count" style="color:#4299e1">{total}</div>
      <div class="exec-label">Total Findings</div>
    </div>
    <div class="exec-card">
      <div class="exec-count" style="color:#805ad5">{avg_cvss:.1f}</div>
      <div class="exec-label">Avg CVSS Score</div>
    </div>
    {agent_summary_html}
    {diff_html}
  </div>
  <div class="section">
    <h2>OWASP Top 10 違反 (上位5件)</h2>
    <ul>{top10_html}</ul>
  </div>
  <div class="section">
    <h2>PCI DSS 違反 (上位5件)</h2>
    <ul>{pci_html}</ul>
  </div>
  <div class="section">
    <h2>推奨事項</h2>
    <ul>{rec_html}</ul>
  </div>
  {observability_html}
  {coverage_html}
  <div class="section">
    <h2>スキャン範囲</h2>
    <p style="font-size:.9rem">{len(visited_urls)} ページを検査 / 検査項目: {", ".join(checks)}</p>
  </div>
</div>
<div class="footer">WScan Security Report &mdash; Executive Summary</div>
</body></html>"""

    # =========================================================================
    # F: Developer Report
    # =========================================================================

    def _build_developer_html(
        self, target, findings, visited_urls, checks,
        attack_plans, ctf_flags, page_graph, diff_result=None, scan_matrix=None,
        observability=None, coverage=None,
    ) -> str:
        """開発者向け: チェックリスト形式・修正コード例・重要度別ソート。"""
        scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        items_html = ""
        for i, f in enumerate(findings):
            color = SEVERITY_COLORS.get(f.severity, "#718096")
            is_agent = getattr(f, "source", "scanner") == "agent"
            source_class = " finding-item-agent" if is_agent else ""
            source_badges = self._agent_badges_html(f)
            ai_fix = getattr(f, "ai_fix", "") or ""
            ai_fix_html = ""
            if ai_fix:
                safe_fix = self._escape(ai_fix).replace("\n", "<br>")
                ai_fix_html = f'<div class="fix-box"><b>修正ガイダンス:</b><br>{safe_fix}</div>'

            compliance_refs = getattr(f, "compliance_refs", None) or {}
            refs_parts = []
            if compliance_refs.get("owasp_top10"):
                refs_parts.append(", ".join(compliance_refs["owasp_top10"]))
            if compliance_refs.get("pci_dss"):
                refs_parts.append(", ".join(compliance_refs["pci_dss"][:2]))
            refs_html = f'<div class="refs">{self._escape(" / ".join(refs_parts))}</div>' if refs_parts else ""

            conf = getattr(f, "confidence", "tentative")
            diff_status = getattr(f, "_diff_status", "") or f.__dict__.get("_diff_status", "")
            status_badge = ""
            if diff_status == "new":
                status_badge = '<span class="new-badge">NEW</span>'
            elif diff_status == "fixed":
                status_badge = '<span class="fixed-badge">FIXED</span>'

            items_html += f"""
            <div class="finding-item{source_class}" style="border-left:4px solid {color}">
                <div class="fi-header">
                    <input type="checkbox" class="fi-check" id="fix-{i}">
                    <label for="fix-{i}">
                        <span class="sev-tag" style="background:{color}">{f.severity.upper()}</span>
                        <b>{self._escape(f.check_type.upper())}</b>
                        {source_badges}
                        {status_badge}
                        — <code>{self._escape(f.field_name)}</code>
                    </label>
                    <span class="conf-tag">信頼度: {conf}</span>
                </div>
                <div class="fi-body">
                    <div class="fi-url">{self._escape(f.url)}</div>
                    <div class="fi-evidence">{self._escape(f.evidence)}</div>
                    <code class="fi-payload">{self._escape(f.payload)}</code>
                    {refs_html}
                    {ai_fix_html}
                </div>
            </div>"""

        diff_summary = ""
        if diff_result:
            diff_summary = f"""
            <div class="diff-bar">
                🆕 新規 {len(diff_result.new_findings)} / ✅ 修正済 {len(diff_result.fixed_findings)} / 🔄 継続 {len(diff_result.persistent_findings)}
            </div>"""
        observability_html = self._build_observability_html(observability or {})
        coverage_html = self._build_coverage_html(coverage or {})

        return f"""<!DOCTYPE html>
<html lang="ja"><head><meta charset="UTF-8">
<title>Developer Report — {self._escape(target)}</title>
<style>
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f7f8fa;color:#1a202c;margin:0}}
.hdr{{background:#1a202c;color:#fff;padding:32px}} .hdr h1{{font-size:1.6rem;font-weight:700}}
.hdr .sub{{color:#a0aec0;font-size:.85rem;margin-top:4px}}
.container{{max-width:960px;margin:0 auto;padding:24px}}
.finding-item{{background:#fff;border-radius:8px;margin-bottom:12px;box-shadow:0 1px 2px rgba(0,0,0,.08);overflow:hidden}}
.finding-item-agent{{box-shadow:0 0 0 2px rgba(107,70,193,.16)}}
.finding-item-agent .fi-header{{background:#faf5ff}}
.fi-header{{padding:12px 16px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;background:#f8fafc}}
.fi-header label{{display:flex;align-items:center;gap:8px;cursor:pointer;flex:1}}
.fi-body{{padding:12px 16px;display:none}}
.fi-check:checked ~ label + * + .fi-body, input:checked ~ .fi-body {{ display:block }}
.finding-item:has(.fi-check:checked) .fi-body{{display:block}}
.sev-tag{{color:#fff;padding:2px 8px;border-radius:12px;font-size:.72rem;font-weight:700}}
.conf-tag{{font-size:.75rem;color:#718096;margin-left:auto}}
.fi-url{{font-size:.82rem;color:#718096;font-family:monospace;word-break:break-all;margin-bottom:6px}}
.fi-evidence{{background:#fff8f0;border:1px solid #fbd38d;border-radius:4px;padding:8px;font-size:.85rem;margin-bottom:6px}}
.fi-payload{{display:block;background:#1a202c;color:#68d391;padding:8px;border-radius:4px;font-size:.8rem;word-break:break-all;margin-bottom:6px;white-space:pre-wrap}}
.fix-box{{background:#f0fff4;border:1px solid #9ae6b4;border-radius:4px;padding:10px;font-size:.85rem;margin-top:6px}}
.refs{{font-size:.75rem;color:#4a5568;margin-top:4px}}
.new-badge{{background:#276749;color:#f0fff4;padding:2px 6px;border-radius:8px;font-size:.7rem;font-weight:700}}
.fixed-badge{{background:#2b6cb0;color:#ebf8ff;padding:2px 6px;border-radius:8px;font-size:.7rem;font-weight:700}}
.badge-agent{{background:#6b46c1;color:#faf5ff;padding:2px 8px;border-radius:10px;font-size:.72rem;font-weight:700}}
.badge-agent-verified{{background:#276749;color:#f0fff4;padding:2px 8px;border-radius:10px;font-size:.72rem;font-weight:700}}
.diff-bar{{background:#ebf8ff;border:1px solid #bee3f8;border-radius:8px;padding:10px 16px;margin-bottom:16px;font-size:.9rem}}
.footer{{text-align:center;color:#a0aec0;font-size:.75rem;padding:20px}}
</style></head><body>
<div class="hdr">
  <h1>Developer Security Checklist</h1>
  <div class="sub">{self._escape(target)} &nbsp;|&nbsp; {scan_date} &nbsp;|&nbsp; {len(findings)} 件の検出</div>
</div>
<div class="container">
  {diff_summary}
  {observability_html}
  {coverage_html}
  <p style="font-size:.85rem;color:#4a5568;margin-bottom:12px">各項目をクリックして詳細を展開してください。チェックボックスで修正完了を記録できます。</p>
  {items_html if items_html else '<p style="color:#38a169;font-weight:600">✓ 検出された脆弱性はありません。</p>'}
</div>
<div class="footer">WScan Security Report &mdash; Developer Checklist</div>
<script>
document.querySelectorAll('.finding-item').forEach(function(item) {{
    item.querySelector('.fi-header').addEventListener('click', function(e) {{
        if (e.target.classList.contains('fi-check')) return;
        var body = item.querySelector('.fi-body');
        body.style.display = body.style.display === 'block' ? 'none' : 'block';
    }});
}});
</script>
</body></html>"""
