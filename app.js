'use strict';
/* FinDeuda Cartera — app privada. Los datos viven solo en su hoja de Google;
   en el celular solo se guarda, cifrado con su PIN, el acceso al script. */
(() => {
  const VAULT = 'fd_vault', FAILS = 'fd_fallos', VERSION = '1.0';
  const ITER = 600000, PIN_LEN = 6, MAX_PIN_FAILS = 5;
  const LOCK_BG_MS = 60 * 1000, IDLE_MS = 5 * 60 * 1000, DIAS_MORA = 45;
  const root = document.getElementById('root');

  let S = null;            // sesión en memoria: {url, token, nombre}
  let D = null;            // datos de la hoja (solo en memoria)
  let ui = { tab: 'inicio', filtro: 'todos', q: '', rango: 'mes', desde: '', hasta: '' };
  let gate = null;         // estado de pantallas de PIN / vinculación
  let F = null;            // estado del formulario abierto
  let sheetBack = null;    // a qué volver al cerrar un formulario
  let lastAct = Date.now(), hiddenAt = 0;

  /* ---------------- utilidades ---------------- */
  const $ = s => document.querySelector(s);
  const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const COP = new Intl.NumberFormat('es-CO', { style: 'currency', currency: 'COP', maximumFractionDigits: 0 });
  const money = n => COP.format(Math.round(Number(n) || 0)).replace(/\s/g, ' ');
  const dots = n => String(Math.round(Number(n) || 0)).replace(/\B(?=(\d{3})+(?!\d))/g, '.');
  const digits = s => String(s ?? '').replace(/\D/g, '');
  const MES = ['ene', 'feb', 'mar', 'abr', 'may', 'jun', 'jul', 'ago', 'sep', 'oct', 'nov', 'dic'];
  const fdate = s => { if (!s) return 'Sin fecha'; const [y, m, d] = s.split('-').map(Number); return `${d} ${MES[m - 1]} ${y}`; };
  const dnum = s => { const [y, m, d] = s.split('-').map(Number); return Date.UTC(y, m - 1, d) / 864e5; };
  const dstr = n => new Date(n * 864e5).toISOString().slice(0, 10);
  const localToday = () => { const t = new Date(); return `${t.getFullYear()}-${String(t.getMonth() + 1).padStart(2, '0')}-${String(t.getDate()).padStart(2, '0')}`; };
  const hoy = () => localToday();
  const initials = n => String(n).split(/\s+/).filter(Boolean).slice(0, 2).map(w => w[0]).join('');
  const pct = (a, b) => b > 0 ? Math.max(0, Math.min(100, a / b * 100)) : 0;

  function toast(msg) {
    const t = $('#toast'); t.textContent = msg; t.classList.add('show');
    clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove('show'), 2600);
  }
  function loading(on) {
    let l = $('#loader');
    if (on && !l) { l = document.createElement('div'); l.id = 'loader'; l.className = 'loader'; l.innerHTML = '<div class="spin"></div>'; document.body.appendChild(l); }
    if (!on && l) l.remove();
  }

  /* ---------------- cifrado (PBKDF2 + AES-GCM) ---------------- */
  const te = new TextEncoder(), td = new TextDecoder();
  const b64 = u8 => btoa(String.fromCharCode(...u8));
  const ub64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  async function deriveKey(pin, salt, it) {
    const base = await crypto.subtle.importKey('raw', te.encode(pin), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: it, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function seal(pin, obj) {
    const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
    const k = await deriveKey(pin, salt, ITER);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, te.encode(JSON.stringify(obj))));
    localStorage.setItem(VAULT, JSON.stringify({ v: 1, it: ITER, salt: b64(salt), iv: b64(iv), ct: b64(ct) }));
  }
  async function unseal(pin) {
    const v = JSON.parse(localStorage.getItem(VAULT));
    const k = await deriveKey(pin, ub64(v.salt), v.it);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ub64(v.iv) }, k, ub64(v.ct));
    return JSON.parse(td.decode(pt));
  }
  function wipe() { localStorage.removeItem(VAULT); localStorage.removeItem(FAILS); S = null; D = null; }

  /* ---------------- API ---------------- */
  async function api(accion, datos, extra) {
    const ctl = new AbortController(); const to = setTimeout(() => ctl.abort(), 45000);
    const url = (extra && extra.url) || S.url;
    let j;
    try {
      const r = await fetch(url, {
        method: 'POST', headers: { 'Content-Type': 'text/plain;charset=utf-8' },
        body: JSON.stringify(Object.assign({ token: S && S.token, accion, datos }, extra && extra.body)),
        redirect: 'follow', cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', signal: ctl.signal
      });
      j = await r.json();
    } catch (e) {
      j = { ok: false, error: e.name === 'AbortError' ? 'La hoja tardó demasiado en responder.' : 'Sin conexión con la hoja. Revise el internet.' };
    } finally { clearTimeout(to); }
    if (j && j.sinSesion) { wipe(); startSetup('Este dispositivo ya no está vinculado. Vincúlelo de nuevo.'); throw new Error('sin sesión'); }
    return j;
  }

  /* ---------------- datos derivados ---------------- */
  function compute() {
    const byId = new Map();
    D.clientes.forEach(c => { c.pagos = []; c.coms = []; c.final = /^finalizado$/i.test(c.estado); byId.set(c.id, c); });
    D.pagos.forEach(p => { const c = byId.get(p.id); if (c) c.pagos.push(p); });
    D.comisiones.forEach(m => { const c = byId.get(m.id); if (c) c.coms.push(m); });
    const t = dnum(D.hoy || hoy());
    D.clientes.forEach(c => {
      const fechas = c.pagos.map(p => p.fecha).filter(Boolean).sort();
      c.ultimo = fechas[fechas.length - 1] || '';
      const base = c.ultimo || c.inicio;
      c.limite = base ? dstr(dnum(base) + DIAS_MORA) : '';
      c.diasMora = c.limite ? t - dnum(c.limite) : 0;
      c.mora = !c.final && c.pendiente > 0 && !!c.limite && c.diasMora > 0;
      c.radicar = String(c.radEstado).toUpperCase() === 'RADICAR';
    });
    D.byId = byId;
  }
  function estadoBadge(c) {
    if (c.final) return '<span class="badge b-gray">Finalizado</span>';
    if (c.mora) return `<span class="badge b-red">En mora · ${c.diasMora} d</span>`;
    return '<span class="badge b-green">Al día</span>';
  }

  /* ---------------- iconos ---------------- */
  const I = {
    home: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 3 2 11.5h3V21h5.5v-6h3v6H19v-9.5h3z"/></svg>',
    users: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8m7 0a3 3 0 1 0 0-6 3 3 0 0 0 0 6M9 13c-3.3 0-7 1.7-7 4.5V20h14v-2.5C16 14.7 12.3 13 9 13m7.4.1c1.6.8 2.6 2.1 2.6 4.4V20h3v-2.5c0-2.6-3-4.1-5.6-4.4"/></svg>',
    cash: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M2 6h20v12H2zm2 2v8h16V8zm8 1.5a2.5 2.5 0 1 1 0 5 2.5 2.5 0 0 1 0-5M5 9h2v2H5zm12 4h2v2h-2z"/></svg>',
    gear: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="m19.4 13 .1-1-.1-1 2.1-1.6-2-3.5-2.5 1a7 7 0 0 0-1.7-1L15 3h-4l-.4 2.7a7 7 0 0 0-1.7 1l-2.5-1-2 3.5L6.6 11l-.1 1 .1 1-2.1 1.6 2 3.5 2.5-1c.5.4 1.1.7 1.7 1L11 21h4l.4-2.7c.6-.3 1.2-.6 1.7-1l2.5 1 2-3.5zM13 15.5a3.5 3.5 0 1 1 0-7 3.5 3.5 0 0 1 0 7" transform="translate(-1)"/></svg>',
    plus: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>',
    reload: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M20 12a8 8 0 1 1-2.3-5.7M20 4v5h-5"/></svg>',
    lock: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M17 9V7A5 5 0 0 0 7 7v2H5v12h14V9zm-8 0V7a3 3 0 1 1 6 0v2z"/></svg>'
  };
  const LOGO = 'icon-180.png';

  /* ================= PANTALLAS DE ACCESO ================= */
  function startSetup(msg) {
    gate = { modo: 'setup', msg: msg || '', url: '', codigo: '', nombre: /iPad/.test(navigator.userAgent) ? 'iPad' : 'iPhone' };
    renderSetup();
  }
  function renderSetup() {
    root.innerHTML = `<div class="gate">
      <img class="logo" src="${LOGO}" alt="">
      <h1>Vincular este dispositivo</h1>
      <p class="sub">Genere un código en Apps Script con <b>appVincularDispositivo</b> y escríbalo aquí.</p>
      ${gate.msg ? `<p class="pinmsg" style="margin-top:12px">${esc(gate.msg)}</p>` : ''}
      <div class="setup">
        <label>URL del script (termina en /exec)</label>
        <input id="su" type="url" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="https://script.google.com/macros/s/…/exec" value="${esc(gate.url)}">
        <label>Código de vinculación</label>
        <input id="sc" autocomplete="one-time-code" autocapitalize="characters" spellcheck="false" placeholder="XXXX-XXXX" maxlength="9" value="${esc(gate.codigo)}">
        <label>Nombre de este dispositivo</label>
        <input id="sn" autocomplete="off" maxlength="30" value="${esc(gate.nombre)}">
        <p class="hint">El código sirve una sola vez y vence en 10 minutos.</p>
        <button class="btn" data-act="setupNext">Continuar</button>
      </div></div>`;
  }
  function setupNext() {
    const url = $('#su').value.trim(), codigo = $('#sc').value.trim(), nombre = $('#sn').value.trim();
    Object.assign(gate, { url, codigo, nombre });
    if (!/^https:\/\/script\.google\.com\/macros\/s\/[\w-]+\/exec$/.test(url)) { gate.msg = 'La URL no parece la de un script de Google (debe terminar en /exec).'; return renderSetup(); }
    if (digits(codigo).length + codigo.replace(/[^A-Za-z]/g, '').length < 8) { gate.msg = 'El código tiene 8 caracteres.'; return renderSetup(); }
    gate.modo = 'crear'; gate.pin = ''; gate.msg = ''; renderPin();
  }

  function renderPin() {
    const t = { abrir: ['FinDeuda', 'Ingrese su PIN'], crear: ['Cree un PIN', `${PIN_LEN} dígitos para abrir la app`], confirmar: ['Confirme el PIN', 'Escríbalo otra vez'],
      viejo: ['Cambiar PIN', 'Escriba su PIN actual'], nuevo: ['PIN nuevo', `${PIN_LEN} dígitos`], nuevo2: ['Confirme el PIN nuevo', 'Escríbalo otra vez'] }[gate.modo];
    const dotsHtml = Array.from({ length: PIN_LEN }, (_, i) => `<i class="${i < gate.pin.length ? 'on' : ''}"></i>`).join('');
    const keys = [1, 2, 3, 4, 5, 6, 7, 8, 9].map(n => `<button data-act="pk" data-k="${n}">${n}</button>`).join('');
    const izq = gate.modo === 'abrir' ? '<button class="txt" data-act="olvide">Olvidé</button>'
      : ['viejo', 'nuevo', 'nuevo2'].includes(gate.modo) ? '<button class="txt" data-act="pinCancel">Cancelar</button>' : '<span></span>';
    root.innerHTML = `<div class="gate">
      <img class="logo" src="${LOGO}" alt="">
      <h1>${t[0]}</h1><p class="sub">${t[1]}</p>
      <div class="dots${gate.shake ? ' shake' : ''}">${dotsHtml}</div>
      <p class="pinmsg">${esc(gate.msg || '')}</p>
      ${gate.busy ? '<div class="spin"></div>' : `<div class="pad">${keys}${izq}<button data-act="pk" data-k="0">0</button><button class="txt" data-act="pk" data-k="del">Borrar</button></div>`}
    </div>`;
    gate.shake = false;
  }
  function pinFail(msg) { gate.pin = ''; gate.msg = msg; gate.shake = true; gate.busy = false; renderPin(); if (navigator.vibrate) navigator.vibrate(120); }

  async function pinKey(k) {
    if (gate.busy) return;
    if (k === 'del') { gate.pin = gate.pin.slice(0, -1); return renderPin(); }
    if (gate.pin.length >= PIN_LEN) return;
    gate.pin += k; renderPin();
    if (gate.pin.length < PIN_LEN) return;
    const pin = gate.pin;

    if (gate.modo === 'abrir' || gate.modo === 'viejo') {
      gate.busy = true; renderPin();
      try {
        const obj = await unseal(pin);
        localStorage.removeItem(FAILS);
        if (gate.modo === 'viejo') { gate = Object.assign(gate, { modo: 'nuevo', pin: '', msg: '', busy: false, obj }); return renderPin(); }
        S = obj; gate = null; startApp();
      } catch (e) {
        const n = Number(localStorage.getItem(FAILS) || 0) + 1;
        if (n >= MAX_PIN_FAILS) { wipe(); return startSetup('Demasiados intentos. Por seguridad se borró el acceso de este dispositivo.'); }
        localStorage.setItem(FAILS, String(n));
        pinFail(`PIN incorrecto. Le quedan ${MAX_PIN_FAILS - n} intento(s).`);
      }
      return;
    }
    if (gate.modo === 'crear' || gate.modo === 'nuevo') {
      if (/^(\d)\1+$/.test(pin) || '0123456789'.includes(pin) || '9876543210'.includes(pin)) return pinFail('Ese PIN es muy fácil de adivinar. Use otro.');
      gate.primero = pin; gate.pin = ''; gate.msg = ''; gate.modo = gate.modo === 'crear' ? 'confirmar' : 'nuevo2'; return renderPin();
    }
    if (gate.modo === 'confirmar' || gate.modo === 'nuevo2') {
      if (pin !== gate.primero) { gate.modo = gate.modo === 'confirmar' ? 'crear' : 'nuevo'; return pinFail('No coinciden. Empiece de nuevo.'); }
      gate.busy = true; renderPin();
      if (gate.modo === 'nuevo2') {
        await seal(pin, gate.obj); S = gate.obj; gate = null; toast('PIN cambiado'); return startApp();
      }
      // vincular con el script
      S = { url: gate.url };
      const r = await api('vincular', null, { url: gate.url, body: { codigo: gate.codigo, nombre: gate.nombre } }).catch(() => null);
      if (!r || !r.ok) { S = null; gate.modo = 'setup'; gate.msg = (r && r.error) || 'No se pudo vincular.'; gate.busy = false; return renderSetup(); }
      S = { url: gate.url, token: r.token, nombre: gate.nombre };
      await seal(pin, S);
      gate = null; toast('Dispositivo vinculado'); startApp();
    }
  }

  function lock() {
    S = null; D = null; F = null;
    closeSheet(true);
    if (localStorage.getItem(VAULT)) { gate = { modo: 'abrir', pin: '', msg: '' }; renderPin(); }
    else startSetup();
  }

  /* ================= APP ================= */
  async function startApp() {
    renderShell(); await load();
  }
  async function load(silent) {
    if (!silent) loading(true);
    try {
      const r = await api('datos');
      if (!r.ok) { toast(r.error || 'No se pudieron leer los datos'); return; }
      D = r; compute(); D.cargado = new Date();
      renderShell();
    } catch (e) { /* sin sesión: ya se manejó */ } finally { loading(false); }
  }

  const TABS = [['inicio', 'Inicio', I.home], ['clientes', 'Clientes', I.users], ['pagos', 'Pagos', I.cash], ['ajustes', 'Ajustes', I.gear]];
  function renderShell() {
    if (!S) return;
    const title = { inicio: 'Cartera', clientes: 'Clientes', pagos: 'Pagos', ajustes: 'Ajustes' }[ui.tab];
    const body = !D ? '<div class="empty">Cargando…</div>' : ({ inicio: vInicio, clientes: vClientes, pagos: vPagos, ajustes: vAjustes }[ui.tab])();
    const scroll = window.scrollY;
    root.innerHTML = `
      <header class="top"><h1>${title}</h1><div class="acts">
        <button class="ibtn" data-act="reload" aria-label="Recargar">${I.reload}</button>
        <button class="ibtn" data-act="lock" aria-label="Bloquear">${I.lock}</button></div></header>
      <main id="main">${body}</main>
      ${ui.tab !== 'ajustes' ? `<button class="fab" data-act="nuevo" aria-label="Agregar">${I.plus}</button>` : ''}
      <nav class="tabs">${TABS.map(([k, l, ic]) => `<button class="${ui.tab === k ? 'on' : ''}" data-act="tab" data-k="${k}">${ic}<span>${l}</span></button>`).join('')}</nav>
      <div id="bd" class="backdrop hidden" data-act="closeSheet"></div><div id="sheet" class="sheet hidden"></div>`;
    window.scrollTo(0, scroll);
  }
  function rerenderMain() {
    const m = $('#main'); if (!m || !D) return;
    m.innerHTML = ({ inicio: vInicio, clientes: vClientes, pagos: vPagos, ajustes: vAjustes }[ui.tab])();
  }

  function clienteItem(c, right) {
    return `<button class="item" data-act="cliente" data-id="${esc(c.id)}">
      <div class="av">${esc(initials(c.nombre))}</div>
      <div class="mid"><div class="t">${esc(c.nombre)}</div><div class="d">${esc(c.id)} · ${esc(c.tipo || '—')}</div>
        <div class="bar"><i style="width:${pct(c.cancelado, c.contrato).toFixed(1)}%"></i></div></div>
      <div class="r">${right || `<div class="v">${money(c.pendiente)}</div>${estadoBadge(c)}`}</div></button>`;
  }
  function pagoItem(p) {
    return `<button class="item" data-act="cliente" data-id="${esc(p.id)}">
      <div class="av" style="background:var(--green)">$</div>
      <div class="mid"><div class="t">${esc((D.byId.get(p.id) || {}).nombre || p.nombre || p.id)}</div><div class="d">${fdate(p.fecha)}</div></div>
      <div class="r"><div class="v">${money(p.valor)}</div></div></button>`;
  }
  const sum = (a, f) => a.reduce((s, x) => s + (Number(f(x)) || 0), 0);
  function sortPagos(a) { return a.slice().sort((x, y) => (y.fecha || '').localeCompare(x.fecha || '') || y.fila - x.fila); }

  function vInicio() {
    const C = D.clientes, act = C.filter(c => !c.final);
    const mes = (D.hoy || hoy()).slice(0, 7);
    const pm = D.pagos.filter(p => (p.fecha || '').slice(0, 7) === mes);
    const mora = act.filter(c => c.mora).sort((a, b) => b.diasMora - a.diasMora);
    const rad = act.filter(c => c.radicar);
    const costos = sum(C, c => c.comision) + sum(C, c => c.descuento) + sum(C, c => c.radicacion);
    const ult = sortPagos(D.pagos.filter(p => p.fecha)).slice(0, 6);
    return `
      <div class="card hero"><div class="lbl">Total por cobrar</div><div class="big">${money(sum(C, c => c.pendiente))}</div>
        <div class="row"><span>Recibido ${money(sum(C, c => c.cancelado))}</span><span>Contratos ${money(sum(C, c => c.contrato))}</span></div></div>
      <div class="grid2">
        <div class="card kpi"><div class="lbl">Recaudado este mes</div><div class="val">${money(sum(pm, p => p.valor))}</div><div class="s">${pm.length} pago(s)</div></div>
        <button class="card kpi" style="text-align:left" data-act="filtro" data-k="activos"><div class="lbl">Clientes activos</div><div class="val">${act.length}</div><div class="s">de ${C.length} en total</div></button>
        <button class="card kpi" style="text-align:left" data-act="filtro" data-k="mora"><div class="lbl">En mora (+${DIAS_MORA} días)</div><div class="val" style="color:var(--red)">${mora.length}</div><div class="s">${money(sum(mora, c => c.pendiente))}</div></button>
        <button class="card kpi" style="text-align:left" data-act="filtro" data-k="radicar"><div class="lbl">Listos para radicar</div><div class="val" style="color:var(--purple)">${rad.length}</div><div class="s">≥ 50% de insolvencia</div></button>
        <div class="card kpi"><div class="lbl">Netos activos</div><div class="val">${money(sum(act, c => c.neto))}</div></div>
        <div class="card kpi"><div class="lbl">Costos (rad., com., desc.)</div><div class="val">${money(costos)}</div></div>
      </div>
      ${mora.length ? `<h2 class="sec">En mora <a data-act="filtro" data-k="mora">Ver todos</a></h2><div class="list">${mora.slice(0, 5).map(c => clienteItem(c)).join('')}</div>` : ''}
      ${rad.length ? `<h2 class="sec">Para radicar <a data-act="filtro" data-k="radicar">Ver todos</a></h2><div class="list">${rad.slice(0, 5).map(c => clienteItem(c, `<div class="v">${((c.radPct || 0) * 100).toFixed(0)}%</div><span class="badge b-purple">Radicar</span>`)).join('')}</div>` : ''}
      <h2 class="sec">Últimos pagos <a data-act="tab" data-k="pagos">Ver todos</a></h2>
      <div class="list">${ult.map(pagoItem).join('') || '<div class="empty">Sin pagos</div>'}</div>
      <p class="sync">Datos de su hoja · ${D.cargado ? D.cargado.toLocaleTimeString('es-CO', { hour: '2-digit', minute: '2-digit' }) : ''}</p>`;
  }

  function vClientes() {
    const C = D.clientes;
    const F_ = { todos: () => true, activos: c => !c.final, mora: c => c.mora, radicar: c => !c.final && c.radicar, final: c => c.final };
    const q = ui.q.trim().toLowerCase(), qd = digits(q);
    let L = C.filter(F_[ui.filtro]).filter(c => !q || c.nombre.toLowerCase().includes(q) || (qd && digits(c.id).includes(qd)));
    L.sort(ui.filtro === 'mora' ? (a, b) => b.diasMora - a.diasMora : (a, b) => a.nombre.localeCompare(b.nombre));
    const chip = (k, l) => `<button class="chip ${ui.filtro === k ? 'on' : ''}" data-act="chip" data-k="${k}">${l} ${C.filter(F_[k]).length}</button>`;
    return `<input class="search" id="q" data-in="q" type="search" placeholder="Buscar por nombre o cédula" value="${esc(ui.q)}" autocomplete="off">
      <div class="chips">${chip('todos', 'Todos')}${chip('activos', 'Activos')}${chip('mora', 'En mora')}${chip('radicar', 'Radicar')}${chip('final', 'Finalizados')}</div>
      <div id="clist">${listaClientes(L)}</div>`;
  }
  function listaClientes(L) {
    return L.length ? `<div class="list">${L.map(c => clienteItem(c)).join('')}</div><p class="sync">${L.length} cliente(s) · pendiente ${money(sum(L, c => c.pendiente))}</p>` : '<div class="empty">No hay clientes con ese filtro</div>';
  }

  function rangoFechas() {
    const t = D.hoy || hoy(), [y, m] = t.split('-').map(Number);
    if (ui.rango === 'mes') return [`${t.slice(0, 7)}-01`, t];
    if (ui.rango === 'ant') { const py = m === 1 ? y - 1 : y, pm = m === 1 ? 12 : m - 1; const last = new Date(Date.UTC(py, pm, 0)).getUTCDate(); const mm = String(pm).padStart(2, '0'); return [`${py}-${mm}-01`, `${py}-${mm}-${last}`]; }
    if (ui.rango === '30') return [dstr(dnum(t) - 29), t];
    if (ui.rango === 'todo') return ['', ''];
    return [ui.desde, ui.hasta];
  }
  function vPagos() {
    const [de, ha] = rangoFechas();
    const L = sortPagos(D.pagos.filter(p => ui.rango === 'todo' || (p.fecha && (!de || p.fecha >= de) && (!ha || p.fecha <= ha))));
    const chip = (k, l) => `<button class="chip ${ui.rango === k ? 'on' : ''}" data-act="rango" data-k="${k}">${l}</button>`;
    return `<div class="chips">${chip('mes', 'Este mes')}${chip('ant', 'Mes anterior')}${chip('30', 'Últimos 30 días')}${chip('todo', 'Todo')}${chip('custom', 'Elegir fechas')}</div>
      ${ui.rango === 'custom' ? `<div class="form"><div class="field"><label>Desde</label><input type="date" data-in="desde" value="${esc(ui.desde)}"></div><div class="field"><label>Hasta</label><input type="date" data-in="hasta" value="${esc(ui.hasta)}"></div></div>` : ''}
      <div class="card hero"><div class="lbl">${ui.rango === 'todo' ? 'Todos los pagos' : `${fdate(de)} – ${fdate(ha)}`}</div><div class="big">${money(sum(L, p => p.valor))}</div><div class="row"><span>${L.length} pago(s)</span></div></div>
      <div class="list">${L.map(pagoItem).join('') || '<div class="empty">No hay pagos en ese rango</div>'}</div>`;
  }

  function vAjustes() {
    return `<div class="list">
        <div class="kv"><span>Dispositivo</span><span>${esc(S.nombre || '—')}</span></div>
        <div class="kv"><span>Clientes / pagos</span><span>${D.clientes.length} / ${D.pagos.length}</span></div>
        <div class="kv"><span>Versión</span><span>${VERSION}</span></div></div>
      <p class="foot">Sus datos se leen de su hoja de Google cada vez que abre la app y no se guardan en el celular. La app se bloquea sola a los 5 minutos sin uso o 1 minuto en segundo plano.</p>
      <button class="btn sec" data-act="reload">Recargar datos</button>
      <button class="btn sec" data-act="cambiarPin">Cambiar PIN</button>
      <button class="btn sec" data-act="lock">Bloquear ahora</button>
      <div style="height:22px"></div>
      <button class="btn danger" data-act="desvincular">Desvincular este dispositivo</button>`;
  }

  /* ================= HOJAS MODALES ================= */
  function openSheet(html) {
    const sh = $('#sheet'), bd = $('#bd'); if (!sh) return;
    sh.innerHTML = '<div class="grab"></div>' + html;
    sh.classList.remove('hidden'); bd.classList.remove('hidden');
    requestAnimationFrame(() => { sh.classList.add('show'); bd.classList.add('show'); });
    document.body.style.overflow = 'hidden';
  }
  function closeSheet(now) {
    const sh = $('#sheet'), bd = $('#bd'); document.body.style.overflow = '';
    if (!sh) return;
    sh.classList.remove('show'); bd.classList.remove('show');
    const fin = () => { sh.classList.add('hidden'); bd.classList.add('hidden'); sh.innerHTML = ''; };
    now ? fin() : setTimeout(fin, 280);
    F = null;
  }
  const head = (t, right) => `<div class="sh-head"><button data-act="${sheetBack ? 'back' : 'closeSheet'}">${sheetBack ? '‹ Atrás' : 'Cerrar'}</button><h3>${esc(t)}</h3>${right ? `<button class="r" data-act="${right[1]}">${right[0]}</button>` : '<button></button>'}</div>`;

  /* ---- detalle de cliente ---- */
  function showCliente(id) {
    const c = D.byId.get(id); if (!c) return toast('Cliente no encontrado');
    sheetBack = null; F = null;
    const mov = c.pagos.map(p => ({ f: p.fecha, t: 'Pago', v: p.valor, p }))
      .concat(c.coms.map(m => ({ f: m.fecha, t: m.descuenta === 'Si' ? 'Descuento comisión' : 'Comisión (no descuenta)', v: m.valor })))
      .sort((a, b) => (b.f || '').localeCompare(a.f || ''));
    const kv = (k, v, neg) => `<div class="kv${neg ? ' neg' : ''}"><span>${k}</span><span>${v}</span></div>`;
    openSheet(head('Cliente') + `<div class="body">
      <div style="padding:4px 4px 12px"><div style="font-size:22px;font-weight:700">${esc(c.nombre)}</div>
        <div style="color:var(--sub);font-size:14px;margin-top:4px">CC ${esc(c.id)} · ${esc(c.tipo)} · inicio ${fdate(c.inicio)}</div>
        <div style="margin-top:6px">${estadoBadge(c)} ${c.radicar && !c.final ? '<span class="badge b-purple">Para radicar</span>' : ''}</div></div>
      <div class="card hero"><div class="lbl">Saldo pendiente</div><div class="big">${money(c.pendiente)}</div>
        <div class="bar" style="background:rgba(255,255,255,.2)"><i style="width:${pct(c.cancelado, c.contrato).toFixed(1)}%"></i></div>
        <div class="row" style="margin-top:8px"><span>Cancelado ${money(c.cancelado)}</span><span>${pct(c.cancelado, c.contrato).toFixed(0)}%</span></div></div>
      <button class="btn" data-act="formPago" data-id="${esc(c.id)}">Registrar pago</button>
      <button class="btn sec" data-act="formComision" data-id="${esc(c.id)}">Agregar comisión</button>
      <h2 class="sec">Seguimiento</h2><div class="list">
        ${kv('Último pago', fdate(c.ultimo))}${kv(`Fecha límite (+${DIAS_MORA} días)`, c.limite ? fdate(c.limite) : '—')}
        ${kv('Estado', c.final ? 'Finalizado' : c.mora ? `En mora hace ${c.diasMora} día(s)` : 'Al día')}
        ${kv('Radicación', `${c.radPct == null ? '—' : ((c.radPct) * 100).toFixed(0) + '%'} · ${esc(c.radEstado || '—')}`)}</div>
      <h2 class="sec">Contrato</h2><div class="list">
        ${kv('Valor de contrato', money(c.contrato))}${kv('Alimentos', money(c.alimentos))}${kv('Insolvencia', money(c.insolvencia))}
        ${kv('Comisión' + (c.tieneComision ? ` (${esc(c.tieneComision)})` : ''), money(c.comision), 1)}${kv('Descuento a contrato', money(c.descuento), 1)}
        ${kv('Radicación', money(c.radicacion), 1)}${kv('Gustavo (10%)', money(c.gustavo), 1)}
        ${kv('Contrato neto', money(c.neto))}${kv('Ganancias netas', money(c.ganancia))}</div>
      <h2 class="sec">Historial (${mov.length})</h2>
      <div class="list">${mov.map(m => `<div class="item"><div class="mid"><div class="t">${m.t}</div><div class="d">${fdate(m.f)}</div></div>
        <div class="r"><div class="v">${money(m.v)}</div></div>${m.p ? `<button class="mini" data-act="anular" data-fila="${m.p.fila}">Anular</button>` : ''}</div>`).join('') || '<div class="empty">Sin movimientos</div>'}</div>
    </div>`);
  }

  async function anular(fila) {
    const p = D.pagos.find(x => x.fila === Number(fila)); if (!p) return;
    if (!confirm(`¿Anular el pago de ${money(p.valor)} del ${fdate(p.fecha)}?\nSe borra de la hoja Pagos (fila ${p.fila}).`)) return;
    loading(true);
    try {
      const r = await api('anularPago', { fila: p.fila, id: p.id, fecha: p.fecha, valor: p.valor });
      if (!r.ok) return toast(r.error);
      toast('Pago anulado'); const id = p.id; await load(true); showCliente(id);
    } catch (e) { } finally { loading(false); }
  }

  /* ---- selector de cliente ---- */
  function pickerHtml() {
    const c = F.id && D.byId.get(F.id);
    if (c) return `<div class="form"><div class="field" data-act="unpick"><label>Cliente</label><div class="ro strong" style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(c.nombre)}</div><span style="color:var(--blue);font-size:14px">Cambiar</span></div></div>`;
    return `<div class="form"><div class="field"><label>Cliente</label><input id="pq" data-in="pq" placeholder="Nombre o cédula" autocomplete="off" value="${esc(F.pq || '')}" style="text-align:left"></div></div><div id="sugs">${sugsHtml()}</div>`;
  }
  function sugsHtml() {
    const q = (F.pq || '').trim().toLowerCase(), qd = digits(q);
    let L = D.clientes.filter(c => !q || c.nombre.toLowerCase().includes(q) || (qd && digits(c.id).includes(qd)));
    L.sort((a, b) => (a.final - b.final) || a.nombre.localeCompare(b.nombre));
    L = L.slice(0, 8);
    return L.length ? `<div class="sugs">${L.map(c => `<button class="item" data-act="pick" data-id="${esc(c.id)}"><div class="mid"><div class="t">${esc(c.nombre)}</div><div class="d">${esc(c.id)}</div></div><div class="r"><div class="v" style="font-size:13px">${money(c.pendiente)}</div></div></button>`).join('')}</div>` : '<div class="empty">Sin resultados</div>';
  }
  const moneyInput = (key, val, ph) => `<input data-in="${key}" inputmode="numeric" placeholder="${ph || '$ 0'}" value="${val ? '$ ' + dots(val) : ''}" autocomplete="off">`;

  /* ---- registrar pago ---- */
  function formPago(id, back) {
    sheetBack = back || null;
    F = { tipo: 'pago', id: id || '', fecha: D.hoy || hoy(), valor: 0, pq: '' };
    openSheet(head('Registrar pago', ['Guardar', 'savePago']) + `<div class="body">
      <div id="picker">${pickerHtml()}</div>
      <div class="form">
        <div class="field"><label>Fecha de pago</label><input type="date" data-in="fecha" value="${F.fecha}"></div>
        <div class="field"><label>Valor</label>${moneyInput('valor', 0)}</div></div>
      <div id="pv">${pvPago()}</div>
      <button class="btn" data-act="savePago">Guardar pago</button></div>`);
    if (!F.id) setTimeout(() => $('#pq') && $('#pq').focus(), 350);
  }
  function pvPago() {
    const c = F.id && D.byId.get(F.id); if (!c) return '';
    const w = [];
    if (F.valor > c.pendiente) w.push('El pago es mayor que el saldo pendiente.');
    if (c.pagos.some(p => p.fecha === F.fecha && p.valor === F.valor)) w.push('Ya hay un pago de este cliente con la misma fecha y valor.');
    if (c.final) w.push('Este cliente ya está finalizado.');
    return `${w.map(x => `<div class="warn">⚠ ${x}</div>`).join('')}<div class="list">
      <div class="kv"><span>Estado</span><span>${c.final ? 'Finalizado' : c.mora ? 'En mora' : 'Al día'}</span></div>
      <div class="kv"><span>Valor de contrato</span><span>${money(c.contrato)}</span></div>
      <div class="kv"><span>Cancelado hasta hoy</span><span>${money(c.cancelado)}</span></div>
      <div class="kv"><span>Saldo pendiente</span><span>${money(c.pendiente)}</span></div>
      <div class="kv"><span>Último pago</span><span>${fdate(c.ultimo)}</span></div>
      <div class="kv"><span><b>Saldo después del pago</b></span><span><b>${money(c.pendiente - F.valor)}</b></span></div></div>`;
  }
  async function savePago(forzar) {
    if (!F || F.busy) return;
    const c = F.id && D.byId.get(F.id);
    if (!c) return toast('Elija un cliente');
    if (!F.fecha) return toast('Elija la fecha');
    if (!(F.valor > 0)) return toast('Escriba el valor');
    F.busy = true; loading(true);
    try {
      const r = await api('pago', { id: c.id, fecha: F.fecha, valor: F.valor, forzar: !!forzar });
      if (r.confirmar) { loading(false); F.busy = false; if (confirm(r.error + '\n\n¿Guardar de todas formas?')) return savePago(true); return; }
      if (!r.ok) { toast(r.error); return; }
      toast(`Pago de ${money(F.valor)} guardado`);
      await load(true); showCliente(c.id);
    } catch (e) { } finally { if (F) F.busy = false; loading(false); }
  }

  /* ---- comisión ---- */
  function formComision(id, back) {
    sheetBack = back || null;
    F = { tipo: 'comision', id: id || '', fecha: D.hoy || hoy(), valor: 0, descuenta: 'Si', pq: '' };
    openSheet(head('Agregar comisión', ['Guardar', 'saveComision']) + `<div class="body">
      <div id="picker">${pickerHtml()}</div>
      <div class="form">
        <div class="field"><label>Valor</label>${moneyInput('valor', 0)}</div>
        <div class="field"><label>Fecha</label><input type="date" data-in="fecha" value="${F.fecha}"></div>
        <div class="field"><label>¿Descuenta?</label><div class="seg" id="segD">${segHtml('descuenta', [['Si', 'Sí'], ['No', 'No']], F.descuenta)}</div></div></div>
      <p class="foot">"Sí" la resta del contrato del cliente (columna Descuento a contrato).</p>
      <button class="btn" data-act="saveComision">Guardar comisión</button></div>`);
  }
  function segHtml(key, opts, val) { return opts.map(([v, l]) => `<button class="${v === val ? 'on' : ''}" data-act="seg" data-key="${key}" data-v="${esc(v)}">${l}</button>`).join(''); }
  async function saveComision() {
    if (!F || F.busy) return;
    const c = F.id && D.byId.get(F.id);
    if (!c) return toast('Elija un cliente');
    if (!(F.valor > 0)) return toast('Escriba el valor');
    F.busy = true; loading(true);
    try {
      const r = await api('comision', { id: c.id, valor: F.valor, descuenta: F.descuenta, fecha: F.fecha });
      if (!r.ok) return toast(r.error);
      toast('Comisión guardada'); await load(true); showCliente(c.id);
    } catch (e) { } finally { if (F) F.busy = false; loading(false); }
  }

  /* ---- nuevo cliente ---- */
  const TIPOS = [['Insolvencia', 'Insolvencia'], ['Alimentos', 'Alimentos'], ['Alimentos y Insolvencia', 'Ambos']];
  function calcCliente() {
    const p = D.parametros || { alimentos: 3000000, porcentaje: 0.1, tarifas: [] };
    const ali = F.tp.includes('Alimentos') ? p.alimentos : 0;
    const ins = F.tp.includes('Insolvencia') ? F.ins : 0;
    const contrato = ali + ins, deuda = ins ? ins / p.porcentaje : 0;
    let t = { tarifa: 0, cuotas: 0 };
    if (deuda) p.tarifas.forEach(x => { if (x.desde <= deuda - 0.001) t = x; });
    const rad = F.radManual ? F.rad : t.tarifa;
    const com = F.com !== 'Si' || !contrato ? 0 : contrato < 6e6 ? 2e5 : contrato < 1e7 ? 2.5e5 : 5e5;
    return { ali, ins, contrato, deuda, tarifa: t.tarifa, cuotas: t.cuotas, rad, com, gus: contrato * 0.1, neto: contrato - com - rad };
  }
  function formCliente() {
    sheetBack = null;
    F = { tipo: 'cliente', nombre: '', ced: '', inicio: D.hoy || hoy(), tp: 'Insolvencia', ins: 0, com: 'No', rad: 0, radManual: false };
    openSheet(head('Nuevo cliente', ['Guardar', 'saveCliente']) + `<div class="body">
      <div class="form">
        <div class="field"><label>Nombre</label><input data-in="nombre" autocapitalize="characters" autocomplete="off" placeholder="NOMBRE COMPLETO"></div>
        <div class="field"><label>Cédula</label><input data-in="ced" inputmode="numeric" autocomplete="off" placeholder="1.090.000.000"></div>
        <div class="field"><label>Fecha de inicio</label><input type="date" data-in="inicio" value="${F.inicio}"></div></div>
      <div class="form">
        <div class="field"><label>Proceso</label><div class="seg" id="segT">${segHtml('tp', TIPOS, F.tp)}</div></div>
        <div class="field" id="fIns"><label>Valor insolvencia</label>${moneyInput('ins', 0)}</div>
        <div class="field"><label>¿Comisión?</label><div class="seg" id="segC">${segHtml('com', [['Si', 'Sí'], ['No', 'No']], F.com)}</div></div>
        <div class="field"><label>Radicación</label><input data-in="rad" id="iRad" inputmode="numeric" autocomplete="off" placeholder="Según la tabla"></div></div>
      <p class="foot">La radicación se llena sola con la tabla de tarifas. Puede cambiarla si lo pactado es otro valor.</p>
      <div id="pv">${pvCliente()}</div>
      <button class="btn" data-act="saveCliente">Guardar cliente</button></div>`);
    syncRad();
  }
  function syncRad() { if (!F.radManual) { const k = calcCliente(); const i = $('#iRad'); if (i) i.value = k.tarifa ? '$ ' + dots(k.tarifa) : '$ 0'; } }
  function pvCliente() {
    const k = calcCliente(), w = [];
    const dg = digits(F.ced);
    if (dg && D.clientes.some(c => digits(c.id) === dg)) w.push('Esta identificación ya existe en Principal.');
    return `${w.map(x => `<div class="warn">⚠ ${x}</div>`).join('')}<h2 class="sec">Cálculo automático</h2><div class="list">
      <div class="kv"><span>Alimentos</span><span>${money(k.ali)}</span></div>
      <div class="kv"><span>Insolvencia</span><span>${money(k.ins)}</span></div>
      <div class="kv"><span><b>Valor de contrato</b></span><span><b>${money(k.contrato)}</b></span></div>
      <div class="kv"><span>Deuda del cliente</span><span>${money(k.deuda)}</span></div>
      <div class="kv"><span>Radicación (tabla)</span><span>${money(k.tarifa)}${k.cuotas ? ` · ${k.cuotas} cuota(s)` : ''}</span></div>
      <div class="kv neg"><span>Comisión</span><span>${money(k.com)}</span></div>
      <div class="kv neg"><span>Radicación usada</span><span>${money(k.rad)}</span></div>
      <div class="kv"><span>Gustavo (10%)</span><span>${money(k.gus)}</span></div>
      <div class="kv"><span><b>Contrato neto</b></span><span><b>${money(k.neto)}</b></span></div></div>`;
  }
  async function saveCliente() {
    if (!F || F.busy) return;
    const k = calcCliente(), dg = digits(F.ced);
    if (F.nombre.trim().length < 5) return toast('Escriba el nombre completo');
    if (dg.length < 5) return toast('Escriba la cédula');
    if (D.clientes.some(c => digits(c.id) === dg)) return toast('Esa cédula ya existe');
    if (F.tp.includes('Insolvencia') && !(F.ins > 0)) return toast('Escriba el valor de insolvencia');
    if (!confirm(`¿Guardar a ${F.nombre.trim().toUpperCase()} con contrato de ${money(k.contrato)}?`)) return;
    F.busy = true; loading(true);
    try {
      const r = await api('cliente', { nombre: F.nombre, id: dots(dg), inicio: F.inicio, tipo: F.tp, insolvencia: F.ins, tieneComision: F.com, radicacion: k.rad });
      if (!r.ok) return toast(r.error);
      toast('Cliente guardado'); await load(true); showCliente(dots(dg));
    } catch (e) { } finally { if (F) F.busy = false; loading(false); }
  }

  function menuNuevo() {
    sheetBack = null; F = null;
    openSheet(head('Agregar') + `<div class="body"><div class="list">
      <button class="item" data-act="formPago"><div class="av" style="background:var(--green)">$</div><div class="mid"><div class="t">Registrar pago</div><div class="d">Abono de un cliente</div></div></button>
      <button class="item" data-act="formCliente"><div class="av">+</div><div class="mid"><div class="t">Nuevo cliente</div><div class="d">Con cálculo de contrato y radicación</div></div></button>
      <button class="item" data-act="formComision"><div class="av" style="background:var(--orange)">%</div><div class="mid"><div class="t">Comisión</div><div class="d">Comisión de un cliente</div></div></button>
    </div></div>`);
  }

  /* ================= EVENTOS ================= */
  const ACT = {
    setupNext, pk: el => pinKey(el.dataset.k),
    olvide: () => { if (confirm('Para entrar sin PIN hay que vincular el dispositivo otra vez con un código nuevo. ¿Borrar el acceso de este dispositivo?')) { wipe(); startSetup(); } },
    pinCancel: () => { S = gate.obj || S; gate = null; startApp(); },
    tab: el => { ui.tab = el.dataset.k; closeSheet(true); renderShell(); window.scrollTo(0, 0); },
    filtro: el => { ui.tab = 'clientes'; ui.filtro = el.dataset.k; ui.q = ''; closeSheet(true); renderShell(); window.scrollTo(0, 0); },
    chip: el => { ui.filtro = el.dataset.k; rerenderMain(); },
    rango: el => { ui.rango = el.dataset.k; if (ui.rango === 'custom' && !ui.desde) { ui.desde = `${(D.hoy || hoy()).slice(0, 7)}-01`; ui.hasta = D.hoy || hoy(); } rerenderMain(); },
    reload: () => load(), lock,
    cliente: el => showCliente(el.dataset.id),
    closeSheet: () => closeSheet(), back: () => { const b = sheetBack; sheetBack = null; b ? showCliente(b) : closeSheet(); },
    nuevo: menuNuevo,
    formPago: el => { const id = el.dataset.id; formPago(id, id || null); },
    formComision: el => { const id = el.dataset.id; formComision(id, id || null); },
    formCliente, savePago: () => savePago(false), saveComision, saveCliente,
    pick: el => { F.id = el.dataset.id; $('#picker').innerHTML = pickerHtml(); const pv = $('#pv'); if (pv && F.tipo === 'pago') pv.innerHTML = pvPago(); },
    unpick: () => { F.id = ''; F.pq = ''; $('#picker').innerHTML = pickerHtml(); const pv = $('#pv'); if (pv) pv.innerHTML = ''; setTimeout(() => $('#pq') && $('#pq').focus(), 50); },
    seg: el => {
      F[el.dataset.key] = el.dataset.v;
      el.parentNode.querySelectorAll('button').forEach(b => b.classList.toggle('on', b === el));
      if (F.tipo === 'cliente') { $('#fIns').classList.toggle('hidden', F.tp === 'Alimentos'); syncRad(); $('#pv').innerHTML = pvCliente(); }
    },
    anular: el => anular(el.dataset.fila),
    cambiarPin: () => { gate = { modo: 'viejo', pin: '', msg: '', obj: S }; closeSheet(true); renderPin(); },
    desvincular: async () => {
      if (!confirm('¿Desvincular este dispositivo? Tendrá que generar un código nuevo para volver a entrar.')) return;
      loading(true);
      try { await api('desvincular'); } catch (e) { }
      loading(false); wipe(); startSetup('Dispositivo desvinculado.');
    }
  };
  document.addEventListener('click', e => {
    const el = e.target.closest('[data-act]'); if (!el) return;
    const f = ACT[el.dataset.act]; if (f) { e.preventDefault(); f(el); }
  });
  document.addEventListener('input', e => {
    const el = e.target, k = el.dataset && el.dataset.in; if (!k) return;
    if (k === 'q') { ui.q = el.value; const L = $('#clist'); if (L) { const v = vClientes(); const tmp = document.createElement('div'); tmp.innerHTML = v; L.innerHTML = tmp.querySelector('#clist').innerHTML; } return; }
    if (k === 'desde' || k === 'hasta') { ui[k] = el.value; rerenderMain(); return; }
    if (!F) return;
    if (k === 'pq') { F.pq = el.value; $('#sugs').innerHTML = sugsHtml(); return; }
    if (k === 'valor' || k === 'ins' || k === 'rad') {
      const n = Number(digits(el.value)) || 0; el.value = n ? '$ ' + dots(n) : '';
      if (k === 'rad') { F.rad = n; F.radManual = el.value !== ''; if (!F.radManual) syncRad(); } else F[k] = n;
      if (k === 'ins') syncRad();
    } else if (k === 'ced') {
      const dg = digits(el.value).slice(0, 12); el.value = dg ? dots(dg) : ''; F.ced = dg;
    } else F[k] = el.value;
    const pv = $('#pv');
    if (pv) pv.innerHTML = F.tipo === 'pago' ? pvPago() : F.tipo === 'cliente' ? pvCliente() : '';
  });

  /* ---- bloqueo automático y privacidad en el selector de apps ---- */
  ['touchstart', 'click', 'keydown', 'scroll'].forEach(ev => document.addEventListener(ev, () => { lastAct = Date.now(); }, { passive: true }));
  setInterval(() => { if (S && Date.now() - lastAct > IDLE_MS) lock(); }, 15000);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) { hiddenAt = Date.now(); root.style.visibility = 'hidden'; }
    else {
      root.style.visibility = '';
      if (S && Date.now() - hiddenAt > LOCK_BG_MS) lock();
      lastAct = Date.now();
    }
  });
  window.addEventListener('pagehide', () => { root.style.visibility = 'hidden'; });
  window.addEventListener('pageshow', () => { root.style.visibility = ''; });

  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => { });

  /* ---- inicio ---- */
  if (!window.crypto || !crypto.subtle) { root.innerHTML = '<div class="gate"><h1>Abra la app desde https</h1></div>'; return; }
  localStorage.getItem(VAULT) ? (gate = { modo: 'abrir', pin: '', msg: '' }, renderPin()) : startSetup();
})();
