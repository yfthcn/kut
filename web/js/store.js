// Ortak durum: sunucudan gelen en son durum + canlı akış (SSE), olmazsa yoklama.
import { api } from './util.js';

export const state = { status: null, policies: null, listeners: new Set() };
let es = null, poll = null, fails = 0;

function push(st) {
  state.status = st;
  for (const f of state.listeners) { try { f(st); } catch (e) { console.error(e); } }
}

export function onStatus(f) { state.listeners.add(f); return () => state.listeners.delete(f); }

export async function refresh() {
  const st = await api('GET', '/api/status');
  push(st);
  return st;
}

export async function loadPolicies() {
  state.policies = await api('GET', '/api/policies');
  return state.policies;
}

function startPolling() {
  if (poll) return;
  poll = setInterval(() => { if (!document.hidden) refresh().catch(() => {}); }, 5000);
}

export function startLive() {
  stopLive();
  if (typeof EventSource === 'undefined') { startPolling(); return; }
  const cur = new EventSource('/api/stream');
  es = cur;
  cur.addEventListener('status', (e) => { fails = 0; try { push(JSON.parse(e.data)); } catch { /* yoksay */ } });
  cur.addEventListener('logout', () => { location.reload(); });
  cur.onerror = () => {
    // HTTP hatasında (429/502) tarayıcı yeniden bağlanmaz (CLOSED): hemen yoklamaya dön.
    if (cur.readyState === EventSource.CLOSED || ++fails >= 3) { cur.close(); if (es === cur) es = null; startPolling(); }
  };
}

export function stopLive() {
  if (es) { es.close(); es = null; }
  if (poll) { clearInterval(poll); poll = null; }
  fails = 0;
}
