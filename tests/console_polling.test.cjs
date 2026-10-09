'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { runInNewContext } = require('node:vm');

// Only the browser surface used by console.js is supplied. Rendering stays real.
function browser() {
  const ids = new Map();
  const requests = [];
  const staleRenders = [];
  let poll;
  let active = 0;
  let maxActive = 0;
  const offline = 'offline:regression';
  const visible = () => ['attempts-list', 'events-list', 'alerts-list']
    .map(id => ids.get(id).textContent).join('\n');
  const observe = () => {
    if (!staleRenders.length && ids.get('domain-select')?.value === offline && visible().includes('LIVE_ONLY')) {
      staleRenders.push(visible());
    }
  };

  class Element {
    constructor(tag) {
      this.tag = tag;
      this.children = [];
      this.listeners = new Map();
      this._text = '';
      this._value = '';
    }
    get textContent() { return this._text + this.children.map(node => node.textContent).join(''); }
    set textContent(value) { this._text = String(value); this.children = []; observe(); }
    get value() { return this._value; }
    set value(value) {
      this._value = value;
      if (this.tag === 'select') this.children.forEach(node => { node.selected = node.value === value; });
    }
    append(...nodes) {
      this.children.push(...nodes);
      if (this.tag === 'select') {
        nodes.forEach(node => { if (node.selected || !this._value) this._value = node.value; });
      }
      observe();
    }
    replaceChildren(...nodes) {
      this._text = '';
      this.children = [];
      if (this.tag === 'select') this._value = '';
      this.append(...nodes);
    }
    addEventListener(name, listener) { this.listeners.set(name, listener); }
  }

  for (const id of ['console', 'domain-select', 'connection-warning', 'capture-title',
    'capture-error', 'last-packet', 'attempt-count', 'event-count', 'alert-count',
    'block-count', 'attempts-list', 'events-list', 'alerts-list', 'blocks-list']) {
    ids.set(id, new Element(id === 'domain-select' ? 'select' : 'div'));
  }
  ids.get('console').dataset = { csrfToken: 'test-only' };
  for (const value of ['live', offline]) {
    const option = new Element('option');
    option.value = value;
    ids.get('domain-select').append(option);
  }
  const context = {
    document: {
      getElementById: id => ids.get(id),
      createElement: tag => new Element(tag),
    },
    URLSearchParams,
    window: { setInterval(callback, delay) { assert.equal(delay, 2000); poll = callback; } },
    fetch(url) {
      active += 1;
      maxActive = Math.max(maxActive, active);
      let responseReady;
      let jsonReady;
      const response = new Promise(resolve => { responseReady = resolve; });
      const json = new Promise(resolve => { jsonReady = resolve; });
      requests.push({
        domain: new URL(url, 'http://console.test').searchParams.get('domain'),
        respond() { responseReady({ ok: true, json: () => json }); },
        finishJson(data) { active -= 1; jsonReady(data); },
      });
      return response;
    },
  };
  runInNewContext(readFileSync(join(__dirname, '../security_lab/static/console.js'), 'utf8'),
    context, { filename: 'console.js' });
  return { ids, requests, staleRenders, offline, poll: () => poll(),
    change(value) { ids.get('domain-select').value = value; ids.get('domain-select').listeners.get('change')(); },
    active: () => active, maxActive: () => maxActive };
}

function snapshot(domain, marker) {
  return {
    capture: { state: marker }, domains: ['live', 'offline:regression'], blocks: [],
    events: [{ kind: 'connection_attempt', domain, src_ip: '192.0.2.1',
      dst_ip: '192.0.2.2', dst_port: 443, time_utc: '2026-10-09T00:00:00Z' }],
    alerts: [{ rule: 'R1', summary: marker, src_ip: '192.0.2.1',
      evidence: { domain, marker }, time_utc: '2026-10-09T00:00:00Z' }],
  };
}

const turn = () => new Promise(resolve => setImmediate(resolve));

test('superseded live polling cannot render under offline selection and immediately refreshes serially', async () => {
  const ui = browser();
  assert.equal(ui.requests.length, 1);
  assert.equal(ui.requests[0].domain, 'live');
  ui.change(ui.offline);
  ui.poll();
  assert.equal(ui.requests.length, 1, 'domain change and poll must not overlap the pending live fetch');
  ui.requests[0].respond();
  await turn();
  ui.poll();
  assert.equal(ui.requests.length, 1, 'JSON parsing is still part of the in-flight request');
  ui.requests[0].finishJson(snapshot('live', 'LIVE_ONLY'));
  await turn();
  assert.deepEqual(ui.staleRenders, [], 'live evidence became visible while offline was selected');
  assert.equal(ui.requests.length, 2, 'latest selection must fetch immediately without an interval tick');
  assert.equal(ui.requests[1].domain, ui.offline);
  assert.equal(ui.active(), 1);
  ui.poll();
  ui.change(ui.offline);
  assert.equal(ui.requests.length, 2, 'only one offline follow-up may run');
  ui.requests[1].respond();
  await turn();
  ui.requests[1].finishJson(snapshot(ui.offline, 'OFFLINE_ONLY'));
  await turn();
  assert.equal(ui.ids.get('domain-select').value, ui.offline);
  assert.match(ui.ids.get('attempts-list').textContent, /offline:regression/);
  assert.match(ui.ids.get('alerts-list').textContent, /OFFLINE_ONLY/);
  assert.match(ui.ids.get('alerts-list').textContent, /"domain":"offline:regression"/);
  assert.doesNotMatch(ui.ids.get('alerts-list').textContent, /LIVE_ONLY/);
  assert.deepEqual(ui.staleRenders, []);
  assert.equal(ui.requests.length, 2);
  assert.equal(ui.active(), 0);
  assert.equal(ui.maxActive(), 1, 'fetch and JSON lifetimes must never overlap');
  assert.equal(ui.ids.get('connection-warning').hidden, true);
});
