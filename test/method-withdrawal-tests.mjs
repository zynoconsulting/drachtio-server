import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { connect, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import Srf from 'drachtio-srf';

const binary = process.env.DRACHTIO_BINARY || fileURLToPath(new URL('../build/drachtio', import.meta.url));
const sdp = 'v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=withdrawal\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n';

async function freePort() {
  const server = createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function startServer(t) {
  const directory = await mkdtemp(join(tmpdir(), 'drachtio-method-withdrawal-'));
  t.after(() => rm(directory, {recursive: true, force: true}));
  const adminPort = await freePort();
  const sipPort = await freePort();
  const secret = randomBytes(24).toString('hex');
  const config = join(directory, 'drachtio.conf.xml');
  await writeFile(config, `<drachtio>
    <admin port="${adminPort}" secret="${secret}">127.0.0.1</admin>
    <sip><contacts><contact>sip:127.0.0.1:${sipPort};transport=tcp</contact></contacts></sip>
    <cdrs>false</cdrs><logging><console/><sofia-loglevel>3</sofia-loglevel><loglevel>error</loglevel></logging>
  </drachtio>`, {mode: 0o600});
  const child = spawn(binary, ['--file', config, '--stdout'], {stdio: ['ignore', 'pipe', 'pipe']});
  let output = '';
  for (const stream of [child.stdout, child.stderr]) stream.on('data', data => { output = (output + data).slice(-4096); });
  let spawnError;
  child.on('error', error => { spawnError = error; });
  t.after(async () => {
    if (child.exitCode !== null || child.signalCode !== null || spawnError) return;
    const exited = once(child, 'exit');
    child.kill('SIGTERM');
    const timer = setTimeout(() => child.kill('SIGKILL'), 1000);
    try { await exited; } finally { clearTimeout(timer); }
  });
  const deadline = Date.now() + 5000;
  for (;;) {
    if (spawnError) throw spawnError;
    assert.equal(child.exitCode, null, `Drachtio exited before startup: ${output.replaceAll(secret, '[fixture-secret]')}`);
    const probe = connect(adminPort, '127.0.0.1');
    const ready = await new Promise(resolve => {
      probe.once('connect', () => resolve(true));
      probe.once('error', () => resolve(false));
    });
    probe.destroy();
    if (ready) return {adminPort, sipPort, secret};
    assert.ok(Date.now() < deadline, 'Drachtio did not start');
    await delay(25);
  }
}

async function application(t, server, name, subscriptions, calls) {
  const srf = new Srf(name);
  const handled = [];
  const respond = (req, res, status = 200) => {
    handled.push({method: req.method, dialogId: req.stackDialogId});
    res.send(status, {headers: {'X-Fixture-Owner': name, ...(req.method === 'SUBSCRIBE' ? {Expires: '3600'} : {})}});
  };
  srf.register((req, res) => respond(req, res));
  srf.options((req, res) => respond(req, res));
  srf.subscribe(async (req, res) => {
    if (req.stackDialogId) {
      assert.equal(subscriptions.get(req.get('Call-ID')), req.stackDialogId, 'subscription identity must survive application handoff');
      respond(req, res, 202);
      return;
    }
    const dialog = await srf.createUAS(req, res, {headers: {Expires: '3600', 'X-Fixture-Owner': name}});
    subscriptions.set(req.get('Call-ID'), dialog.id);
    srf.removeDialog(dialog);
  });
  srf.invite(async (req, res) => {
    if (!req.get('Call-ID').startsWith('established-')) {
      respond(req, res, 486);
      return;
    }
    const dialog = await srf.createUAS(req, res, {localSdp: sdp, headers: {'X-Fixture-Owner': name}});
    dialog.on('info', (request, response) => respond(request, response));
    dialog.on('destroy', () => calls.delete(req.get('Call-ID')));
    calls.set(req.get('Call-ID'), {dialog, owner: name});
  });
  srf.on('error', () => {});
  t.after(() => {
    try { srf.disconnect(); } catch { /* Already disconnected after the handoff assertion. */ }
  });
  const connected = once(srf, 'connect');
  srf.connect({host: '127.0.0.1', port: server.adminPort, secret: server.secret, reconnect: {maxAttempts: 1}});
  await connected;
  return {srf, handled};
}

// Use the native acknowledged command directly, so this regression also runs with
// the upstream SDK whose unregisterForMessages method does not expose its reply.
async function command(srf, name, method) {
  const agent = srf.app.client;
  const [socket, state] = [...agent.mapServer][0];
  await new Promise((resolve, reject) => {
    const id = agent.wp.send(socket, `${name}|${method}`);
    const timer = setTimeout(() => {
      state.pendingRequests.delete(id);
      reject(new Error('native route command was not acknowledged'));
    }, 2000);
    state.pendingRequests.set(id, response => {
      clearTimeout(timer);
      if (response[0] === 'OK') resolve();
      else reject(new Error(`native route command failed: ${response[0]}`));
    });
  });
}

async function sipPeer(t, sipPort) {
  const socket = connect(sipPort, '127.0.0.1');
  t.after(() => socket.destroy());
  await once(socket, 'connect');
  let buffer = Buffer.alloc(0);
  const pending = new Map();
  const notifications = [];
  const send = (start, headers, body = '') => socket.write([start,
    ...Object.entries(headers).map(([name, value]) => `${name}: ${value}`),
    `Content-Length: ${Buffer.byteLength(body)}`, '', body].join('\r\n'));
  socket.on('data', data => {
    buffer = Buffer.concat([buffer, data]);
    for (;;) {
      const end = buffer.indexOf('\r\n\r\n');
      if (end < 0) return;
      const [start, ...lines] = buffer.subarray(0, end).toString().split('\r\n');
      const headers = Object.fromEntries(lines.map(line => {
        const colon = line.indexOf(':');
        return [line.slice(0, colon).toLowerCase(), line.slice(colon + 1).trim()];
      }));
      const length = end + 4 + Number(headers['content-length'] || 0);
      if (buffer.length < length) return;
      buffer = buffer.subarray(length);
      const status = Number(start.split(' ')[1]);
      if (start.startsWith('SIP/2.0 ')) {
        if (status >= 200) pending.get(`${headers['call-id']}:${headers.cseq}`)?.({status, headers});
      } else {
        notifications.push({start, headers});
        send('SIP/2.0 200 OK', Object.fromEntries(['via', 'from', 'to', 'call-id', 'cseq'].map(name => [name, headers[name]])));
      }
    }
  });
  const request = async (method, options = {}) => {
    const callId = options.callId || randomUUID();
    const cseq = `${options.sequence || 1} ${method}`;
    const uri = options.uri || `sip:resource@127.0.0.1:${sipPort}`;
    const headers = {
      Via: `SIP/2.0/TCP 127.0.0.1:${socket.localPort};branch=z9hG4bK${randomUUID()}`,
      From: options.from || '<sip:fixture@localhost>;tag=fixture',
      To: options.to || '<sip:resource@localhost>',
      'Call-ID': callId,
      CSeq: cseq,
      'Max-Forwards': '70',
      Contact: `<sip:fixture@127.0.0.1:${socket.localPort};transport=tcp>`,
      ...(method === 'SUBSCRIBE' ? {Event: 'dialog', Expires: '3600'} : {}),
      ...(method === 'INVITE' ? {'Content-Type': 'application/sdp'} : {})
    };
    if (method === 'ACK') { send(`${method} ${uri} SIP/2.0`, headers); return; }
    const response = await new Promise((resolve, reject) => {
      const key = `${callId}:${cseq}`;
      const timer = setTimeout(() => { pending.delete(key); reject(new Error(`SIP ${method} timed out`)); }, 3000);
      pending.set(key, result => { clearTimeout(timer); pending.delete(key); resolve(result); });
      send(`${method} ${uri} SIP/2.0`, headers, method === 'INVITE' ? sdp : '');
    });
    return {...response, callId, uri, from: headers.From};
  };
  return {request, notifications};
}

it('withdraws only selected methods while calls and subscriptions retain their owners', {timeout: 30000}, async t => {
  const server = await startServer(t);
  const subscriptions = new Map();
  const calls = new Map();
  const retiring = await application(t, server, 'retiring', subscriptions, calls);
  const peer = await sipPeer(t, server.sipPort);
  const call = await peer.request('INVITE', {callId: `established-${randomUUID()}`});
  assert.equal(call.status, 200);
  const dialogRequest = {callId: call.callId, from: call.from, to: call.headers.to, uri: call.headers.contact.replace(/^<|>$/g, '')};
  await peer.request('ACK', dialogRequest);
  const subscription = await peer.request('SUBSCRIBE');
  assert.equal(subscription.status, 202);
  const survivor = await application(t, server, 'survivor', subscriptions, calls);

  // Duplicate registrations must all be removed, without disturbing another method.
  await command(retiring.srf, 'route', 'register');
  await command(retiring.srf, 'remove_route', 'register');
  await command(retiring.srf, 'remove_route', 'register');
  for (let index = 0; index < 6; index++) {
    const registration = await peer.request('REGISTER');
    assert.equal(registration.status, 200);
    assert.equal(registration.headers['x-fixture-owner'], 'survivor');
  }
  const invitationOwners = new Set();
  const subscriptionOwners = new Set();
  for (let index = 0; index < 6; index++) {
    const invitation = await peer.request('INVITE');
    assert.equal(invitation.status, 486);
    invitationOwners.add(invitation.headers['x-fixture-owner']);
    const subscribed = await peer.request('SUBSCRIBE');
    assert.equal(subscribed.status, 202);
    subscriptionOwners.add(subscribed.headers['x-fixture-owner']);
  }
  assert.deepEqual(invitationOwners, new Set(['retiring', 'survivor']));
  assert.deepEqual(subscriptionOwners, new Set(['retiring', 'survivor']));

  for (const method of ['subscribe', 'options']) await command(retiring.srf, 'remove_route', method);
  for (let index = 0; index < 6; index++) for (const method of ['REGISTER', 'SUBSCRIBE', 'OPTIONS']) {
    const response = await peer.request(method);
    assert.equal(response.status, method === 'SUBSCRIBE' ? 202 : 200);
    assert.equal(response.headers['x-fixture-owner'], 'survivor');
  }
  const renewalRequest = {callId: subscription.callId, from: subscription.from, to: subscription.headers.to,
    uri: subscription.headers.contact.replace(/^<|>$/g, ''), sequence: 2};
  const renewal = await peer.request('SUBSCRIBE', renewalRequest);
  assert.equal(renewal.status, 202);
  assert.equal(renewal.headers['x-fixture-owner'], 'retiring', 'existing subscription remains on its connected owner');
  const info = await peer.request('INFO', {...dialogRequest, sequence: 2});
  assert.equal(info.status, 200);
  assert.equal(info.headers['x-fixture-owner'], 'retiring', 'method withdrawal must preserve established call signaling');
  const ended = await peer.request('BYE', {...dialogRequest, sequence: 3});
  assert.equal(ended.status, 200);
  const endedDeadline = Date.now() + 2000;
  while (calls.has(call.callId)) {
    assert.ok(Date.now() < endedDeadline, 'the call owner did not observe normal hangup');
    await delay(5);
  }
  const closed = once(retiring.srf, 'close');
  retiring.srf.disconnect();
  await closed;
  const handoff = await peer.request('SUBSCRIBE', {...renewalRequest, sequence: 3});
  assert.equal(handoff.status, 202);
  assert.equal(handoff.headers['x-fixture-owner'], 'survivor');
  assert.ok(survivor.handled.some(request => request.dialogId === subscriptions.get(subscription.callId)));
  const notifyStatus = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('surviving subscription owner did not complete NOTIFY')), 3000);
    survivor.srf.request('sip:placeholder', {
      method: 'NOTIFY', stackDialogId: subscriptions.get(subscription.callId),
      headers: {Event: 'dialog', 'Subscription-State': 'active;expires=3600'}
    }, (error, request) => {
      if (error) { clearTimeout(timer); reject(error); return; }
      request.on('response', response => {
        if (response.status < 200) return;
        clearTimeout(timer);
        resolve(response.status);
      });
    });
  });
  assert.equal(notifyStatus, 200);
  assert.ok(peer.notifications.some(notification => notification.start.startsWith('NOTIFY ') && notification.headers['call-id'] === subscription.callId));
});
