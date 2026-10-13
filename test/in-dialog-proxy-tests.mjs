import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { createSocket } from 'node:dgram';
import { once } from 'node:events';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { connect, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { it } from 'node:test';
import { connect as connectTls } from 'node:tls';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import Srf from 'drachtio-srf';

// Each case starts an isolated local server. Override DRACHTIO_BINARY to check another build.
const binary = process.env.DRACHTIO_BINARY || fileURLToPath(new URL('../build/drachtio', import.meta.url));

async function freePort() {
  const server = createServer();
  const listening = once(server, 'listening');
  server.listen(0, '127.0.0.1');
  await listening;
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function startServer(t, transport) {
  const directory = await mkdtemp(join(tmpdir(), 'drachtio-in-dialog-proxy-'));
  t.after(() => rm(directory, {recursive: true, force: true}));
  const adminPort = await freePort();
  const sipPort = await freePort();
  let plainContact = '';
  if (transport === 'tls') {
    const plainPort = await freePort();
    plainContact = `<contact>sip:127.0.0.1:${plainPort};transport=udp,tcp</contact>`;
  }
  const secret = randomBytes(24).toString('hex');
  const scheme = transport === 'tls' ? 'sips' : 'sip';
  const keyFile = join(directory, 'server.key');
  const certFile = join(directory, 'server.crt');
  if (transport === 'tls') {
    await new Promise((resolve, reject) => {
      execFile('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyFile, '-out', certFile,
        '-subj', '/CN=localhost', '-days', '1'], error => error ? reject(error) : resolve());
    });
  }
  const config = join(directory, 'drachtio.conf.xml');
  await writeFile(config, `<drachtio>
    <admin port="${adminPort}" secret="${secret}">127.0.0.1</admin>
    <sip>
      <contacts>${plainContact}<contact>${scheme}:127.0.0.1:${sipPort};transport=${transport}</contact></contacts>
      <tls><key-file>${keyFile}</key-file><cert-file>${certFile}</cert-file><chain-file>${certFile}</chain-file><min-tls-version>1.2</min-tls-version></tls>
    </sip>
    <cdrs>false</cdrs>
    <logging><console/><sofia-loglevel>3</sofia-loglevel><loglevel>error</loglevel></logging>
  </drachtio>`, {mode: 0o600});
  const child = spawn(binary, ['--file', config, '--stdout'], {stdio: ['ignore', 'pipe', 'pipe']});
  let output = '';
  for (const stream of [child.stdout, child.stderr]) {
    stream.on('data', data => { output = (output + data).slice(-4096); });
  }
  let srf;
  let spawnError;
  child.on('error', error => { spawnError = error; });
  t.after(async () => {
    if (srf) {
      const closed = once(srf, 'close');
      srf.disconnect();
      await closed;
    }
    if (child.exitCode !== null || child.signalCode !== null || spawnError) return;
    const exited = once(child, 'exit');
    child.kill('SIGTERM');
    const killTimer = setTimeout(() => child.kill('SIGKILL'), 1000);
    try { await exited; } finally { clearTimeout(killTimer); }
  });
  const deadline = Date.now() + 5000;
  for (;;) {
    if (spawnError) throw spawnError;
    assert.equal(child.exitCode, null, `Drachtio exited before its admin listener was ready: ${output.replaceAll(secret, '[fixture-secret]')}`);
    const socket = connect(adminPort, '127.0.0.1');
    const ready = await new Promise(resolve => {
      socket.once('connect', () => resolve(true));
      socket.once('error', () => resolve(false));
    });
    socket.destroy();
    if (ready) break;
    assert.ok(Date.now() < deadline, 'Drachtio admin listener did not start');
    await delay(25);
  }
  srf = new Srf();
  srf.register((req, res) => res.send(200, {headers: {Contact: req.get('Contact'), Expires: '3600'}}));
  const connected = once(srf, 'connect');
  srf.connect({host: '127.0.0.1', port: adminPort, secret});
  await connected;
  return {srf, sipPort, scheme};
}

async function createPeer(t, transport, sipPort) {
  const socket = transport === 'udp' ? createSocket('udp4')
    : transport === 'tls' ? connectTls({host: '127.0.0.1', port: sipPort, rejectUnauthorized: false})
    : connect(sipPort, '127.0.0.1');
  t.after(() => transport === 'udp' ? socket.close() : socket.destroy());
  const received = [];
  const responses = new Map();
  const send = packet => transport === 'udp' ? socket.send(packet, sipPort, '127.0.0.1') : socket.write(packet);
  const receive = packet => {
    const raw = packet.toString();
    const lines = raw.split('\r\n');
    const headers = Object.fromEntries(lines.slice(1).filter(line => line.includes(':')).map(line => {
      const colon = line.indexOf(':');
      return [line.slice(0, colon).toLowerCase(), line.slice(colon + 1).trim()];
    }));
    if (raw.startsWith('SIP/2.0 ')) {
      const status = Number(lines[0].split(' ')[1]);
      if (status >= 200) responses.get(headers['call-id'])?.(status);
      return;
    }
    received.push({uri: lines[0].split(' ')[1], headers});
    send(['SIP/2.0 200 OK', ...['via', 'from', 'to', 'call-id', 'cseq'].map(name => `${name}: ${headers[name]}`),
      'Content-Length: 0', '', ''].join('\r\n'));
  };
  if (transport === 'udp') {
    socket.on('message', receive);
    const listening = once(socket, 'listening');
    socket.bind(0, '127.0.0.1');
    await listening;
  } else {
    socket.setEncoding('utf8');
    let buffer = '';
    socket.on('data', data => {
      buffer += data;
      for (;;) {
        const end = buffer.indexOf('\r\n\r\n');
        if (end < 0) return;
        const length = Number(/Content-Length:\s*(\d+)/i.exec(buffer.slice(0, end))?.[1] || 0);
        const frameLength = end + 4 + length;
        if (buffer.length < frameLength) return;
        const frame = buffer.slice(0, frameLength);
        buffer = buffer.slice(frameLength);
        receive(frame);
      }
    });
    await once(socket, transport === 'tls' ? 'secureConnect' : 'connect');
  }
  const port = transport === 'udp' ? socket.address().port : socket.localPort;
  return {
    port, received,
    request(method, contact, scheme) {
      const callId = randomUUID();
      const response = new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          responses.delete(callId);
          reject(new Error(`${method} response timed out`));
        }, 3000);
        responses.set(callId, status => {
          clearTimeout(timer);
          responses.delete(callId);
          resolve(status);
        });
      });
      send([`${method} ${scheme}:watched@127.0.0.1:${sipPort} SIP/2.0`,
        `Via: SIP/2.0/${transport.toUpperCase()} 127.0.0.1:${port};branch=z9hG4bK-${randomUUID()};rport`,
        `From: <sip:watcher@tenant.test>;tag=${randomUUID()}`, 'To: <sip:watched@tenant.test>',
        `Call-ID: ${callId}`, 'CSeq: 1 ' + method, `Contact: <${contact}>`, 'Max-Forwards: 70',
        'Event: dialog', 'Expires: 3600', 'Content-Length: 0', '', ''].join('\r\n'));
      return response;
    }
  };
}

async function notify(srf, contact, options) {
  const response = await new Promise((resolve, reject) => {
    srf.request(contact, {method: 'NOTIFY', uri: contact,
      headers: {Event: 'dialog', 'Subscription-State': 'active;expires=3600'}, ...options}, (error, request) => {
      if (error) return reject(error);
      request.on('response', result => {
        if (result.status >= 200) resolve(result);
      });
    });
  });
  assert.equal(response.status, 200);
}

for (const fixture of [
  {name: 'UDP next hop by dialog id', transport: 'udp'},
  {name: 'UDP next hop by Call-ID', transport: 'udp', byCallId: true},
  {name: 'TCP next hop with inherited transport', transport: 'tcp'},
  {name: 'TCP next hop with another URI parameter', transport: 'tcp', proxyParams: ';lr'},
  {name: 'TCP next hop with explicit transport', transport: 'tcp', explicitTransport: true},
  {name: 'SIPS next hop', transport: 'tls'},
  {name: 'UDP dialog without a next hop', transport: 'udp', noProxy: true},
  {name: 'TCP dialog without a next hop', transport: 'tcp', noProxy: true},
  {name: 'already reachable public Contact', transport: 'udp', publicContact: true}
]) {
  it(fixture.name, {timeout: 15000}, async t => {
    const {srf, sipPort, scheme} = await startServer(t, fixture.transport);
    const original = await createPeer(t, fixture.transport, sipPort);
    const current = await createPeer(t, fixture.transport, sipPort);
    const contact = `${scheme}:watcher@${fixture.publicContact ? '127.0.0.1' : '10.0.0.25'}:${original.port}`;
    let resolveDialog;
    let rejectDialog;
    const established = new Promise((resolve, reject) => { resolveDialog = resolve; rejectDialog = reject; });
    srf.subscribe((req, res) => {
      srf.createUAS(req, res, {headers: {Expires: '3600'}}).then(resolveDialog, rejectDialog);
    });
    const subscribed = original.request('SUBSCRIBE', contact, scheme);
    const dialog = await established;
    assert.equal(await subscribed, 202);
    srf.removeDialog(dialog);
    assert.equal(await current.request('REGISTER', contact, scheme), 200);
    const destination = fixture.noProxy || fixture.publicContact ? original : current;
    const peerUri = `${scheme}:127.0.0.1:${destination.port}${fixture.explicitTransport ? ';transport=tcp' : fixture.proxyParams || ''}`;
    const options = fixture.byCallId ? {headers: {Event: 'dialog', 'Subscription-State': 'active;expires=3600', 'Call-ID': dialog.sip.callId,
      From: `<sip:watched@tenant.test>;tag=${dialog.sip.localTag}`, To: `<sip:watcher@tenant.test>;tag=${dialog.sip.remoteTag}`}}
      : {stackDialogId: dialog.id};
    if (!fixture.noProxy) options.proxy = peerUri;

    await notify(srf, contact, options);

    assert.equal(destination.received.length, 1, 'NOTIFY must arrive at the selected peer');
    assert.equal((destination === original ? current : original).received.length, 0, 'other peer must receive no NOTIFY');
    const message = destination.received[0];
    assert.equal(message.uri, contact, 'Contact remains the Request-URI');
    assert.equal(message.headers['call-id'], dialog.sip.callId, 'subscription dialog is preserved');
    assert.ok(message.headers.from.includes(`;tag=${dialog.sip.localTag}`));
    assert.ok(message.headers.to.includes(`;tag=${dialog.sip.remoteTag}`));
  });
}
