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
const callSdp = 'v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=contact-test\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n';

async function freePort() {
  const server = createServer();
  const listening = once(server, 'listening');
  server.listen(0, '127.0.0.1');
  await listening;
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function startServer(t, transport, fixture) {
  const directory = await mkdtemp(join(tmpdir(), 'drachtio-subscription-refresh-'));
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
      <contacts>${plainContact}<contact${fixture.externalIp ? ` external-ip="${fixture.externalIp}"` : ''}>${scheme}:127.0.0.1:${sipPort};transport=${transport}</contact></contacts>
      <tls><key-file>${keyFile}</key-file><cert-file>${certFile}</cert-file><chain-file>${certFile}</chain-file><min-tls-version>1.2</min-tls-version></tls>
    </sip>
    <cdrs>false</cdrs>
    <logging><console/><sofia-loglevel>3</sofia-loglevel><loglevel>error</loglevel></logging>
  </drachtio>`, {mode: 0o600});
  const child = spawn(binary, ['--file', config, '--stdout', ...(fixture.aggressive ? ['--aggressive-nat-detection'] : [])], {stdio: ['ignore', 'pipe', 'pipe'], env: {...process.env, DRACHTIO_TPORT_CONTACT_ALIAS: fixture.aliases ? '1' : '0'}});
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
  if (transport !== 'udp') for (let attempt = 0; ; attempt++) {
    const ready = await new Promise(resolve => {
      const probe = transport === 'tls'
        ? connectTls({host: '127.0.0.1', port: sipPort, rejectUnauthorized: false})
        : connect(sipPort, '127.0.0.1');
      probe.once(transport === 'tls' ? 'secureConnect' : 'connect', () => { probe.destroy(); resolve(true); });
      probe.once('error', () => { probe.destroy(); resolve(false); });
    });
    if (ready) break;
    assert.ok(attempt < 100, 'SIP listener did not become ready');
    await delay(25);
  }
  return {srf, sipPort, scheme};
}

async function createPeer(t, transport, sipPort) {
  const socket = transport === 'udp' ? createSocket('udp4') : transport === 'tls' ? connectTls({host: '127.0.0.1', port: sipPort, rejectUnauthorized: false})
    : connect(sipPort, '127.0.0.1');
  t.after(() => transport === 'udp' ? socket.close() : socket.destroy());
  const received = [];
  const responses = new Map();
  let resolveAck;
  const acknowledged = new Promise(resolve => { resolveAck = resolve; });
  let subscriptionContact;
  let inviteContact;
  const subscriptionTag = randomUUID();
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
    const method = lines[0].split(' ')[0];
    received.push({method, uri: lines[0].split(' ')[1], headers});
    if (method === 'ACK') { resolveAck(); return; }
    const acceptsSubscription = raw.startsWith('SUBSCRIBE ') && subscriptionContact;
    const acceptsInvite = method === 'INVITE' && inviteContact;
    send(['SIP/2.0 200 OK', ...['via', 'from', 'to', 'call-id', 'cseq'].map(name =>
      `${name}: ${headers[name]}${(acceptsSubscription || acceptsInvite) && name === 'to' && !headers.to.includes(';tag=') ? ';tag=' + subscriptionTag : ''}`),
      ...(acceptsSubscription ? [`Contact: <${subscriptionContact}>`, 'Expires: 3600'] : []),
      ...(acceptsInvite ? [`Contact: <${inviteContact}>`, 'Content-Type: application/sdp'] : []),
      `Content-Length: ${acceptsInvite ? Buffer.byteLength(callSdp) : 0}`, '', acceptsInvite ? callSdp : ''].join('\r\n'));
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
    port, received, acknowledged, close: () => transport === 'udp' ? socket.close() : socket.destroy(),
    setSubscriptionContact: contact => { subscriptionContact = contact; },
    setInviteContact: contact => { inviteContact = contact; },
    hangup(invite) {
      send([`BYE ${invite.headers.contact.slice(1, -1)} SIP/2.0`,
        `Via: SIP/2.0/${transport.toUpperCase()} 127.0.0.1:${port};branch=z9hG4bK-${randomUUID()};rport`,
        `From: ${invite.headers.to};tag=${subscriptionTag}`, `To: ${invite.headers.from}`,
        `Call-ID: ${invite.headers['call-id']}`, 'CSeq: 2 BYE', 'Max-Forwards: 70',
        'Content-Length: 0', '', ''].join('\r\n'));
    },
    request(method, contact, scheme, options = {}) {
      const callId = options.callId || randomUUID();
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
        `From: <sip:watcher@tenant.test>;tag=${options.fromTag || randomUUID()}`, `To: <sip:watched@tenant.test>${options.toTag ? ";tag=" + options.toTag : ""}`,
        `Call-ID: ${callId}`, `CSeq: ${options.cseq || 1} ${method}`, ...(contact ? [`Contact: <${contact}>`] : []), ...(options.recordRoute ? [`Record-Route: ${options.recordRoute}`] : []), 'Max-Forwards: 70',
        'Event: dialog', `Expires: ${options.expires ?? 3600}`, 'Content-Length: 0', '', ''].join('\r\n'));
      return response;
    }
  };
}

for (const fixture of [
  {transport: 'tcp', externalIp: '198.51.100.25'},
  {transport: 'tls', externalIp: '198.51.100.25'},
  {transport: 'tls'},
  {transport: 'tls', externalIp: '198.51.100.25', appContact: '<sips:application@example.test>'},
  {transport: 'tls', externalIp: '198.51.100.25', appContact: '<sips:application@localhost>'}
]) {
  it(`${fixture.transport}: registered peer INVITE advertises ${fixture.appContact || fixture.externalIp || 'local listener'}`, {timeout: 10000}, async t => {
    const {srf, sipPort, scheme} = await startServer(t, fixture.transport, fixture);
    const peer = await createPeer(t, fixture.transport, sipPort);
    const remoteContact = `sip:watcher@10.0.0.25:${peer.port};transport=${fixture.transport}`;
    peer.setInviteContact(remoteContact);
    const registerStatus = await peer.request('REGISTER', remoteContact, scheme);
    assert.equal(registerStatus, 200);

    const dialog = await srf.createUAC(remoteContact, {localSdp: callSdp, headers: fixture.appContact ? {Contact: fixture.appContact} : {}});
    const invite = peer.received.find(request => request.method === 'INVITE');
    assert.ok(invite, 'INVITE uses the registered socket rather than the unreachable private Contact');
    const expectedContact = fixture.appContact
      ? fixture.appContact.replace('localhost', `${fixture.externalIp}:${sipPort}`)
      : `<${scheme}:${fixture.externalIp || '127.0.0.1'}:${sipPort};transport=${fixture.transport}>`;
    assert.equal(invite.headers.contact, expectedContact);

    await peer.acknowledged;
    const destroyed = once(dialog, 'destroy');
    peer.hangup(invite);
    await destroyed;
  });
}

for (const transport of ['tcp', 'tls']) {
  it(`${transport}: outbound subscription retains REGISTER peer handoff`, {timeout: 10000}, async t => {
    const {srf, sipPort, scheme} = await startServer(t, transport, {});
    const original = await createPeer(t, transport, sipPort);
    const current = await createPeer(t, transport, sipPort);
    const remoteContact = `sip:watcher@10.0.0.25:${original.port};transport=${transport}`;
    original.setSubscriptionContact(remoteContact);
    current.setSubscriptionContact(remoteContact);
    await delay(50);
    assert.equal(await original.request('REGISTER', remoteContact, scheme), 200);

    // Reuse the peer's established connection to create a locally initiated dialog.
    const initialTarget = `${scheme}:watcher@127.0.0.1:${original.port};transport=${transport}`;
    const dialog = await srf.createUAC(initialTarget, {method: 'SUBSCRIBE', headers: {Event: 'dialog', Expires: '3600'}});
    assert.equal(original.received.length, 1);
    original.received.length = 0;
    assert.equal(await current.request('REGISTER', remoteContact, scheme), 200);

    const response = await dialog.request({method: 'SUBSCRIBE', headers: {Event: 'dialog', Expires: '3600'}});
    assert.equal(response.status, 200);
    assert.equal(current.received.length, 1, 'outbound renewal retains the existing REGISTER cache handoff');
    assert.equal(original.received.length, 0, 'old connection receives no outbound renewal');
    assert.equal(current.received[0].uri, remoteContact, 'handoff preserves the subscription remote target');
  });
}

async function notify(srf, uri, stackDialogId, terminated) {
  const response = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('NOTIFY did not receive a final response within 3 seconds')), 3000);
    // Dialog.request emits this placeholder when the application omits the Request-URI.
    srf.request(uri || 'sip:placeholder', {method: 'NOTIFY', stackDialogId,
      headers: {Event: 'dialog', 'Subscription-State': terminated ? 'terminated;reason=timeout' : 'active;expires=3600'}},
    (error, request) => {
      if (error) { clearTimeout(timer); return reject(error); }
      request.on('response', result => {
        if (result.status >= 200) { clearTimeout(timer); resolve(result); }
      });
    });
  });
  assert.equal(response.status, 200);
}

const fixtures = [
  {name: 'SIPS Contact over TLS', transports: ['tls'], sips: true},
  {name: 'bare SIP Contact over TLS', transports: ['tls'], bareContact: true},
  {name: 'same connection, corrected public Contact', transports: ['tls'], sameConnection: true, publicContact: true},
  {name: 'replacement connection, unchanged Contact, explicit URI', transports: ['udp', 'tls'], sameContact: true},
  {name: 'replacement connection, changed private Contact, explicit URI'},
  {name: 'replacement connection, changed private Contact, default URI', transports: ['tls'], defaultUri: true},
  {name: 'replacement connection, corrected public Contact', transports: ['udp', 'tls'], publicContact: true},
  {name: 'initial reachable Contact', transports: ['udp', 'tls'], publicInitially: true, publicContact: true},
  {name: 'replacement connection, omitted Contact', transports: ['tls'], omitContact: true},
  {name: 'replacement connection, rejected renewal', transports: ['udp', 'tls'], rejection: 403},
  {name: 'replacement connection, challenged renewal with aliases enabled', transports: ['tls'], rejection: 401, sameContact: true, aliases: true},
  {name: 'rejected renewal cannot follow a Contact alias after cache expiry', transports: ['tls'], rejection: 403, sameContact: true, aliases: true, initialExpires: 1},
  {name: 'REGISTER on another connection, default URI', transports: ['tls'], registerElsewhere: true, defaultUri: true},
  {name: 'established route set survives renewal', transports: ['udp', 'tls'], recordRoute: true},
  {name: 'UDP NAT hint survives renewal without Record-Route', transports: ['udp'], recordRoute: true, aggressive: true},
  {name: 'original connection closes after renewal', transports: ['tls'], closeOriginal: true},
  {name: 'accepted cancellation refreshes peer and target despite stale application URI', transports: ['udp', 'tls'], expires: 0}
];
for (const transport of ['udp', 'tcp', 'tls']) {
  for (const fixture of fixtures) {
    if (fixture.transports && !fixture.transports.includes(transport)) continue;
    it(`${transport}: ${fixture.name}`, {timeout: 10000}, async t => {
      const {srf, sipPort, scheme} = await startServer(t, transport, fixture);
      const original = await createPeer(t, transport, sipPort);
      const current = fixture.sameConnection ? original : await createPeer(t, transport, sipPort);
      const contactScheme = fixture.sips ? 'sips' : 'sip';
      const contactTransport = fixture.bareContact ? '' : `;transport=${transport}`;
      const oldContact = `${contactScheme}:watcher@${fixture.publicInitially ? '127.0.0.1' : '10.0.0.25'}:${original.port}${contactTransport}`;
      const newContact = fixture.sameContact || fixture.omitContact ? oldContact
        : `${contactScheme}:watcher@${fixture.publicContact ? '127.0.0.1' : '10.0.0.25'}:${current.port}${contactTransport}`;
      const originalRoute = fixture.recordRoute
        ? fixture.aggressive ? `<sip:proxy.tenant.test:5060;transport=udp;lr;nat=yes>`
          : transport === 'udp' ? `<sip:127.0.0.1:${original.port};transport=udp;lr>`
          : `<sip:proxy.tenant.test:5061;transport=${transport};lr>`
        : undefined;
      let resolveDialog;
      let rejectDialog;
      let refreshedDialogId;
      const established = new Promise((resolve, reject) => { resolveDialog = resolve; rejectDialog = reject; });
      srf.subscribe((req, res) => {
        if (req.stackDialogId) {
          refreshedDialogId = req.stackDialogId;
          res.send(fixture.rejection || 202, {headers: {Expires: String(fixture.expires ?? 3600)}});
          return;
        }
        srf.createUAS(req, res, {headers: {Expires: String(fixture.initialExpires ?? 3600)}}).then(resolveDialog, rejectDialog);
      });
      // SUBSCRIBE route registration and the SIP request use different sockets.
      await delay(50);
      const subscribed = original.request('SUBSCRIBE', oldContact, scheme, {recordRoute: originalRoute});
      const dialog = await established;
      assert.equal(await subscribed, 202);
      // Keep the native dialog only, so the application cannot refresh routing in a local Dialog object.
      srf.removeDialog(dialog);
      await notify(srf, oldContact, dialog.id);
      assert.equal(original.received.length, 1, 'initial NOTIFY uses the established peer');
      original.received.length = 0;
      if (fixture.initialExpires) await delay(1600);
      const refreshStatus = await current.request('SUBSCRIBE', fixture.omitContact ? undefined : newContact, scheme, {
        callId: dialog.sip.callId, fromTag: dialog.sip.remoteTag, toTag: dialog.sip.localTag, cseq: 2,
        expires: fixture.expires, recordRoute: fixture.recordRoute && !fixture.aggressive ? '<sip:other-proxy.tenant.test;lr>' : undefined
      });
      assert.equal(refreshStatus, fixture.rejection || 202);
      assert.equal(refreshedDialogId, dialog.id, 'renewal belongs to the existing dialog');
      if (fixture.registerElsewhere) assert.equal(await original.request('REGISTER', newContact, scheme), 200);
      if (fixture.closeOriginal && transport !== 'udp') original.close();
      // An application may still pass its previous target when sending a terminal NOTIFY.
      const notifyUri = fixture.defaultUri ? undefined : fixture.expires === 0 ? oldContact : newContact;
      await notify(srf, notifyUri, dialog.id, fixture.expires === 0);
      const destination = fixture.rejection || (transport === 'udp' && fixture.recordRoute && !fixture.aggressive) ? original : current;
      const other = destination === original ? current : original;
      assert.equal(destination.received.length, 1, 'NOTIFY uses the accepted peer or established route set');
      if (other !== destination) assert.equal(other.received.length, 0, 'other peer receives no NOTIFY');
      const delivered = destination.received[0];
      assert.equal(delivered.uri, fixture.rejection ? oldContact : newContact, 'accepted Contact is the remote target');
      assert.equal(delivered.headers['call-id'], dialog.sip.callId);
      assert.ok(delivered.headers.from.includes(`;tag=${dialog.sip.localTag}`));
      assert.ok(delivered.headers.to.includes(`;tag=${dialog.sip.remoteTag}`));
      assert.equal(delivered.headers.route, originalRoute, 'renewal preserves the established SIP route set');
    });
  }
}
