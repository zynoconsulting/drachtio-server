import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { connect, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { it } from 'node:test';
import { connect as connectTls, createServer as createTlsServer } from 'node:tls';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const binary = process.env.DRACHTIO_BINARY || fileURLToPath(new URL('../build/drachtio', import.meta.url));
const keyFile = fileURLToPath(new URL('./tls/server.key', import.meta.url));
const certFile = fileURLToPath(new URL('./tls/server.crt', import.meta.url));
const sdp = direction => `v=0\r\no=fixture 1 1 IN IP4 127.0.0.1\r\ns=duplicate-final\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=${direction}\r\n`;
const header = (message, name) => message.match(new RegExp(`^${name}:\\s*(.+)$`, 'im'))?.[1]?.trim();
const sip = (start, headers, body = '') => [start,
  ...Object.entries(headers).map(([name, value]) => `${name}: ${value}`),
  `Content-Length: ${Buffer.byteLength(body)}`, '', body].join('\r\n');

async function waitFor(predicate, label) {
  const deadline = Date.now() + 5000;
  for (;;) {
    const result = predicate();
    if (result) return result;
    assert.ok(Date.now() < deadline, `timed out waiting for ${label}`);
    await delay(5);
  }
}

async function freePort() {
  const server = createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

async function startServer(t, transport) {
  const directory = await mkdtemp(join(tmpdir(), 'drachtio-duplicate-final-'));
  const config = join(directory, 'drachtio.conf.xml');
  const adminPort = await freePort();
  const sipPort = await freePort();
  const plainPort = await freePort();
  const scheme = transport === 'tls' ? 'sips' : 'sip';
  const secret = randomUUID();
  await writeFile(config, `<drachtio>
    <admin port="${adminPort}" secret="${secret}">127.0.0.1</admin>
    <sip><contacts>
      <contact>${scheme}:127.0.0.1:${sipPort};transport=${transport}</contact>
      ${transport === 'tls' ? `<contact>sip:127.0.0.1:${plainPort};transport=tcp</contact>` : ''}
    </contacts><tls><key-file>${keyFile}</key-file><cert-file>${certFile}</cert-file><chain-file>${certFile}</chain-file></tls></sip>
    <cdrs>false</cdrs><logging><console/><sofia-loglevel>3</sofia-loglevel><loglevel>info</loglevel></logging>
  </drachtio>`, {mode: 0o600});
  const child = spawn(binary, ['--file', config, '--stdout'], {stdio: ['ignore', 'pipe', 'pipe']});
  let output = '';
  let spawnError;
  child.on('error', error => { spawnError = error; });
  for (const stream of [child.stdout, child.stderr]) stream.on('data', data => { output = (output + data).slice(-65536); });
  t.after(async () => {
    if (!spawnError && child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit');
      child.kill('SIGTERM');
      const timer = setTimeout(() => child.kill('SIGKILL'), 1000);
      try { await exited; } finally { clearTimeout(timer); }
    }
    await rm(directory, {recursive: true, force: true});
  });
  // The admin thread starts before Sofia has finished creating SIP transports.
  // Wait for both listeners before sending the initial application INVITE.
  for (const target of [{port: adminPort, tls: false}, {port: sipPort, tls: transport === 'tls'}]) {
    const deadline = Date.now() + 5000;
    for (;;) {
      if (spawnError) throw spawnError;
      assert.equal(child.exitCode, null, `Drachtio exited during startup: ${output.replaceAll(secret, '[fixture-secret]')}`);
      const probe = target.tls ? connectTls({host: '127.0.0.1', port: target.port, rejectUnauthorized: false}) : connect(target.port, '127.0.0.1');
      const ready = await new Promise(resolve => {
        probe.once(target.tls ? 'secureConnect' : 'connect', () => resolve(true));
        probe.once('error', () => resolve(false));
      });
      probe.destroy();
      if (ready) break;
      assert.ok(Date.now() < deadline, `Drachtio listener ${target.port} did not start`);
      await delay(25);
    }
  }
  return {adminPort, sipPort, scheme, secret, output: () => output};
}

// Drive the native SRF framing directly so no SDK deduplication can hide the
// second final response or repair the server's dialog-to-application association.
async function application(t, server) {
  const socket = connect(server.adminPort, '127.0.0.1');
  t.after(() => socket.destroy());
  const frames = [];
  let buffer = Buffer.alloc(0);
  socket.on('data', data => {
    buffer = Buffer.concat([buffer, data]);
    for (;;) {
      const boundary = buffer.indexOf('#');
      if (boundary < 0) return;
      const end = boundary + 1 + Number(buffer.subarray(0, boundary).toString());
      if (buffer.length < end) return;
      const raw = buffer.subarray(boundary + 1, end).toString();
      buffer = buffer.subarray(end);
      const split = raw.indexOf('\r\n');
      const metadata = (split < 0 ? raw : raw.slice(0, split)).split('|');
      const message = split < 0 ? '' : raw.slice(split + 2);
      const frame = {metadata, message};
      frames.push(frame);
      if (metadata[1] !== 'sip' || metadata[2] !== 'network' || !/^(INVITE|BYE) /.test(message)) continue;
      const body = message.startsWith('INVITE') ? sdp(header(message, 'CSeq') === '2 INVITE' ? 'recvonly' : 'sendrecv') : '';
      send(`sip|${metadata.at(-3)}|\r\n${sip('SIP/2.0 200 OK', body ? {'Content-Type': 'application/sdp'} : {}, body)}`);
    }
  });
  const send = command => {
    const id = randomUUID();
    const frame = `${id}|${command}`;
    socket.write(`${Buffer.byteLength(frame)}#${frame}`);
    return id;
  };
  await once(socket, 'connect');
  const id = send(`authenticate|${server.secret}`);
  await waitFor(() => frames.find(frame => frame.metadata[1] === 'response' && frame.metadata[2] === id && frame.metadata[3] === 'OK'), 'SRF authentication');
  return {socket, frames, send};
}

async function phone(t, transport) {
  const messages = [];
  const sockets = new Set();
  let socket;
  const accept = connection => {
    socket = connection;
    sockets.add(socket);
    let buffer = Buffer.alloc(0);
    socket.on('data', data => {
      buffer = Buffer.concat([buffer, data]);
      for (;;) {
        const boundary = buffer.indexOf('\r\n\r\n');
        if (boundary < 0) return;
        const length = Number(header(buffer.subarray(0, boundary).toString(), 'Content-Length') || 0);
        const end = boundary + 4 + length;
        if (buffer.length < end) return;
        messages.push(buffer.subarray(0, end).toString());
        buffer = buffer.subarray(end);
      }
    });
  };
  const key = transport === 'tls' ? await readFile(keyFile) : undefined;
  const cert = transport === 'tls' ? await readFile(certFile) : undefined;
  const server = transport === 'tls'
    ? createTlsServer({key, cert}, accept)
    : createServer(accept);
  t.after(async () => {
    for (const connection of sockets) connection.destroy();
    await new Promise(resolve => server.close(resolve));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return {port: server.address().port, messages, send: message => socket.write(message)};
}

async function establish(t, transport, duplicate, disconnected = false) {
  const server = await startServer(t, transport);
  const app = await application(t, server);
  const peer = await phone(t, transport);
  const callId = `duplicate-final-${randomUUID()}`;
  const contact = `<${server.scheme}:102@127.0.0.1:${peer.port};transport=${transport}>`;
  app.send(`sip||\r\n${sip(`INVITE ${contact.slice(1, -1)} SIP/2.0`, {
    From: '<sip:caller@localhost>;tag=fixture-local-tag', To: contact,
    'Call-ID': callId, CSeq: '1 INVITE', 'Content-Type': 'application/sdp'
  }, sdp('sendrecv'))}`);
  const invite = await waitFor(() => peer.messages.find(message => message.startsWith('INVITE ')), 'outbound INVITE');
  const answer = sip('SIP/2.0 200 OK', {
    Via: header(invite, 'Via'), From: header(invite, 'From'),
    To: `${header(invite, 'To')};tag=fixture-phone-tag`,
    'Call-ID': callId, CSeq: '1 INVITE', Contact: contact, 'Content-Type': 'application/sdp'
  }, sdp('sendrecv'));
  // One write sends both identical finals before the application ACK, matching
  // the incident without any dependency on a phone's retransmission timer.
  peer.send(answer.repeat(duplicate ? 2 : 1));
  const final = await waitFor(() => app.frames.find(frame => frame.metadata[2] === 'network' && frame.message.startsWith('SIP/2.0 200 ')), 'application final');
  const dialogId = final.metadata.at(-2);
  assert.ok(dialogId.includes(callId));
  if (disconnected) {
    // Leave the initial INVITE awaiting ACK: after ACK, a duplicate takes the
    // already-cleared IIP path and would not exercise transaction-owner cleanup.
    const closed = once(app.socket, 'close');
    app.socket.destroy();
    await closed;
    await waitFor(() => /ClientController::leave - Removed client.*count of connected clients is now: 0/.test(server.output()), 'application disconnect');
    peer.send(answer);
    await waitFor(() => server.output().includes('route_response_inside_transaction - client managing transaction has disconnected:'),
      'duplicate response cleanup for the disconnected owner');
  } else {
    app.send(`sip||${dialogId}\r\n${sip('ACK sip:placeholder SIP/2.0', {})}`);
    await waitFor(() => peer.messages.find(message => message.startsWith('ACK ')), 'initial ACK');
  }
  const request = async (method, sequence, direction) => {
    const body = direction ? sdp(direction) : '';
    const cseq = `${sequence} ${method}`;
    peer.send(sip(`${method} ${header(invite, 'Contact').replace(/^<|>$/g, '')} SIP/2.0`, {
      Via: `SIP/2.0/${transport.toUpperCase()} 127.0.0.1:${peer.port};branch=z9hG4bK${randomUUID()}`,
      From: `${header(invite, 'To')};tag=fixture-phone-tag`, To: header(invite, 'From'),
      'Call-ID': callId, CSeq: cseq, Contact: contact, 'Max-Forwards': '70',
      ...(body ? {'Content-Type': 'application/sdp'} : {})
    }, body));
    if (method === 'ACK') return;
    return waitFor(() => peer.messages.find(message => /^SIP\/2.0 [2-6]/.test(message) && header(message, 'CSeq') === cseq), `${cseq} final`);
  };
  return {app, request};
}

for (const transport of ['tcp', 'tls']) {
  for (const duplicate of [false, true]) {
    it(`${transport}: ${duplicate ? 'duplicate' : 'single'} INVITE final preserves hold, resume and BYE routing`, {timeout: 15000}, async t => {
      const {app, request} = await establish(t, transport, duplicate);
      const hold = await request('INVITE', 2, 'sendonly');
      assert.match(hold, /^SIP\/2.0 200 /, 'hold must reach the live application');
      assert.match(hold, /\r\na=recvonly\r\n/);
      await request('ACK', 2);
      const resume = await request('INVITE', 3, 'sendrecv');
      assert.match(resume, /^SIP\/2.0 200 /, 'resume must reach the live application');
      assert.match(resume, /\r\na=sendrecv\r\n/);
      await request('ACK', 3);
      const bye = await request('BYE', 4);
      assert.match(bye, /^SIP\/2.0 200 /, 'BYE must reach the live application');
      const incoming = app.frames.filter(frame => frame.metadata[2] === 'network' && /^(INVITE|BYE) /.test(frame.message));
      assert.deepEqual(incoming.map(frame => header(frame.message, 'CSeq')), ['2 INVITE', '3 INVITE', '4 BYE']);
      assert.equal(app.frames.filter(frame => frame.metadata[2] === 'network' && /^CSeq: 1 INVITE\r?$/m.test(frame.message)).length, 1,
        'the completed INVITE final must not be delivered twice');
      // A later request cannot revive the dialog after its real terminal BYE.
      const lateInvite = await request('INVITE', 5, 'sendonly');
      assert.match(lateInvite, /^SIP\/2.0 481 /);
    });
  }
  it(`${transport}: duplicate INVITE final preserves direct BYE routing`, {timeout: 15000}, async t => {
    const {app, request} = await establish(t, transport, true);
    const bye = await request('BYE', 2);
    assert.match(bye, /^SIP\/2.0 200 /);
    assert.equal(app.frames.filter(frame => frame.metadata[2] === 'network' && frame.message.startsWith('BYE ')).length, 1);
  });
  it(`${transport}: duplicate final before ACK does not retain a disconnected application's dialog`, {timeout: 15000}, async t => {
    const {request} = await establish(t, transport, false, true);
    const hold = await request('INVITE', 2, 'sendonly');
    const bye = await request('BYE', 3);
    assert.match(hold, /^SIP\/2.0 481 /);
    assert.match(bye, /^SIP\/2.0 481 /);
  });
}
