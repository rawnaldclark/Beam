// server.js — Entry point: HTTP server + WebSocket upgrade
import { createServer } from 'node:http';
import { WebSocketServer } from 'ws';
import { Gateway } from './gateway.js';
import { Presence } from './presence.js';
import { Signaling } from './signaling.js';
import { DataRelay } from './relay.js';

const PORT = parseInt(process.env.PORT || '8080', 10);

const httpServer = createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
    return;
  }
  res.writeHead(404);
  res.end();
});

const wss = new WebSocketServer({ server: httpServer });
const gateway = new Gateway(wss);

httpServer.listen(PORT, () => {
  console.log(`ZapTransfer relay listening on :${PORT}`);
});

export { httpServer, wss, gateway };
