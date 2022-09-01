import { WebSocket, WebSocketServer } from 'ws';
// import { createServer } from 'http';

// const server = createServer();


const wss = new WebSocketServer({ port: 8080 });

const sendBoardcast = (clients: Set<WebSocket>, data, isBinary: boolean) => {
    clients.forEach(function each(client) {
        if (client.readyState === WebSocket.OPEN) {
            client.send(data, { binary: isBinary });
        }
    })
}
wss.on('connection', function connection(ws,) {

    ws.on('message', function message(data, isBinary) {
        sendBoardcast(wss.clients, data, isBinary)
    });

    ws.send('connection is successful.');

});

// server.listen(8080);