const fs = require('fs');
const net = require('net');
const ini = require('ini'); // Import the ini package
const Logger = require('./Logger');
const WebSocket = require('ws');
const https = require('https');
const { v4: uuidv4 } = require('uuid');
//const { exec, execSync } = require('child_process');

// Read config.ini file
const config = ini.parse(fs.readFileSync('config_gw.ini', 'utf-8'));
const server_ip = config.settings.server; // Get router server from config
const in_server_ip = config.settings.in_server; // 
const listen_port = config.settings.listen_port;
const router_port = config.settings.router_port;
const log_level = config.settings.logLevel;
const logFile = config.settings.logFile;

const token_string = "_kenan_header_"; //. Normal TCP router
const endToken_string = "_kenan_header_end_"; //. 
const kconnect_init_string = "_kenan_connect_init_"; //. 
const logger = new Logger(log_level, logFile);
const loopback_policy_port = 43210;


let lv_companies_list = [];

function getConnectIP(id) {
    const entry = lv_companies_list.find(entry => entry.id == id);
    if (entry) {
        return entry.connect_ip;
    } else {
        return -1;
    }
}

function checkConnectInfo(id, token) {
    let     status = -1;

    const entry = lv_companies_list.find(entry => entry.id == id);
    if (entry) {
        if(entry.connect_token == token){
            status = 1;
        }
    } else {
    }
    return status;
}


function LoopBackGetPolicyServer() {
    const server = net.createServer((from) => {
        const clientIP = from.remoteAddress;
        const localIP = from.localAddress;
        const clientPort = from.remotePort;

        //. 
        if(clientIP == localIP){
        }
        else{
            from.end(); 
            return;
        }
        // Replace net connection with WebSocket connection
        const ws = new WebSocket(`wss://${server_ip}:${router_port}`, {
            rejectUnauthorized: false,
        });
        let bufferQueue = [];
  
        ws.on('open', () => {
            const header = token_string + `{\"ip\":\"${clientIP}\",\"user_id\":\"-1\",\"machine_id\":\"-1\",\"listen_port\":\"${loopback_policy_port}\", \"session_id\":\"-1\"}`;
            ws.send(header);
            //Flush any buffered data
            bufferQueue.forEach((message) => {
                ws.send(message);
            });
            bufferQueue = [];  
        });

        // Forward data from client to WebSocket server with header
        from.on('data', (chunk) => {
            // const bufTemp = Buffer.from(token_string);
            // const cated = Buffer.concat([bufTemp, chunk]);
            //const cated = chunk;
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(chunk);
            } else {
                bufferQueue.push(chunk);
            }
            
        });

        // Forward data from WebSocket server back to client
        ws.on('message', function message(chunk) {
            from.write(chunk); // Write data from WebSocket to client
        });

        // Handle client and WebSocket connection errors
        ws.on('error', (err) => {
            from.end(); // Close client connection on error
        });

        from.on('error', (err) => {
            ws.close(); // Close WebSocket connection on error
        });

        // Handle client disconnection
        from.on('close', () => {
            ws.close();  // Close WebSocket connection
        });

        // Handle WebSocket server disconnection
        ws.on('close', () => {
            from.end();
        });

    }).listen(loopback_policy_port, '127.0.0.1', () => {
        logger.status(`Client started on port ${listen_port}`);
    });

    // Handle server errors
    server.on('error', (err) => {
        //logger.error(`Client error on port ${listen_port}:`, err.message);
    });
}


function ProxyEngine(target, target_port, ws, left, client_realIp){

    let messageQueue = [];  
    let isRouterReady = false;

    if (!target || target === "null") {
        ws.close();
        return;
    }

    const routerWS = new WebSocket(`wss://${target}:${target_port}`, {
        // headers: {
        //     'X-Real-IP': client_realIp  //
        // },
        rejectUnauthorized: false,
    });
    //. 
    if(left){
        messageQueue.push(left);
    }
    //. 
    routerWS.on('open', () => {
        isRouterReady = true;
        // Send any buffered messages
        while (messageQueue.length > 0) {
            routerWS.send(messageQueue.shift());
        }
    });
    //.
    ws.on('message', (message) => {
        if (isRouterReady) {
            routerWS.send(message);  // Send directly if ready
        } else {
            messageQueue.push(message);  // Buffer messages if not ready
        }
    });
    //.
    routerWS.on('message', (data) => {
        ws.send(data);  // Send data back to the client
    });

    ws.on('error', (err) => {
        routerWS.close();
    });

    ws.on('close', () => {
        routerWS.close();
    });

    routerWS.on('error', (err) => {
        ws.close();
    });

    routerWS.on('close', () => {
        ws.close();
    });
}
let lv_kconnect_ws_list = [];
function upsetKConnect_WS(company_id, kconnect_ws) {
    const index = lv_kconnect_ws_list.findIndex(entry => entry.company_id == company_id);

    if (index !== -1) {
        console.log(`upsetKConnect_WS update : ${company_id}:`);
        lv_kconnect_ws_list[index].kconnect_ws = kconnect_ws;
    }
    else{
        console.log(`upsetKConnect_WS push : ${company_id}:`);
        lv_kconnect_ws_list.push({ company_id: company_id, kconnect_ws: kconnect_ws });
    }
}

function getKConnect_WS(company_id) {
    const index = lv_kconnect_ws_list.findIndex(entry => entry.company_id == company_id);
  
    if (index !== -1) {
        //lv_kconnect_ws_list[index].status = 1;
        return lv_kconnect_ws_list[index].kconnect_ws
    } else {
        return null;
    }
}
function deleteIDKConnect_WS(company_id) {
    // Remove all entries from lv_kconnect_ws_list 
    lv_kconnect_ws_list = lv_kconnect_ws_list.filter(entry => entry.company_id != company_id);
}

//let lv_clients = new Map();  // 
let lv_clients_ws_list = [];
function upsetKAgent_WS(clientId, company_id, kagent_ws) {
    const index = lv_clients_ws_list.findIndex(entry => entry.clientId == clientId && entry.company_id == company_id);

    if (index !== -1) {
        lv_clients_ws_list[index].kagent_ws = kagent_ws;
    }
    else{
        lv_clients_ws_list.push({ clientId: clientId, company_id: company_id, kagent_ws:kagent_ws});
    }
}
function getKAgent_WS(clientId, company_id) {
    const index = lv_clients_ws_list.findIndex(entry => entry.clientId == clientId && entry.company_id == company_id);
  
    if (index !== -1) {
        //lv_kconnect_ws_list[index].status = 1;
        return lv_clients_ws_list[index].kagent_ws
    } else {
        return null;
    }
}

function deleteIDKAgent_WS(clientId, company_id) {
    // Remove all entries from lv_kconnect_ws_list 
    lv_clients_ws_list = lv_clients_ws_list.filter(entry => !(entry.clientId == clientId && entry.company_id == company_id));
}


function deleteAllKAgent_WS(company_id) {
    // Remove all entries from lv_kconnect_ws_list 
    lv_clients_ws_list = lv_clients_ws_list.filter(entry => entry.company_id != company_id);
}

function closeEventFromKConnect(company_id, kconect_ws)
{
    kconect_ws.on('message', async(message) => {
        const { clientId, payload } = JSON.parse(message.toString());

        let msg_payload = payload.toString();
        const binaryPayload = Buffer.from(payload, 'base64'); // Convert back to Buffer
        const client = getKAgent_WS(clientId, company_id);
        if(msg_payload.includes("_kenan_socket_ping_")){
            const send_message = {clientId : "_kenan_connect_testID__",  payload: "_kenan_socket_ping_"};
            kconect_ws.send((JSON.stringify(send_message)));
        }
        else if (client && client.readyState === WebSocket.OPEN) {
            try {
                if (msg_payload.includes("_kenan_socket_close_")) {
                    //console.log(`_kenan_socket_close_ ---  `);
                    client.close();
                }
                else{
                    client.send(binaryPayload);
                }
            
            } catch (error) {
                //console.log(`111 Failed to send to ${clientId}:`);
                client.close();
                deleteIDKAgent_WS(clientId, company_id);
            }
        } else {
            deleteIDKAgent_WS(clientId, company_id);
            // client.close();
            //console.log(`222 Failed to send to ${clientId}:`);
        }
    });

    kconect_ws.on('error', (err) => {
        console.log(`kconect_ws error ---  ${company_id}, ${err.message}`);
        //. Delete {company_id, kconnect_ws}
        deleteIDKConnect_WS(company_id, kconect_ws);
        kconect_ws.close();
    });

    kconect_ws.on('close', () => {
        console.log(`kconect_ws close ---   ${company_id}  `);
        deleteIDKConnect_WS(company_id, kconect_ws);
        kconect_ws.close();
        deleteAllKAgent_WS(company_id);
    });

}

function ProcDataFromKAgent(company_id, listen_port, kagent_ws, left_msg){

    //let     w_nKconnect_traff_cnt = 0;

    if(company_id < 0){
        kagent_ws.close();
        return;
    }
    //. 
    let w_kconnect_ws = getKConnect_WS(company_id);
    if(w_kconnect_ws == null){
        console.log(`ProcDataFromKAgent getKConnect_WS == null ---  ${company_id} , ${listen_port}`);
        kagent_ws.close();
        deleteAllKAgent_WS(company_id);
        return;
    }
    const clientId = uuidv4();
    upsetKAgent_WS(clientId, company_id, kagent_ws);

    //console.log(`ProcDataFromKAgent Start ---  ${company_id} , ${listen_port}`);

    if(left_msg){
        const send_message = {
            clientId,
            payload: left_msg
          };
        w_kconnect_ws.send((JSON.stringify(send_message)));
    }

    //.
    kagent_ws.on('message', async(message) => {
        if (w_kconnect_ws && w_kconnect_ws.readyState == WebSocket.OPEN) {
            //w_nKconnect_traff_cnt = w_nKconnect_traff_cnt + 1;
            // if(w_nKconnect_traff_cnt > 1){
                const send_message = {
                    clientId,
                    payload: message.toString('base64')
                };
                w_kconnect_ws.send((JSON.stringify(send_message)));
            // }
            // else{
                // w_kconnect_ws.ping((err) => {
                //     if (err) {
                //         console.log(`ProcDataFromKAgent w_kconnect_ws.ping error : ${err.message}`);
                //         kagent_ws.close();
                //         deleteIDKAgent_WS(clientId, company_id);
                //         deleteIDKConnect_WS(company_id, w_kconnect_ws);
                //         w_kconnect_ws.close();
                //     } else {
                //         //. OK
                //         const send_message = {
                //             clientId,
                //             payload: message.toString('base64')
                //         };
                //         w_kconnect_ws.send(JSON.stringify(send_message));
                //     }
                // });
            //}
        }
        else{
            console.log(`---------- kagent_ws.on message w_kconnect_ws == null ---  ${company_id} , ${listen_port}`);
            kagent_ws.close();
            deleteIDKAgent_WS(clientId, company_id);

            //.
        }
    });

    //.
    kagent_ws.on('error', (err) => {
        console.log(`ProcDataFromKAgent kagent_ws error ... ${err.message}`);
        kagent_ws.close();
    });

    kagent_ws.on('close', () => {
        kagent_ws.close();
        deleteIDKAgent_WS(clientId, company_id);
    });

}

function startMainServer() {

    // Load SSL certificates
    const serverOptions = {
        key: fs.readFileSync('certs/kenan-gw-wss.key'),   // Path to your private key file
        cert: fs.readFileSync('certs/kenan-gw-wss.crt'),  // Path to your certificate file
    };

    // Create an HTTPS server with SSL options
    const httpsServer = https.createServer(serverOptions);

    // Attach the WebSocket server to the HTTPS server
    const wss = new WebSocket.Server({ server: httpsServer });

    httpsServer.listen(listen_port, () => {
        logger.status(`WebSocket server started on port ${listen_port}`);
    });

    wss.on('connection', (ws, req) => {
        const clientIP = req.socket.remoteAddress;
        const clientPort = req.socket.remotePort;

        let client_realIp = "";
        client_realIp = req.headers['x-real-ip'] || "";
        //console.log(`client_realIp : ${client_realIp}`);

        if(clientIP.trim().includes(in_server_ip)){
        }
        else{
            ws.close(); 
            return;
        }
        ws.once('message', (message) => {
            message=message.toString();

            const regex = /_kenan_header_(\{.*?\})/; // Regex to capture the JSON object part
            const matchJson = message.match(regex);
            let left = null;
            let company_id = -1;
            let company_token = "";
            let kconnect_init = "";
            let extractedPort = null;

            if (matchJson && matchJson[1]) {
                const parsedData = JSON.parse(matchJson[1]);
                extractedPort = parsedData.listen_port; 

                if ('company_id' in parsedData) {
                    company_id = parsedData.company_id;
                } else {
                    company_id = -1;
                }
                company_id = parseInt(company_id, 10)
                //. 
                if ('company_token' in parsedData) {
                    company_token = parsedData.company_token;
                } else {
                    company_token = "";
                }
                if ('kconnect_init' in parsedData) {
                    kconnect_init = parsedData.kconnect_init;
                } else {
                    kconnect_init = "";
                }

                left = message;

            } else {
                ws.close(); // Close connection if parsing fails
                return;
            }

            //. check packet type
            //. connect from launcher to tcp router
            if(/*extractedPort == 43210 && */company_id == -111){
                //console.log(`connect from launcher to tcp router company_id == -111`);
                ProxyEngine(server_ip, router_port, ws, left, client_realIp);
            }
            //. from kagent to kenan_connector
            else if(company_id > 0 && company_token == ""){
                console.log(`from kagent to kenan_connector company_id = ${company_id} company_token = ${company_token}`);
                if(extractedPort == "18889"){
                    console.log(`extractedPort == 18889 to tcp router ${company_id}`);
                    ProxyEngine(server_ip, router_port, ws, left, client_realIp);
                }
                else{
                    let  connect_ip = getConnectIP(company_id);
                    if(connect_ip == -1){
                        ws.close(); 
                        return;
                    }
                    else{
                        //. check IP    
    
    
    
                        //. proc data from kagent
                        ProcDataFromKAgent(company_id, extractedPort, ws, left);
                    }
                }
            }
            //. kconnect -> GW
            else if(company_id > 0 && company_token != ""){
                let status = checkConnectInfo(company_id, company_token);
                if(status == 1){
                    //. 
                    let  connect_ip = getConnectIP(company_id);
                    if(connect_ip == -1){
                        console.log(`kconnect -> GW getConnectIP == -1 , ${company_id}`);
                        ws.close(); 
                        return;
                    }
                    if(client_realIp != connect_ip){
                        console.log(`kconnect -> GW client_realIp != connect_ip , ${client_realIp}, ${connect_ip}`);
                        ws.close(); 
                        return;
                    }
                    //. 
                    if(kconnect_init == kconnect_init_string){
                        // if( getKConnect_WS(company_id) == null){
                            console.log(`kconnect -> GW kconnect_init ${company_id} , ${company_token}`);
                            //. registe input ws to {company_id, kconnect_ws}
                            upsetKConnect_WS(company_id, ws);
                            //. proc for close event from kconnect
                            closeEventFromKConnect(company_id, ws);
                        // }
                        // else{
                        //     ws.close(); 
                        //     return;
                        // }
                    }
                    else{
                        //console.log(`kconnect -> GW ProxyEngine ${company_id} , ${company_token}`);
                        ProxyEngine(server_ip, router_port, ws, left, client_realIp);
                    }
                }
                else{
                    console.log(`kconnect -> GW checkConnectInfo == 0  ${company_id} , ${company_token}`);
                    ws.close(); 
                    return;
                }
            }
            else{
                ws.close(); // Close connection if parsing fails
                return;
            }

        });
    });

    wss.on('error', (err) => {
        logger.error(`WebSocket server error on port ${listen_port}:`, err.message);
    });
   
}

//. 
function getGWPolicyFromServer() {
	const options = {
	    hostname: "127.0.0.1",
	    port: 43210,
	    path: '/api/network/gw-rules',
	    method: 'POST',
	    headers: {
	        'Content-Type': 'application/json',
	        'Connection': 'keep-alive'
	    },
        rejectUnauthorized: false
	};

    const req = https.request(options, (res) => {
        let data = '';
        // Accumulate data chunks
        res.on('data', (chunk) => {
            data += chunk;
        });

        // Process complete response
        res.on('end', () => {
            try {
                const responseJsonData = JSON.parse(data);
                // Start the proxy server for each active configuration
                lv_companies_list = responseJsonData.data.companies;
 //               console.log(lv_companies_list);

            } catch (err) {
                // logger.error(`Failed to parse response from ${policy_url}:${policy_port}`);
                // logger.debug(policy_data.toString());
            }
        });
    });

    req.on('error', (error) => {
        //logger.error(`Request error from ${policy_url}:${policy_port} : `, error.message);
    });

    // End request
    req.end();
}

//. Main
LoopBackGetPolicyServer();
getGWPolicyFromServer();
setInterval(getGWPolicyFromServer, 10000);
//. 
startMainServer();
