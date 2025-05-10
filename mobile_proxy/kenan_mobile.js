const fs = require('fs');
const net = require('net');
const ini = require('ini');
const Logger = require('./Logger');
const WebSocket = require('ws');
const http = require('http');
const https = require('https');

//.
//const SYS_PROXY_PORT = 18888;
const SYS_WAIT_LISTEN_START = 19000;
const SYS_WAIT_LISTEN_CNT = 1000;

//.
const config = ini.parse(fs.readFileSync('config_mobile.ini', 'utf-8'));
const router_ip = config.settings.router_server; // Get router server from config
const router_port = config.settings.router_port;

const log_level = config.settings.logLevel;
const logFile = config.settings.logFile;

const token_string = "_kenan_header_";
const logger = new Logger(log_level, logFile);
const loopback_policy_port = 43210;




let https_port_list = [];
function upsetHttpsCon(listenport, targethost, targetport, isDirect) {
    const index = https_port_list.findIndex(entry => entry.listen_port === listenport);
    
    if (index !== -1) {
        https_port_list[index].target_url = targethost;
        https_port_list[index].target_port = targetport;
        https_port_list[index].is_direct = isDirect;
    } else {
        https_port_list.push({ listen_port: listenport, target_url: targethost , target_port: targetport, is_direct: isDirect});
    }
}

function getTargetURL(listenport) {
    const entry = https_port_list.find(entry => entry.listen_port === listenport);
    if (entry) {
        return entry.target_url;
    } else {
        return "-1";
    }
}

function getTargetPort(listenport) {
    const entry = https_port_list.find(entry => entry.listen_port === listenport);
    if (entry) {
        return entry.target_port;
    } else {
        return -1;
    }
}

function getIsDirect(listenport) {
    const entry = https_port_list.find(entry => entry.listen_port === listenport);
    if (entry) {
        return entry.is_direct;
    } else {
        return -1;
    }
}
function DeletId(listenport) {
    // Remove all entries from https_port_list where user_id matches the provided userId
    https_port_list = https_port_list.filter(entry => entry.listen_port !== listenport);
}

let lv_sys_proxy_list = [];
//. moblie device list from Admin Server
let lv_mobile_devices_list = [];
//. 
function getIsDirectFromURLInfo(proxy_port, full_url) {
    for (let mobile_device_item of lv_mobile_devices_list) {
        if(mobile_device_item.proxy_port != proxy_port){
            continue;
        }
        //. 
        for (let mobile_device_port_item of mobile_device_item.ports) {
            if (full_url.includes(mobile_device_port_item.target)) {
                console.log(`getIsDirectFromURLInfo -- ok ${full_url},  ${mobile_device_port_item.target}`);
                return 0; //mobile_device_port_item.is_direct;  
            }        
        }

    }
    console.log(`getIsDirectFromURLInfo -- faild ${full_url}`);
    return -1;  // Return null if no hostname contains ".com"
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
        const ws = new WebSocket(`wss://${router_ip}:${router_port}`, {
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
        //logger.status(`Client started on port ${listen_port}`);
    });

    // Handle server errors
    server.on('error', (err) => {
        //logger.error(`Client error on port ${listen_port}:`, err.message);
    });
}


//. 
function getMobilePolicyFromServer() {
	const options = {
	    hostname: "127.0.0.1",
	    port: 43210,
	    //hostname: "192.168.149.201",
	    //port: 8000,

        path: '/api/network/mobile-rules',
	    method: 'POST',
	    headers: {
	        'Content-Type': 'application/json',
	        'Connection': 'keep-alive'
	    },
        rejectUnauthorized: false
	};

    //const req = http.request(options, (res) => {
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
                if(responseJsonData.status == 200){
                    lv_mobile_devices_list = responseJsonData.data.mobile_devices;
                    array_cnt = lv_mobile_devices_list.length;
                    console.log(lv_mobile_devices_list);
                    console.log(`mobile_devices items count ${array_cnt}`);
                    for (let i = 0; i < lv_mobile_devices_list.length; i++) {
                        console.log(`mobile_devices ${i}:`, lv_mobile_devices_list[i].ports);
                    }
                    CheckSysMobileProxy();
                }
                else{
                }

            } catch (err) {
            }
        });
    });

    req.on('error', (error) => {
//        console.log(`Request error getMobilePolicyFromServer : `, error.message);
    });
    // End request
    req.end();
}

function CheckSysMobileProxy(){
    //.
    // Iterate over a copy of the lv_sys_proxy_list to avoid mutation issues
    for (let i = lv_sys_proxy_list.length - 1; i >= 0; i--) {
        const entry = lv_sys_proxy_list[i];
        const run_proxy_port = entry.proxy_port;
        let bFind = false;

        // Check if the proxy port is in the mobile devices list
        for (let mobile_device_item of lv_mobile_devices_list) {
            if (mobile_device_item.proxy_port === run_proxy_port) {
                bFind = true;
                break;
            }
        }

        // If not found, close the proxy server and remove the entry
        if (!bFind) {
            entry.sys_proxy_server.close((err) => {
                if (err) {
//                    console.log(`Error closing server on port ${run_proxy_port}: ${err.message}`);
                } else {
                    console.log(`------ Server on port ${run_proxy_port} closed.`);
                }
            });
            lv_sys_proxy_list.splice(i, 1);
        }
    }
    //. 
    for (let i = lv_mobile_devices_list.length - 1; i >= 0; i--) {
        const entry = lv_mobile_devices_list[i];
        const policy_proxy_port = entry.proxy_port;
        let bFind = false;

        for (let sys_proxy_item of lv_sys_proxy_list) {
            if (sys_proxy_item.proxy_port === policy_proxy_port) {
                bFind = true;
                break;
            }
        }
        
        if (!bFind) {
            StartSysMobileProxy(policy_proxy_port);
        }
    }

    return;
}

//.
function StartSysMobileProxy(proxy_port){

    let sys_proxy_server = http.createServer((req, res) => {
        const clientAddress = req.socket.remoteAddress;
        const clientPort = req.socket.remotePort;
    });
    
    // Handle CONNECT requests for HTTPS tunneling
    sys_proxy_server.on('connect', (req, clientSocket, head) => {
        const clientAddress = clientSocket.remoteAddress;
        const clientPort = clientSocket.remotePort;
    
        const [hostname, port] = req.url.split(':');
        // check is_direct option
        let  w_ret = getIsDirectFromURLInfo(proxy_port, hostname);
        if(w_ret == -1){
            clientSocket.end(`HTTP/1.1 403 Forbidden\r\n\r\n`);
            return;
        }
    
        let  my_is_direct = w_ret; //. 0 : to router
        //////////////////////////////////////////////////////////////////
        let 	my_listen_port = -1;
        let 	target_port;
        
        for (let i = SYS_WAIT_LISTEN_START; i < SYS_WAIT_LISTEN_START + SYS_WAIT_LISTEN_CNT; i++) {
            //. new listen port
            if(getTargetURL(i) == "-1"){
                my_listen_port = i;
                break;
            }
        }
        //. 
        if(my_listen_port == -1 || !(my_is_direct == 0 || my_is_direct == 1)){
            clientSocket.end(`HTTP/1.1 403 Forbidden\r\n\r\n`);
            return;        
        } 
        
        target_port = port || 443;
        upsetHttpsCon(my_listen_port, hostname, target_port, my_is_direct);
        /////////////////////////////////////////////////////////////////////
        const serverSocket = net.connect(my_listen_port, "127.0.1.255", () => {
            // Respond to the client indicating the tunnel is established
            clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        });
        
        // serverSocket.on('data', (data) => {
        //     clientSocket.write(data); 
        // });
        
        // clientSocket.on('data', (data) => {
        //     serverSocket.write(data); 
        // });
        serverSocket.pipe(clientSocket);
        clientSocket.pipe(serverSocket);
    
        // Error handling
        serverSocket.on('error', (err) => {
            clientSocket.end(`HTTP/1.1 500 Internal serverSocket Error\r\n\r\n`);
            DeletId(my_listen_port);
        });

        clientSocket.on('error', (err) => {
            clientSocket.end(`HTTP/1.1 500 Internal clientSocket Error\r\n\r\n`);
            DeletId(my_listen_port);
        });

        serverSocket.on('close', () => {
            clientSocket.end(`HTTP/1.1 500 Internal serverSocket close\r\n\r\n`);
            DeletId(my_listen_port);
        });

        clientSocket.on('close', () => {
            serverSocket.end();
            DeletId(my_listen_port);
        });
        
    });
    
    // Start the proxy server
    sys_proxy_server.listen(proxy_port, '0.0.0.0', () => {
        console.log(`--- StartSysMobileProxy : ${proxy_port}`);
    });

    lv_sys_proxy_list.push({sys_proxy_server: sys_proxy_server, proxy_port: proxy_port});
}

//. HTTPS Protocol
function Proxy_ConServer_IS_HTTPS(listen_port, policy_url, policy_port){

    let     w_URL = null;

    const server = net.createServer((from) => {
        const clientIP = from.remoteAddress;
        const localIP = from.localAddress;
        const clientPort = from.remotePort;

        //. 
        w_is_direct = getIsDirect(listen_port);
        w_URL = getTargetURL(listen_port);
        if(w_URL == "-1"){
            from.end();
            return;
        }

        policy_url =  getTargetURL(listen_port);
        policy_port =  getTargetPort(listen_port);
        if(policy_port == -1){
            from.end();
            return;
        }

        //console.log(`Proxy_ConServer_IS_HTTPS : ${policy_url}, ${policy_port}`);
        // Create a TCP connection to the target server
        const targetSocket = net.createConnection({
            host: policy_url,
            port: policy_port
        }, () => {
        });

        // // Forward data from client to WebSocket server with header
        // from.on('data', (chunk) => {
        //     targetSocket.write(chunk);
        // });

        // // Forward data from WebSocket server back to client
        // targetSocket.on('data', (chunk) => {
        //     from.write(chunk);
        // });
        from.pipe(targetSocket);
        targetSocket.pipe(from);

        // Handle client and WebSocket connection errors
        targetSocket.on('error', (err) => {
            from.end(); // Close client connection on error
        });
        // Handle WebSocket server disconnection
        targetSocket.on('close', () => {
            from.end();
        });

        from.on('error', (err) => {
            targetSocket.end();
        });

        // Handle client disconnection
        from.on('close', () => {
            targetSocket.end();
        });



    }).listen(listen_port, '127.0.1.255', () => {
        //logger.status(`VM Agent started on port ${listen_port}`);
    });

    // Handle server errors
    server.on('error', (err) => {
        //logger.error(`VM Agent error on port ${listen_port}:`, err.message);
    });

}

//. main
//. For System Proxy
for (let i = SYS_WAIT_LISTEN_START; i < SYS_WAIT_LISTEN_START + SYS_WAIT_LISTEN_CNT; i++) {
    Proxy_ConServer_IS_HTTPS( i , "my_test.com", 11111);
}


//. Main
LoopBackGetPolicyServer();
getMobilePolicyFromServer();
setInterval(getMobilePolicyFromServer, 10000);