const fs = require('fs');
const net = require('net');
const ini = require('ini');
const Logger = require('./Logger');
const WebSocket = require('ws');
const http = require('http');
//const { exec, execSync } = require('child_process');

//.
const SYS_PROXY_PORT = 18888;
const MOBILE_PROXY_PORT = 18889;
const SYS_WAIT_LISTEN_START = 19000;
const SYS_WAIT_LISTEN_CNT = 500;

//.
const gw_port = 16443;//
//const gw_port = 443;//

const log_level = 1;//
const logFile = "kagent.log";//

const token_string = "_kenan_header_";
const token_end = "_kenan_agent_end_";
const logger = new Logger(log_level, logFile);
let   g_bStartServerEngine = false;
const g_KagentParamFile = 'kagent_param.dat';
const g_MobileParamFile = 'kagent_mobile.dat';
const g_PolicyfilePath = 'policy.dat'; 


let  g_User_ID;
let  g_Machine_ID;
let  g_Company_ID = -1;

let lv_MobileParam;
let lv_MobileInfo_OPT = 0; //. 1 : read, 2 : update
let lv_host_ip = "";
let lv_gw_ip = "";
let lv_global_ip = "";
let lv_session_id = "";
let lv_allow_outbound = 0; //. 1 : allow

function XORCipher(input, key) {
    let output = input; // Start with the input string

    // Perform XOR operation
    for (let i = 0; i < input.length; i++) {
        // XOR with the key, cycling through the key
        output = output.substring(0, i) + 
                 String.fromCharCode(input.charCodeAt(i) ^ key.charCodeAt(i % key.length)) + 
                 output.substring(i + 1);
    }

    return output;
}
function getAgentParam(){
    try {
        if (fs.existsSync(g_KagentParamFile)) {
            // Read encrypted data from a file synchronously
            const data = fs.readFileSync(g_KagentParamFile, 'utf8');

            // Decrypt the data
            const key = "_kenan-agent-Param-2025-01-15_"; // Use the same key used for encryption
            const decrypted = XORCipher(data, key);
            
            const jsonData = JSON.parse(decrypted);
            if (jsonData.sign != "kenan_agent_param") {
                console.error("invalid json data");
                return;
            }
            const {host_ip, gw_ip, global_ip, session_id, outbound} = jsonData;

            lv_host_ip = host_ip;
            lv_gw_ip = gw_ip;
            lv_global_ip = global_ip;
            lv_session_id = session_id;
            lv_allow_outbound = outbound;

            logger.status(`init param :  ${lv_host_ip} , ${lv_gw_ip}, ${lv_global_ip} , ${lv_allow_outbound}`);
        }
        else{
//            logger.error(`fs.existsSync(g_KagentParamFile) :  ${g_KagentParamFile}`);
        }

    } catch (err) {
//        logger.error(`try-catch fs.existsSync(g_KagentParamFile)`);
    }
    //fs.unlinkSync(g_KagentParamFile);
}


//. 
function sendNoHTTPConStatus(listen_port, status) {
	const options = {
	    hostname: "127.0.0.1",
	    port: 18080,
	    path: '/api/set_port_usage',
	    method: 'POST',
	    headers: {
	        'Content-Type': 'application/json',
	        'Connection': 'keep-alive'
	    },
        rejectUnauthorized: false
	};

    const req = http.request(options, (res) => {
        let data = '';
        // Accumulate data chunks
        res.on('data', (chunk) => {
            data += chunk;
        });
        // Process complete response
        res.on('end', () => {
            try {
            } catch (err) {
            }
        });
    });

    req.on('error', (error) => {
    });

    // Create the request body
    let requestBody = JSON.stringify({
        port: listen_port,
        type: status
    });

    let encData = XORCipher(requestBody, "__kenan_enckey_20241114");

    // Write the request body to the request stream
    req.write(encData);
    // End request
    req.end();
}



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

//.
let https_url_list = [];
function upsetURLInfo(hostname, isDirect) {
    const index = https_url_list.findIndex(entry => entry.url_hostname === hostname);
    
    if (index !== -1) {
        https_url_list[index].is_direct = isDirect;
    } else {
        https_url_list.push({ url_hostname: hostname, is_direct: isDirect});
    }
}

function getIsDirectFromURLInfo(full_url) {
    for (let entry of https_url_list) {
        if (full_url.includes(entry.url_hostname)) {
            return entry.is_direct;  // Return the isDirect value as soon as a match is found
        }
    }
    return -1;  // Return null if no hostname contains ".com"
}


function getUtcTime() {
    const now = new Date();
    return now.toISOString(); 
}

function decodeBase64FromFile() {
    try {
        // Read the file content
        const policy_key = "_policy_enckey_kenan250114_"; // Use the same key used for encryption
        const base64Data = XORCipher(fs.readFileSync(g_PolicyfilePath, 'utf8'), policy_key);
        //.
        const decodedData = Buffer.from(base64Data, 'base64').toString('utf8');
        const decodedData_json = JSON.parse(decodedData);
        if (decodedData_json && Object.keys(decodedData_json).length > 0 && g_bStartServerEngine == false) {
            g_bStartServerEngine = true;
            startServer(decodedData_json);
        }
        //. get Moblie Device
        if (decodedData_json && Object.keys(decodedData_json).length > 0 && g_bStartServerEngine == true) {
            decodedData_json.forEach((config) => {
                const {user_id, machine_id, listen_port, is_direct, target, target_port, is_https} = config; // Extract target info
                if(listen_port == 0){
                    lv_MobileParam = config;
                    lv_MobileInfo_OPT = 1;
                }
            });
        }

        //. ????
        //fs.unlinkSync(g_PolicyfilePath);
    } catch (error) {
    }
}

function WSS_StartServer() {
    getAgentParam();
    decodeBase64FromFile();
}
WSS_StartServer();
setInterval(decodeBase64FromFile, 5000);


//.
global.lv_nTotalByte = 0;
global.lv_RealSpeed = 0;
function CalNetSpeed() {
    global.lv_RealSpeed = Math.round(global.lv_nTotalByte * 8 / 30);
    global.lv_nTotalByte = 0;
}

setInterval(CalNetSpeed, 30000);

//. adb , Mobile protocol
function WSS_ConServer_Mobile(){

    let     is_https = 0;
    const server = net.createServer((from) => {
        //. Testing
        //lv_MobileInfo_OPT = 1;
        if(lv_MobileInfo_OPT == 0){
            logger.status(`WSS_ConServer_Mobile Error : lv_MobileInfo_OPT == 0`);
            from.end();
            return;
        }
        
        const {user_id, machine_id, listen_port, is_direct, target, target_port, is_https} = lv_MobileParam;
        // //. Testing
        // let user_id = -1;
        // let machine_id = -1;
        // let target = "2.88.141.30";
        // let target_port = 333;

        policy_url = target;
        policy_port = target_port;

        // Replace net connection with WebSocket connection
        const ws = new WebSocket(`wss://${lv_host_ip}:${gw_port}/gw`, {
            rejectUnauthorized: false,
        });
        let bufferQueue = [];
  
        ws.on('open', () => {
            const utcTime = getUtcTime();
            const header = token_string + `{\"ip\":\"${lv_global_ip}\",\"user_id\":\"${user_id}\",\"machine_id\":\"${machine_id}\",\"listen_port\":\"${MOBILE_PROXY_PORT}\", \"session_id\":\"${lv_session_id}\", \"policy_url\":\"${policy_url}\", \"policy_port\":\"${policy_port}\", \"bps_speed\":\"${global.lv_RealSpeed}\" , \"client_time\":\"${utcTime}\", \"is_https\":\"0\", \"company_id\":\"${g_Company_ID}\"}`;

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

    }).listen(MOBILE_PROXY_PORT, '127.0.1.255', () => {
    });
    // Handle server errors
    server.on('error', (err) => {
    });
}

//. RDP , MySQL protocol
function WSS_ConServer_NO_HTTPS(user_id, machine_id, listen_port, gw_taget_port, policy_url, policy_port, is_direct){

    let     is_https = 0;

    const server = net.createServer((from) => {
        const clientIP = from.remoteAddress;
        const localIP = from.localAddress;
        const clientPort = from.remotePort;

        // Replace net connection with WebSocket connection
        const ws = new WebSocket(`wss://${lv_host_ip}:${gw_taget_port}/gw`, {
            rejectUnauthorized: false,
        });
        let bufferQueue = [];
  
        ws.on('open', () => {
            sendNoHTTPConStatus(listen_port, "add");
            const utcTime = getUtcTime();
            const header = token_string + `{\"ip\":\"${lv_global_ip}\",\"user_id\":\"${user_id}\",\"machine_id\":\"${machine_id}\",\"listen_port\":\"${listen_port}\", \"session_id\":\"${lv_session_id}\", \"policy_url\":\"${policy_url}\", \"policy_port\":\"${policy_port}\", \"bps_speed\":\"${global.lv_RealSpeed}\" , \"client_time\":\"${utcTime}\", \"is_https\":\"${is_https}\", \"company_id\":\"${g_Company_ID}\"}`;
            ws.send(header);
            //Flush any buffered data
            bufferQueue.forEach((message) => {
                ws.send(message);
            });
            bufferQueue = [];  
        });


        // Forward data from client to WebSocket server with header
        from.on('data', (chunk) => {
            global.lv_nTotalByte = global.lv_nTotalByte + chunk.length;
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(chunk);
            } else {
                bufferQueue.push(chunk);
            }
        });

        // Forward data from WebSocket server back to client
        ws.on('message', function message(chunk) {
            global.lv_nTotalByte = global.lv_nTotalByte + chunk.length;
            from.write(chunk); // Write data from WebSocket to client
        });

        // Handle client and WebSocket connection errors
        ws.on('error', (err) => {
            sendNoHTTPConStatus(listen_port, "remove");
            from.end(); // Close client connection on error
        });

        from.on('error', (err) => {
            sendNoHTTPConStatus(listen_port, "remove");
            ws.close(); // Close WebSocket connection on error
        });

        // Handle client disconnection
        from.on('close', () => {
            sendNoHTTPConStatus(listen_port, "remove");
            ws.close();  // Close WebSocket connection
        });

        // Handle WebSocket server disconnection
        ws.on('close', () => {
            sendNoHTTPConStatus(listen_port, "remove");
            from.end();
        });

    }).listen(listen_port, '127.0.1.255', () => {
    });

    // Handle server errors
    server.on('error', (err) => {
    });

}

//. HTTPS Protocol
function WSS_ConServer_IS_HTTPS(user_id, machine_id, listen_port, gw_taget_port, policy_url, policy_port){

    let     is_https = 1;
    let     w_gw_target_port = gw_taget_port;
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

        if(w_is_direct == 0){
            w_gw_target_port = gw_taget_port ;
        }
        else if(w_is_direct == 1){
            w_gw_target_port = gw_taget_port + 1;
        }
        else{
            from.end();
            return;
        }

        policy_url =  getTargetURL(listen_port);
        policy_port =  getTargetPort(listen_port);
        if(policy_port == -1){
            from.end();
            return;
        }

        // Replace net connection with WebSocket connection
        const ws = new WebSocket(`wss://${lv_host_ip}:${w_gw_target_port}/gw`, {
            rejectUnauthorized: false,
        });
        let bufferQueue = [];
  
        ws.on('open', () => {
            //.
            //logger.status(`WSS_ConServer_IS_HTTPS :  ${lv_host_ip}:${w_gw_target_port}`);

            const utcTime = getUtcTime();
            const header = token_string + `{\"ip\":\"${lv_global_ip}\",\"user_id\":\"${user_id}\",\"machine_id\":\"${machine_id}\",\"listen_port\":\"${listen_port}\", \"session_id\":\"${lv_session_id}\", \"policy_url\":\"${policy_url}\", \"policy_port\":\"${policy_port}\", \"bps_speed\":\"${global.lv_RealSpeed}\" , \"client_time\":\"${utcTime}\", \"is_https\":\"${is_https}\", \"company_id\":\"${g_Company_ID}\"}`;

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
            // let cated = Buffer.concat([bufTemp, chunk]);

            global.lv_nTotalByte = global.lv_nTotalByte + chunk.length;
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(chunk);
            } else {
                bufferQueue.push(chunk);
            }
        });

        // Forward data from WebSocket server back to client
        ws.on('message', function message(chunk) {
            global.lv_nTotalByte = global.lv_nTotalByte + chunk.length;
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

    }).listen(listen_port, '127.0.1.255', () => {
        //logger.status(`VM Agent started on port ${listen_port}`);
    });

    // Handle server errors
    server.on('error', (err) => {
        //logger.error(`VM Agent error on port ${listen_port}:`, err.message);
    });

}

//. router server 
function startServer(policyData) {

    // Loop through each routing rule in the policy
    policyData.forEach((config) => {
        const {user_id, machine_id, listen_port, company_id, is_direct, target, target_port, is_https} = config; // Extract target info

        if(listen_port > 0){
            //.
            if(is_direct == 0 && is_https == 0){
                WSS_ConServer_NO_HTTPS(user_id, machine_id, listen_port , gw_port, target, target_port, is_direct);
            }
            if(is_direct == 1 && is_https == 0){
                WSS_ConServer_NO_HTTPS(user_id, machine_id, listen_port , gw_port + 1, target, target_port, is_direct);
            }
            
            g_User_ID = user_id;
            g_Machine_ID = machine_id;
            g_Company_ID = company_id;

            //. Add URL, is_direct information
            if(is_https == 1){
                upsetURLInfo(target, is_direct);
                logger.status(`upsetURLInfo  is_https == 1 ${target} , ${is_direct}`);
            }
        }
    });
    
    //. For System Proxy
    for (let i = SYS_WAIT_LISTEN_START; i < SYS_WAIT_LISTEN_START + SYS_WAIT_LISTEN_CNT; i++) {
        WSS_ConServer_IS_HTTPS(g_User_ID, g_Machine_ID, i , gw_port, "my_test.com", 11111);
  	}
    
    //. 
    WSS_ConServer_Mobile();

}

///////////////////////////////////////////////////////////////////////////////////
// Create the HTTP proxy server
const sys_proxy_server = http.createServer((req, res) => {
    const clientAddress = req.socket.remoteAddress;
    const clientPort = req.socket.remotePort;
});

// Handle CONNECT requests for HTTPS tunneling
sys_proxy_server.on('connect', (req, clientSocket, head) => {
    const clientAddress = clientSocket.remoteAddress;
    const clientPort = clientSocket.remotePort;

    const [hostname, port] = req.url.split(':');
    // check is_direct option
    let  w_ret = getIsDirectFromURLInfo(hostname);
    if(w_ret == -1){
        //. security policy
        if(lv_allow_outbound != 1){
            clientSocket.end(`HTTP/1.1 403 Forbidden\r\n\r\n`);
            return;
        }
        //. allow
        else{
            const serverSocket = net.connect(port || 443, hostname, () => {
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

            serverSocket.on('error', (err) => {
                clientSocket.end(`HTTP/1.1 500 Internal serverSocket Error\r\n\r\n`);
                serverSocket.end();
            });
        
            clientSocket.on('error', (err) => {
                clientSocket.end(`HTTP/1.1 500 Internal clientSocket Error\r\n\r\n`);
                serverSocket.end();
            });
        
            serverSocket.on('close', () => {
                clientSocket.end(`HTTP/1.1 500 Internal serverSocket close\r\n\r\n`);
                serverSocket.end();
            });
        
            clientSocket.on('close', (err) => {
                clientSocket.end(`HTTP/1.1 500 Internal clientSocket close\r\n\r\n`);
                serverSocket.end();
            });

            return;
        }
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
    if(my_listen_port == -1){
        clientSocket.end(`HTTP/1.1 403 Forbidden\r\n\r\n`);
        return;        
    } 
    if(!(my_is_direct == 0 || my_is_direct == 1)){
        clientSocket.end(`HTTP/1.1 403 Forbidden\r\n\r\n`);
        return;        
    }   

    target_port = port || 443;
    upsetHttpsCon(my_listen_port, hostname, target_port, my_is_direct);

    //logger.status(`upsetHttpsCon :  ${my_listen_port},   ${hostname}`);

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
sys_proxy_server.listen(SYS_PROXY_PORT, '127.0.0.1', () => {
});
