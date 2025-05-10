
const net = require('net');
const ini = require('ini'); // Import the ini package
const fs = require('fs'); // Required to read the config file
const replace = require('buffer-replace'); // Required to read the config file
const Logger = require('./Logger');
const WebSocket = require('ws');
const https = require('https');
const http = require('http');
const { exec, execSync } = require('child_process');
const SSHMng = require('./SSHMng');
const WinRMMng = require('./WinRMMng');
const { generateSecurePassword, parseUserName, generateUserName } = require('./Util.js');


const config = ini.parse(fs.readFileSync('config_connect.ini', 'utf-8'));
const gw_server_ip = config.settings.gw_server; // Get router server from config
const private_listen_port = config.settings.private_listen_port;
const gw_port = config.settings.gw_port;
const log_level = config.settings.logLevel;
const logFile = config.settings.logFile;
//const admin_server_ip = config.settings.admin_server;
const admin_port = 8443;//config.settings.admin_port;
let lv_company_id = -111;
let lv_company_token = config.settings.company_token;
let lv_company_access_token = "";
let lv_company_is_valid = false;
let lv_private_ip = null;

const token_string = "_kenan_header_"; //. Normal TCP router
const endToken_string = "_kenan_header_end_"; //. 
const kconnect_init_string = "_kenan_connect_init_"; //. 
const logger = new Logger(log_level, logFile);
const loopback_policy_port = 43210;

let lv_policy_data = [];
let lv_credential_user_list = [];
let lv_get_credential_users_ok = false;
let lv_con_server_user_list = [];
let lv_global_ip = "";
const LOOP_SKIP_CNT = 100;
const PING_PONG_TIME_OUT = 2000;
//const MAX_GW_WS_CNT = 300;
let   lv_gw_ws_cnt = 0;
let   LOOP_INIT_KCONNET_WS_TIME = 1000;
let lv_GW_Cert_OK = false;


const certpath = 'certs/gw.crt';
const ssl_command = `openssl x509 -noout -in ${certpath} -fingerprint -sha256`;
const generate_SHA256_fingerprint = () => {
    try {
      const stdout = execSync(ssl_command); 
      return stdout.toString().split('=')[1].trim(); 
    } catch (error) {
      throw new Error('Error executing OpenSSL command: ' + error.message);
    }
};
const g_gwCert256 = generate_SHA256_fingerprint();

function getUtcTime() {
    const now = new Date();
    return now.toISOString(); 
}
//. 
// function getGlobalIP() {
//     return new Promise((resolve, reject) => {
//         https.get('https://api.ipify.org?format=json', (resp) => {
//             let data = '';

//             resp.on('data', (chunk) => {
//                 data += chunk;
//             });

//             resp.on('end', () => {
//                 try {
//                     const jsonResponse = JSON.parse(data);
//                     const lv_global_ip = jsonResponse.ip;
//                     resolve(lv_global_ip); // Resolve the promise with the IP
//                 } catch (error) {
//                     reject(error); // Reject the promise on error
//                 }
//             });
//         }).on("error", (err) => {
//             reject(err); // Reject the promise on request error
//         });
//     });
// }

function getListenPortFromURLInfo(full_url) {
    try {
        for (let entry of lv_policy_data) {
            if (full_url.includes(entry.target)) {
                return entry.listen_port;  //
            }
        }
        return -1;  
    } catch (err) {
        return -1;  
    }
}
//.
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
        const ws = new WebSocket(`wss://${gw_server_ip}:${gw_port}/gw`, {
            rejectUnauthorized: false,
        });
        let bufferQueue = [];
  
        ws.on('open', () => {
            //.
            if(lv_GW_Cert_OK == false){
                const serverCertificate = ws._socket.getPeerCertificate();
                if(serverCertificate.fingerprint256 != g_gwCert256){
                    ws.close();
                    return;
                }
                else{
                    lv_GW_Cert_OK = true;
                }
            }
            let header = ""
            if(lv_company_id > 0){
                header = token_string + `{\"ip\":\"-1\",\"user_id\":\"-1\",\"machine_id\":\"-1\",\"listen_port\":\"${loopback_policy_port}\", \"session_id\":\"-1\" , \"company_id\":\"${lv_company_id}\", \"company_token\":\"${lv_company_token}\"}`;
            }
            else{
                header = token_string + `{\"ip\":\"-1\",\"user_id\":\"-1\",\"machine_id\":\"-1\",\"listen_port\":\"${loopback_policy_port}\", \"session_id\":\"-1\" , \"company_id\":\"-111\"}`;
            }
            ws.send(header);
            //Flush any buffered data
            bufferQueue.forEach((message) => {
                ws.send(message);
            });
            bufferQueue = [];  
        });

        // Forward data from WebSocket server back to client
        ws.on('message', async(chunk) => {
            from.write(chunk); // Write data from WebSocket to client
        });
        // Handle client and WebSocket connection errors
        ws.on('error', (err) => {
            from.end(); // Close client connection on error
        });
        // Handle WebSocket server disconnection
        ws.on('close', () => {
            from.end();
        });

        // Forward data from client to WebSocket server with header
        from.on('data', async(chunk) => {
            // const bufTemp = Buffer.from(token_string);
            // const cated = Buffer.concat([bufTemp, chunk]);
            //const cated = chunk;
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(chunk);
            } else {
                bufferQueue.push(chunk);
            }
            
        });

        from.on('error', (err) => {
            ws.close(); // Close WebSocket connection on error
        });

        // Handle client disconnection
        from.on('close', () => {
            ws.close();  // Close WebSocket connection
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
function loginToAdminserver() {
	const login_Options = {
	    hostname: "127.0.0.1",
	    port: 43211,
	    path: '/api/connect/login',
	    method: 'POST',
	    headers: {
	        'Content-Type': 'application/json',
	        'Connection': 'keep-alive'
	    },
        rejectUnauthorized: false
	};

    const getToken_Options = {
	    hostname: "127.0.0.1",
	    port: 43210,
	    path: '/api/connect/get-token',
	    method: 'POST',
	    headers: {
	        'Content-Type': 'application/json',
	        'Connection': 'keep-alive'
	    },
        rejectUnauthorized: false
	};
    const tmp_users_info = {
	    hostname: "127.0.0.1",
	    port: 43210,
	    path: '/api/connect/tmp_users',
	    method: 'POST',
	    headers: {
	        'Content-Type': 'application/json',
	        'Connection': 'keep-alive'
	    },
        rejectUnauthorized: false
	};

    
    //. login OK
    if(lv_company_id > 0){
        const req = https.request(getToken_Options, (res) => {
            let data = '';
            // Accumulate data chunks
            res.on('data', (chunk) => {
                data += chunk;
            });

            // Process complete response
            res.on('end', () => {
                try {
                    const responseJsonData = JSON.parse(data);
                    if ('status' in responseJsonData) {
                        if(responseJsonData.status == 500){
                            lv_company_is_valid = false;
                        }
                        else if(responseJsonData.status == 200 &&  responseJsonData.data.token == lv_company_token){
                            lv_company_is_valid = true;
                        }
                    }
                } catch (err) {
                }
            });
        });

        req.on('error', (error) => {
        });
        // Create the request body
        const requestBody = JSON.stringify({
            refresh_token: lv_company_token
        });
        // Write the request body to the request stream
        req.write(requestBody);
        // End request
        req.end();   


        //. 
        {
            const req = https.request(tmp_users_info, (res) => {
                let data = '';
                // Accumulate data chunks
                res.on('data', (chunk) => {
                    data += chunk;
                });
    
                // Process complete response
                res.on('end', () => {
                    try {
                        const responseJsonData = JSON.parse(data);
                        if ('status' in responseJsonData) {
                            if(responseJsonData.status == 200 ){
                                lv_credential_user_list = responseJsonData.data;
                                lv_get_credential_users_ok = true;
                                //console.log(lv_credential_user_list);
                            }
                            
                            if(responseJsonData.status != 200){
                                logger.status(`tmp_users_info message : ${responseJsonData.status}, ${responseJsonData.message} `);
                            }
                        }
                    } catch (err) {
                    }
                });
            });
    
            req.on('error', (error) => {
            });
            // Create the request body
            const requestBody = JSON.stringify({
                company_id: lv_company_id
            });
            // Write the request body to the request stream
            req.write(requestBody);
            // End request
            req.end(); 
        }
        return;
    }

    //. Init
    {
        const req = https.request(getToken_Options, (res) => {
            let data = '';
            // Accumulate data chunks
            res.on('data', (chunk) => {
                data += chunk;
            });

            // Process complete response
            res.on('end', () => {
                try {
                    const responseJsonData = JSON.parse(data);
                    if ('status' in responseJsonData) {
                        if(responseJsonData.status == 200 &&  responseJsonData.data.token == lv_company_token){
                            lv_company_access_token = responseJsonData.data.access_token;
                            lv_company_is_valid = true;
                        }
                        
                        if(responseJsonData.status != 200){
                            logger.status(`getToken_Options message : ${responseJsonData.status}, ${responseJsonData.message} `);
                        }
                    }
                } catch (err) {
                }
            });
        });

        req.on('error', (error) => {
        });
        // Create the request body
        const requestBody = JSON.stringify({
            refresh_token: lv_company_token
        });
        // Write the request body to the request stream
        req.write(requestBody);
        // End request
        req.end();        
    }
    //. 
    if(lv_company_access_token != ""){
        const req = https.request(login_Options, (res) => {
            let data = '';
            // Accumulate data chunks
            res.on('data', (chunk) => {
                data += chunk;
            });

            // Process complete response
            res.on('end', () => {
                try {
                    const responseJsonData = JSON.parse(data);
                    if ('status' in responseJsonData) {
                        if(responseJsonData.status == 200 &&  responseJsonData.data.connect_status == 1){
                            lv_company_id = responseJsonData.data.company_id;
                            lv_private_ip = responseJsonData.data.private_ip;
                        }   
                        else{
                            logger.status(`login_Options message : ${responseJsonData.status}, ${responseJsonData.message} `);
                            lv_company_id = -1;
                        }           
                    }
                    else{
                        lv_company_id = -1;
                    }

                } catch (err) {
                }
            });
        });

        req.on('error', (error) => {
        });
        // Create the request body
        const requestBody = JSON.stringify({
            //ip: lv_global_ip,
            token: lv_company_access_token
        });

        // Write the request body to the request stream
        req.write(requestBody);
        // End request
        req.end();
    }
    //.
    if(lv_company_id > 0){
        const req = https.request(tmp_users_info, (res) => {
            let data = '';
            // Accumulate data chunks
            res.on('data', (chunk) => {
                data += chunk;
            });

            // Process complete response
            res.on('end', () => {
                try {
                    const responseJsonData = JSON.parse(data);
                    if ('status' in responseJsonData) {
                        if(responseJsonData.status == 200 ){
                            lv_credential_user_list = responseJsonData.data;
                            lv_get_credential_users_ok = true;
                        }
                        
                        if(responseJsonData.status != 200){
                            logger.status(`tmp_users_info message : ${responseJsonData.status}, ${responseJsonData.message} `);
                        }
                    }
                } catch (err) {
                }
            });
        });

        req.on('error', (error) => {
        });
        // Create the request body
        const requestBody = JSON.stringify({
            company_id: lv_company_id
        });
        // Write the request body to the request stream
        req.write(requestBody);
        // End request
        req.end(); 
    }



}
let  lv_Policy_Data_OK = false;
function getPortPolicyData() {

    if(lv_company_id <= 0){
        logger.status(`getPortPolicyData lv_company_id <= 0 `);
        return;
    }

	const options = {
	    hostname: "127.0.0.1",
	    port: 43210,
	    path: '/api/connect/port-rules',
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
                lv_policy_data = responseJsonData.data.ports;
                lv_Policy_Data_OK = true;
                //console.log(lv_policy_data);
            } catch (err) {
            }
        });
    });

    req.on('error', (error) => {
    });

    // Create the request body
    const requestBody = JSON.stringify({
        company_id: lv_company_id
    });

    // Write the request body to the request stream
    req.write(requestBody);
    // End request
    req.end();
}
function ActiveStatusToAdminServer(realClientIP, user_id, machine_id, extractedPort, session_id, bps_speed, connect_status, delayTime, subTarget) {

	const options = {
	    hostname: "127.0.0.1",
	    port: 43210,
	    path: '/api/network/backend-connect',
	    method: 'POST',
	    headers: {
	        'Content-Type': 'application/json',
	        'Connection': 'keep-alive'
	    },
        rejectUnauthorized: false
	};
    const requestData = {
        "user_id": user_id,
        "machine_id": machine_id,
        "listen_port": extractedPort,
        "target": subTarget,
        "speed": bps_speed,
        "ip":realClientIP,
        "session_id":session_id,
        "latency": delayTime,
        "connection_status":connect_status
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
            } 
            catch (err) {
            }
        });
    });

    req.on('error', (error) => {
//        logger.error(`ActiveStatusToAdminServer - Error : `, error.message);
    });

    // Send the JSON data in the request body
    req.write(JSON.stringify(requestData));  // Convert the JS object to JSON string
//    console.log(requestData);
    // End request
    req.end();
}

function WSS_ADMIN_Check_Login(listen_port){

    let     is_https = 1;

    const server = net.createServer((from) => {

        try{
            const clientIP = from.remoteAddress;
            const localIP = from.localAddress;
            const clientPort = from.remotePort;
    
            const targetSocket = net.createConnection({
                host: gw_server_ip,
                port: 443
            }, () => {
            });
    
            targetSocket.on('data', async(chunk) => {
                try {
                    from.write(chunk);
                } catch (err) {
                    logger.status(`WSS_ADMIN_Check_Login Error writing data to client: ${err.message}`);
                    targetSocket.end();
                }
            });
            from.on('data', async(chunk) => {
                try {
                    targetSocket.write(chunk);
                } catch (err) {
                    logger.status(`WSS_ADMIN_Check_Login Error writing data to target socket: ${err.message}`);
                    from.end();
                }
            });
            targetSocket.on('error', (err) => {
                targetSocket.end();
            });
            // Handle client disconnection
            targetSocket.on('close', () => {
                from.end();
            });
            // Forward data from client to WebSocket server with header

    
            from.on('error', (err) => {
                from.end();
            });
            // Handle client disconnection
            from.on('close', () => {
                targetSocket.end();
            });
    
        } catch (err) {
            logger.status(`Error in WSS_ADMIN_Check_Login: ${err.message}`);
            from.end();
        }


    }).listen(listen_port, "127.0.0.1", () => {
        logger.status(`WSS_ADMIN_Check_Login Start ... OK `);
    });

    // Handle server errors
    server.on('error', (err) => {
        logger.status(`WSS_ADMIN_Check_Login Error , ${err.message}`);
    });
}
//. 
function WSS_ADMIN_CONNECT_HTTPS(user_id, machine_id, listen_port, gw_taget_port, policy_url, policy_port, is_direct){

    let     is_https = 1;

    const server = net.createServer((from) => {
        const clientIP = from.remoteAddress;
        const localIP = from.localAddress;
        const clientPort = from.remotePort;

        if(lv_company_id <= 0){
            logger.status(`WSS_ADMIN_CONNECT_HTTPS lv_company_id <= 0 `);
            from.end();
            return;
        }
        if(lv_company_is_valid == false ){
            logger.status(`WSS_ADMIN_CONNECT_HTTPS lv_company_is_valid == false `);
            from.end();
            return;
        }
 
     const targetSocket = net.createConnection({
        host: gw_server_ip,
        port: 443
    }, () => {
    });

    targetSocket.on('data', async(chunk) => {
        from.write(chunk);
    });
    targetSocket.on('error', (err) => {
        targetSocket.end();
    });
    // Handle client disconnection
    targetSocket.on('close', () => {
        from.end();
    });
    // Forward data from client to WebSocket server with header
    from.on('data', async(chunk) => {
        targetSocket.write(chunk);
    });

    from.on('error', (err) => {
        from.end();
    });
    // Handle client disconnection
    from.on('close', () => {
        targetSocket.end();
    });


    }).listen(listen_port, "0.0.0.0", () => {
        logger.status(`WSS_ADMIN_CONNECT_HTTPS Start : ${listen_port}`);
    });

    // Handle server errors
    server.on('error', (err) => {
        logger.status(`WSS_ADMIN_CONNECT_HTTPS Error : ${listen_port} , ${err.message}`);
    });
}


function WSS_SERVER_PRIVATE(listen_port) {

    const w_listen_port = listen_port;
    const serverOptions = {
        key: fs.readFileSync('certs/kenan-connect-wss.key'),   // Path to your private key file
        cert: fs.readFileSync('certs/kenan-connect-wss.crt'),  // Path to your certificate file
    };

    // Create an HTTPS server with SSL options
    const server = https.createServer(serverOptions);

    // Create WebSocket server
    const wss = new WebSocket.Server({ server });

    // Handle WebSocket connection
    wss.on('connection', (ws, req) => {
        const private_clientIP = req.socket.remoteAddress;
 
        // Handle incoming data from the WebSocket client
        ws.once('message', (message) => {
            message=message.toString();
  
            const regex = /_kenan_header_(\{.*?\})/; // Regex to capture the JSON object part
            const matchJson = message.match(regex);
            let left = null;
            let company_token = null;
            let private_log = -1;

            if (matchJson && matchJson[1]) {
                const parsedData = JSON.parse(matchJson[1]);
                company_token = parsedData.company_token; // Extract the port field

                if ('private_log' in parsedData) {
                    private_log = parsedData.private_log;
                } else {
                    private_log = -1;
                }

                message = message.replace(regex, "");  // Clean the message
                if (message.length > 0) 
                    left = message.substring(matchJson[1].length);
                
            } else {
                ws.close(); // Close connection if parsing fails
                return;
            }

            if(lv_Policy_Data_OK == false){
                ws.close(); 
                return;
            }

            //. check ip
            if(lv_private_ip == null || lv_private_ip == ""){
                logger.status(`WSS_SERVER_PRIVATE lv_private_ip == null`);
                ws.close(); 
                return;
            }
            //logger.status(`WSS_SERVER_PRIVATE private_clientIP : ${private_clientIP}`);
            if(private_clientIP == "127.0.0.1" || private_clientIP == lv_private_ip){
            }
            else{
                logger.status(`private_clientIP != lv_private_ip, ${private_clientIP}, ${lv_private_ip}`);
                ws.close(); 
                return;
            }

            //. check token
            if(lv_company_token != company_token){
                logger.status(`WSS_SERVER_PRIVATE private token Error : ${company_token}`);
                ws.close(); 
                return;
            }
            //.
            if(private_log == 1){
                ws.send("_recv_log_data_");  
            }
            else{
                //. get internal ports
                const wPrivatePolicyData = lv_policy_data.filter(policy => policy.is_direct == 2);
                let   send_message = {clientId:"policy_data",  payload: wPrivatePolicyData};
                //. Send Policy data for KPrivate Server
                try {
                    ws.send((JSON.stringify(send_message)));
                } catch (err) {
                    logger.status(`WSS_SERVER_PRIVATE send Error : ${err.message}`);
                }
            }


            //.
            ws.on('message', (chunk) => {
                if(private_log == 1){
                    const { clientId, payload } = JSON.parse(chunk.toString());
                    if(clientId == "delete_user"){
                        w_recvData = JSON.parse(payload.toString());
                        logger.status(`WSS_SERVER_PRIVATE delete_user : ${w_recvData.name}, ${w_recvData.listen_port}`);
                        delCredentialUserFromServer(w_recvData.name, w_recvData.listen_port, 1);
                    }
                    if(clientId == "add_user"){
                        w_recvData = JSON.parse(payload.toString());

                        logger.status(`WSS_SERVER_PRIVATE delete_user : ${w_recvData.name}, ${w_recvData.listen_port}`);
                        addCredentialUserFromServer(w_recvData.user_id, w_recvData.company_id, w_recvData.type, w_recvData.target_ip, w_recvData.listen_port, w_recvData.name, w_recvData.password , w_recvData.key, w_recvData.generator_type, w_recvData.local_created_at, 1);
                        //.
                        const w_PortInfoyData = lv_policy_data.find(policy => policy.listen_port == w_recvData.listen_port);
                        if (w_PortInfoyData) {
                            let w_ownerChangePasswd = w_PortInfoyData.tmp_type;
                            if(w_ownerChangePasswd == 1) 
                                setChangePasswdFromServer(w_recvData.company_id, w_recvData.listen_port, w_recvData.password, w_recvData.key);
                        }

                    }
                    if(clientId == "report_user"){
                        w_recvData = JSON.parse(payload.toString());
                        reportCredentialUserFromServer(w_recvData.user_id, w_recvData.company_id, w_recvData.type, w_recvData.target_ip, w_recvData.listen_port, w_recvData.ip, w_recvData.description);
                    }

                    if(clientId == "change_pw"){
                        w_recvData = JSON.parse(payload.toString());
                        if(w_recvData.company_id == ""){
                            w_recvData.company_id = lv_company_id;
                        }
                        logger.status(`WSS_SERVER_PRIVATE change_pw : ${w_recvData.listen_port}`);
                        setChangePasswdFromServer(w_recvData.company_id, w_recvData.listen_port, w_recvData.tmp_password, w_recvData.tmp_key);
                    }


                    ws.close(); 
                }
                else{
                    let recv_msg = chunk.toString();
                    //.  Identify the message type and send port information and temporarily created server registration user information.
                    //   When a termination message arrives, ws.close() terminates. 
                    if(recv_msg.includes("_get_credential_user_lists_")){
    
                        let     w_private_credential_user_list = "";
                        if(lv_get_credential_users_ok == true){
                            w_private_credential_user_list = lv_credential_user_list.filter(credential_user => credential_user.generator_type != 0);
                            //w_private_credential_user_list = lv_credential_user_list;
                        }
                        else{
                        }
                        const send_message = {clientId:"credential_data",  payload: w_private_credential_user_list};
                        ws.send((JSON.stringify(send_message)));
                    }
                    }

            });

            ws.on('error', (err) => {
                logger.status(`WSS_SERVER_PRIVATE ws Error : ${err.message}`);
                ws.close(); 
            });
            // Handle client disconnection
            ws.on('close', () => {
                ws.close(); 
            });
        });
    });

    // Start the server
    server.listen(w_listen_port, '0.0.0.0', () => {
        logger.status(`WSS_SERVER_PRIVATE server started on port ${w_listen_port}`);
    });

    // Handle server errors
    server.on('error', (err) => {
        logger.status(`WSS_SERVER_PRIVATE error on port ${w_listen_port}:`, err.message);
    });
}


///////////////////////////////////////////////////////////////////////////////////////////
////// Contect to GW WSS
let lv_clients = new Map();  
let lv_nConnectLoopCnt = new Map();  
let lv_nRecvTarget_OK = new Map();  
let lv_gw_ws = null;


let lv_last_ping_time  = 0;
let lv_end_ping_time  = 0;

// 
function sendCloseSocket(clientId, gw_ws) {
    const send_message = {clientId,  payload: "_kenan_socket_close_"};
    try {
        if(gw_ws){
            gw_ws.send(JSON.stringify(send_message));
        }
    } catch (err) {
        logger.status(`Error sendCloseSocket : ${err.message}`);
    }
}

function Ping_GW_WSS_CONNECT() {

    if(lv_gw_ws == null){
        return ;
    }
    if(lv_last_ping_time > 0 && lv_end_ping_time > 0){
        //.
        let diffMs = lv_end_ping_time - lv_last_ping_time;
        if(diffMs > (PING_PONG_TIME_OUT * 2) || diffMs < (0 - (PING_PONG_TIME_OUT * 2))){
            logger.status(`Ping_GW_WSS_CONNECT time out ---- diffMs = ${diffMs}, lv_end_ping_time = ${lv_end_ping_time}, lv_last_ping_time = ${lv_last_ping_time}`);
            lv_last_ping_time  = 0;
            lv_end_ping_time  = 0;
            lv_gw_ws.close();
            // lv_gw_ws_cnt = 0;
            // lv_clients.clear();
            // lv_nConnectLoopCnt.clear();
            // lv_nRecvTarget_OK.clear();
        }
        else{
            //logger.status(`Ping_GW_WSS_CONNECT OK ---- diffMs = ${diffMs}`);
        }
    }

    //. 
    if(lv_gw_ws && lv_gw_ws.readyState === WebSocket.OPEN){
        const send_message = {clientId : "_kenan_connect_testID__",  payload: "_kenan_socket_ping_"};
        lv_gw_ws.send(JSON.stringify(send_message));
        //.
        lv_last_ping_time = Date.now();
    }
}

//.
async function Init_GW_WSS_CONNECT() {
    if(lv_company_id <= 0){
        //logger.status(`Init_GW_WSS_CONNECT lv_company_id <= 0 `);
        return;
    }
    if(lv_Policy_Data_OK == false){
        return;
    }

    if(lv_gw_ws_cnt < 0 ){
        lv_gw_ws_cnt = lv_gw_ws_cnt + 1;
        return;
    }
    //. check lv_gw_ws status
    if(lv_gw_ws_cnt > 0 ){
        return;
    }
    lv_gw_ws_cnt = lv_gw_ws_cnt + 1;
    logger.status(`Init_GW_WSS_CONNECT Start  ---------  `);

    lv_gw_ws = new WebSocket(`wss://${gw_server_ip}:${gw_port}/gw`, {
        rejectUnauthorized: false,
    });

    let targetSocket = null;

    lv_gw_ws.on('open', () => {
        const header = token_string + `{\"ip\":\"-1\",\"user_id\":\"-1\",\"machine_id\":\"-1\",\"listen_port\":\"443\", \"session_id\":\"-1\" , \"company_id\":\"${lv_company_id}\" , \"company_token\":\"${lv_company_token}\", \"kconnect_init\":\"${kconnect_init_string}\"}`;
        lv_gw_ws.send(Buffer.from(header));
    });
    //. 
    lv_gw_ws.on('message', async(chunk) => {
        const { clientId, payload } = JSON.parse(chunk.toString());
        const binaryPayload = Buffer.from(payload, 'base64'); // Convert back to Buffer

        let w_policy_url = "";
        let w_policy_port = 443;

        let message = payload.toString();

        if(message.includes("_kenan_header_")){

            const regex = /_kenan_header_(\{.*\})/; // Regex to capture the JSON object part
            const matchJson = message.match(regex);
            let left = null;
            let extractedPort = null;
            let realClientIP = "";
            let user_id = 0;
            let machine_id = "";
            let session_id = "";
            let bps_speed = 0;
            let delayTime = 0;
            let clientGlobalTime;
            let w_is_https;
            let w_company_id = -1;
            let w_userOpt = "";

            if (matchJson && matchJson[1]) {
                const parsedData = JSON.parse(matchJson[1]);

                //. user management for SSH, RDP
                if ('userOpt' in parsedData) {
                    w_userOpt = parsedData.userOpt;
                    logger.status(`Init_GW_WSS_CONNECT userOpt ----- ${w_userOpt}`);
                    //.
                    let w_ret = null;
                    w_ret = await processUserCreation(parsedData);
                    if(w_ret == null){
                        w_ret = { status: 0, message: "processUserCreation return null." };
                    }
                    logger.status(`Init_GW_WSS_CONNECT processUserCreation w_ret ---- ok`);

                    let w_data = JSON.stringify(w_ret);
                    let temp = Buffer.from(w_data).toString('base64');
                    const send_message = {clientId,  payload: temp};
                    lv_gw_ws.send(JSON.stringify(send_message));
                    //. 
                    //sendCloseSocket(clientId, lv_gw_ws);
                    return;
                } 
                else {
                    extractedPort = parsedData.listen_port; // Extract the port field
                    realClientIP = parsedData.ip;
                    user_id = parsedData.user_id;
                    machine_id = parsedData.machine_id;
                    session_id = parsedData.session_id;
                    bps_speed = parsedData.bps_speed;
                    clientGlobalTime = parsedData.client_time;
                    w_is_https = parsedData.is_https;
                    w_policy_url = parsedData.policy_url;
                    w_policy_port = parsedData.policy_port;
                    if ('company_id' in parsedData) {
                        w_company_id = parsedData.company_id;
                    } else {
                        w_company_id = -1;
                    }
                    //.
                    message = message.replace(regex, "");  // Clean the message
                    if (message.length > 0) 
                        left = message.substring(matchJson[1].length);
                }
            } else {
                logger.status(`Init_GW_WSS_CONNECT matchJson && matchJson[1] ----- faild`);
                sendCloseSocket(clientId, lv_gw_ws);
                return;
            }
            //. check company ID
            if(w_company_id < 0 || w_company_id != lv_company_id){
                logger.status(`Init_GW_WSS_CONNECT w_company_id != lv_company_id ${w_company_id} , ${lv_company_id} `);
                sendCloseSocket(clientId, lv_gw_ws);
                return;
            }
            //. 
            {
                //. only get data from kagent ( is not 43210)
                const clientUtcTime = new Date(clientGlobalTime); // 
                const serverUtcTime = new Date(getUtcTime()); // 
                delayTime = serverUtcTime - clientUtcTime; // 
                if(delayTime < 0){
                    delayTime = 0;
                }

                if(w_is_https == 0){
                    // Find the matching policy entry based on the extracted port
                    const matchingPolicy = lv_policy_data.find(policy => policy.listen_port == extractedPort);
                    if (!matchingPolicy) {
                        logger.status(`Init_GW_WSS_CONNECT matchingPolicy error : ${extractedPort}  `);
                        sendCloseSocket(clientId, lv_gw_ws);
                        return;
                    }
                    const { target, target_port} = matchingPolicy;
                    w_policy_url = target;
                    w_policy_port = target_port;
                }
                else{
                    //. check extractedPort value
                    extractedPort = getListenPortFromURLInfo(w_policy_url);
                    if(extractedPort == -1){
                        logger.status(`Init_GW_WSS_CONNECT getListenPortFromURLInfo error : ${w_policy_url}  `);
                        sendCloseSocket(clientId, lv_gw_ws);
                        return;
                    }
                }
                //. 
                {
                    if(w_is_https == 0 ){
                        const matchingPolicy = lv_policy_data.find(policy => policy.listen_port == extractedPort);
                        if(matchingPolicy && (matchingPolicy.credential_type == 1 || matchingPolicy.credential_type == 2)){
                            addConServerUserInfo(user_id, matchingPolicy.company_id, matchingPolicy.listen_port);
                        }
                    }

                    targetSocket = net.createConnection({
                        host: w_policy_url,
                        port: w_policy_port
                    }, () => {
                    });

                    logger.status(`Init_GW_WSS_CONNECT net.createConnection : w_policy_url: ${w_policy_url} , w_policy_port: ${w_policy_port} `);

                    lv_clients.set(clientId, targetSocket);
                    lv_nConnectLoopCnt.set(clientId, LOOP_SKIP_CNT);
                    lv_nRecvTarget_OK.set(clientId, 0);

                    if (left) {
                        targetSocket.write(Buffer.from(left));
                    }
                    //.
                    targetSocket.on('data', async(chunk) => {

                        //. running  
                        let     w_nConnectLoopCnt = lv_nConnectLoopCnt.get(clientId);
                        if((w_nConnectLoopCnt % LOOP_SKIP_CNT) == 0){
                            setImmediate(() => {
                                ActiveStatusToAdminServer(realClientIP, user_id, machine_id, extractedPort, session_id, bps_speed, 2, delayTime, w_policy_url);
                            });
                            w_nConnectLoopCnt = 1;
                        }
                        else{
                            w_nConnectLoopCnt = w_nConnectLoopCnt + 1;
                        }
                        lv_nConnectLoopCnt.set(clientId, w_nConnectLoopCnt);

                        const send_message = {clientId,  payload: chunk.toString('base64')};
                        lv_gw_ws.send(JSON.stringify(send_message));
                        lv_nRecvTarget_OK.set(clientId, 1);

                    });

                    // Handle errors and disconnections
                    targetSocket.on('error', (err) => {
                         //. if connect aaa.bbb.com 
                        if(lv_nRecvTarget_OK.get(targetSocket) == 0){
                            setImmediate(() => {
                                ActiveStatusToAdminServer(realClientIP, user_id, machine_id, extractedPort, session_id, bps_speed, 3, delayTime, w_policy_url);
                            });
                        } 
                        sendCloseSocket(clientId, lv_gw_ws);
                        lv_nConnectLoopCnt.delete(clientId);
                        lv_nRecvTarget_OK.delete(clientId);
                        lv_clients.delete(clientId);

                        if(w_is_https == 0 ){
                            const matchingPolicy = lv_policy_data.find(policy => policy.listen_port == extractedPort);
                            if(matchingPolicy && (matchingPolicy.credential_type == 1 || matchingPolicy.credential_type == 2)){
                                delConServerUserInfo(user_id, matchingPolicy.company_id, matchingPolicy.listen_port);
                            }
                        }

                    });

                    targetSocket.on('close', () => {
                        setImmediate(() => {
                            ActiveStatusToAdminServer(realClientIP, user_id, machine_id, extractedPort, session_id, bps_speed, 0, delayTime, w_policy_url);
                        });
                        sendCloseSocket(clientId, lv_gw_ws);
                        lv_nConnectLoopCnt.delete(clientId);
                        lv_nRecvTarget_OK.delete(clientId);
                        lv_clients.delete(clientId);

                        if(w_is_https == 0 ){
                            const matchingPolicy = lv_policy_data.find(policy => policy.listen_port == extractedPort);
                            if(matchingPolicy && (matchingPolicy.credential_type == 1 || matchingPolicy.credential_type == 2)){
                                delConServerUserInfo(user_id, matchingPolicy.company_id, matchingPolicy.listen_port);
                            }
                        }
                    });

                }
            }
        }
        else if(message.includes("_kenan_socket_ping_")){
            if(lv_last_ping_time > 0){
                lv_end_ping_time = Date.now();
            }
        }
        else {
            const targetSocket = lv_clients.get(clientId);
            if(targetSocket == null){
                // sendCloseSocket(clientId, lv_gw_ws);
                // lv_clients.delete(clientId);
                // lv_nConnectLoopCnt.delete(clientId);
                // lv_nRecvTarget_OK.delete(clientId);
                logger.status(`Init_GW_WSS_CONNECT targetSocket == null  ${clientId} , ${w_policy_url} `);
            }
            else{
                targetSocket.write(binaryPayload);
            }
        }
    });

    //. Handle client and WebSocket connection errors
    lv_gw_ws.on('error', (err) => {
        logger.status(`Init_GW_WSS_CONNECT lv_gw_ws error : ${err.message} `);
        lv_gw_ws.close();
    });
    lv_gw_ws.on('close', () => {
        logger.status(`Init_GW_WSS_CONNECT lv_gw_ws close `);
        lv_clients.clear();
        lv_nConnectLoopCnt.clear();
        lv_nRecvTarget_OK.clear();
        lv_gw_ws_cnt = 0;
        lv_gw_ws = null;

    });    
    
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////

function setChangePasswdFromServer(company_id, listen_port, tmp_password, tmp_key) {

    const options = {
	    hostname: "127.0.0.1",
	    port: 43210,
	    path: '/api/connect/set_tmp_password',
	    method: 'POST',
	    headers: {
	        'Content-Type': 'application/json',
	        'Connection': 'keep-alive'
	    },
        rejectUnauthorized: false
	};

    //. update tmp_password, tmp_key of lv_policy_data
    const index = lv_policy_data.findIndex(entry => entry.listen_port == listen_port);
    if (index != -1) {
        lv_policy_data[index].tmp_password = tmp_password;
        lv_policy_data[index].tmp_key = tmp_key;

    } else {
    }

    //.
    const req = https.request(options, (res) => {
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
    const requestBody = JSON.stringify({
        company_id: company_id,
        listen_port: listen_port,
        tmp_password: tmp_password,
        tmp_key: tmp_key
    });

    // Write the request body to the request stream
    req.write(requestBody);
    // End request
    req.end();
}

function delCredentialUserFromServer(kenan_username, listen_port, kconnect_log) {

	const options = {
	    hostname: "127.0.0.1",
	    port: 43210,
	    path: '/api/connect/delete_tmp_user',
	    method: 'POST',
	    headers: {
	        'Content-Type': 'application/json',
	        'Connection': 'keep-alive'
	    },
        rejectUnauthorized: false
	};

    let w_credential_user = lv_credential_user_list.find(credential_user => credential_user.name == kenan_username && credential_user.listen_port == listen_port);
    if(w_credential_user == null){
        logger.status(`delCredentialUserFromServer error w_credential_user == null , ${kenan_username}, ${listen_port}`);
        return;
    }

    // console.log(`delCredentialUserFromServer start  `);
    // console.log(lv_credential_user_list);

    // let w_ret = parseUserName(kenan_username);
    // if(w_ret.status == 0){
    //     return;
    // }

    //if(kconnect_log == 1){
        //lv_credential_user_list = lv_credential_user_list.filter(credential_user => credential_user.name != kenan_username);
        lv_credential_user_list = lv_credential_user_list.filter(credential_user => !(credential_user.name == kenan_username && credential_user.listen_port == listen_port));
    //}


    const req = https.request(options, (res) => {
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
    const requestBody = JSON.stringify({
        user_id: w_credential_user.user_id,
        listen_port: w_credential_user.listen_port
    });

    // Write the request body to the request stream
    req.write(requestBody);
    // End request
    req.end();
}
//.
function addCredentialUserFromServer(user_id, company_id, RDP_SSH_Type, target, listen_port, username, password , key, generator_type, local_created_at, kconnect_log) {

	const options = {
	    hostname: "127.0.0.1",
	    port: 43210,
	    path: '/api/connect/create_tmp_user',
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
            } catch (err) {
            }
        });
    });

    req.on('error', (error) => {
    });

    console.log(`addCredentialUserFromServer local_created_at : ${local_created_at}, username = ${username}`);
    if(kconnect_log == 1){
        //lv_credential_user_list = lv_credential_user_list.filter(credential_user => credential_user.name != username);
        lv_credential_user_list = lv_credential_user_list.filter(credential_user => !(credential_user.name == username && credential_user.listen_port == listen_port));
        lv_credential_user_list.push({ user_id: user_id, type: RDP_SSH_Type, target_ip: target, listen_port: listen_port, name: username, password: password, key: key, generator_type: generator_type, local_created_at: local_created_at});
    }


    // Create the request body
    const requestBody = JSON.stringify({
        user_id: user_id,
        company_id: company_id,
        type: RDP_SSH_Type,
        target_ip: target,
        listen_port: listen_port,
        name: username,
        password: password,
        key: key,
        generator_type: generator_type,
        local_created_at: local_created_at,
    });

    // Write the request body to the request stream
    req.write(requestBody);
    // End request
    req.end();
}
function reportCredentialUserFromServer(company_id, listen_port, target_ip, type , user_id, ip, description) {

	const options = {
	    hostname: "127.0.0.1",
	    port: 43210,
	    path: '/api/connect/report_tmp_user',
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
            } catch (err) {
            }
        });
    });

    req.on('error', (error) => {
    });

    // Create the request body
    const requestBody = JSON.stringify({
        company_id: company_id,
        listen_port: listen_port,
        type: type,
        target_ip: target_ip,
        user_id: user_id,
        ip: ip,
        description: description,

    });

    // Write the request body to the request stream
    req.write(requestBody);
    // End request
    req.end();
}

function addConServerUserInfo(user_id, company_id, listen_port)
{
    //. add to lv_con_server_user_list
    let     w_ConUserName = generateUserName(listen_port, company_id, user_id);

    const w_PortInfoyData = lv_policy_data.find(policy => policy.listen_port == listen_port);
    if (w_PortInfoyData) {
        let w_ownerChangePasswd = w_PortInfoyData.tmp_type;
        if(w_ownerChangePasswd == 1){
            w_ConUserName = w_PortInfoyData.tmp_username;
        }
    }
    const index = lv_con_server_user_list.findIndex(entry => entry.username == w_ConUserName && entry.listen_port == listen_port);
    if (index != -1) {
    } else {
        console.log(`lv_con_server_user_list push : ${w_ConUserName}, ${listen_port}`);
         lv_con_server_user_list.push({ username: w_ConUserName, listen_port: listen_port});
    }

}

function delConServerUserInfo(user_id, company_id, listen_port)
{
    //. del to lv_con_server_user_list
    let     w_ConUserName = generateUserName(listen_port, company_id, user_id);

    const w_PortInfoyData = lv_policy_data.find(policy => policy.listen_port == listen_port);
    if (w_PortInfoyData) {
        let w_ownerChangePasswd = w_PortInfoyData.tmp_type;
        if(w_ownerChangePasswd == 1){
            w_ConUserName = w_PortInfoyData.tmp_username;
        }
    }
    console.log(`lv_con_server_user_list del : ${w_ConUserName}, ${listen_port}`);
    lv_con_server_user_list = lv_con_server_user_list.filter(entry => !(entry.username == w_ConUserName && entry.listen_port == listen_port));
}


function del_pinky_user_command(username, pinky_list)
{
    let     w_retCommand = "";
    let     w_nCount = 0;

    for (let i = pinky_list.length - 1; i >= 0; i--) {
        const pinky_user = pinky_list[i];
        if(pinky_user.Login.includes(username)){
            if(w_nCount > 0){
                w_retCommand = w_retCommand + " && "
            }
            //.sudo pkill -9 -t pts/0
            w_retCommand = w_retCommand + "sudo pkill -9 -t " +  pinky_user.TTY;      
            w_nCount++;
        }
    }
    return w_retCommand;
}
function convertUserTimeout(sec_time)
{
    let  w_ntimeout = parseInt(sec_time, 10)
    if(w_ntimeout < 120 ){
        return 1;
    }
    else{
        return w_ntimeout / 60;
    }

}

let   lv_fCreateUser_Start = false;
async function processUserCreation(parsedData) {

    if (lv_fCreateUser_Start) {
        while (lv_fCreateUser_Start) {
            console.log(`------Waiting for user creation to complete...`);
            await new Promise(resolve => setTimeout(resolve, 200));
        }
    }
    
    lv_fCreateUser_Start = true;
    let w_result = await AutoCreateAndDelUser(parsedData);
    lv_fCreateUser_Start = false;
    
    return w_result;

}

async function AutoCreateAndDelUser_RDP(parsedData) 
{
    let w_listen_port = parsedData.listen_port; 
    let w_company_id = parsedData.company_id;
    let w_user_id = parsedData.user_id;
    let w_userOpt = parsedData.userOpt;
    let w_CmdUserResult;

    let   w_KenanUserName = generateUserName(w_listen_port, w_company_id, w_user_id);
    const w_PortInfoyData = lv_policy_data.find(policy => policy.listen_port == w_listen_port && policy.is_direct == 0);
    if (!w_PortInfoyData) {
        return { status: 0, message: "can not find data from lv_policy_data" };
    }

    let w_ownerChangePasswd = w_PortInfoyData.tmp_type;
    if(w_ownerChangePasswd == 1){
        w_KenanUserName = w_PortInfoyData.tmp_username;
    }

    let winrmmng;
    if(w_ownerChangePasswd == 0){
        winrmmng = new WinRMMng(w_PortInfoyData.target, w_PortInfoyData.target_port, w_PortInfoyData.credential_username , w_PortInfoyData.credential_password);
    }
    else{
        winrmmng = new WinRMMng(w_PortInfoyData.target, w_PortInfoyData.target_port, w_PortInfoyData.tmp_username , w_PortInfoyData.tmp_password);
    }


    if(w_userOpt == "useradd"){
        //console.log(`AutoCreateAndDelUser_RDP useradd ${w_KenanUserName} ${w_ownerChangePasswd}`);
        if(w_ownerChangePasswd == 1){
            await winrmmng.deleteRDPSession(w_KenanUserName);
        }
        else{
            await winrmmng.deleteRDPUserAndSession(w_KenanUserName);
        }
        //.
        delCredentialUserFromServer(w_KenanUserName, w_listen_port, 1);

        //.
        let w_Credential_PASSWD = generateSecurePassword();
        if(w_ownerChangePasswd == 1){
            w_CmdUserResult = await winrmmng.changeRDPUserPasswd(w_KenanUserName, w_Credential_PASSWD);
        }
        else{
            w_CmdUserResult = await winrmmng.createRDPUser(w_KenanUserName, w_Credential_PASSWD);
        }

        // console.log(`AutoCreateAndDelUser_RDP useradd result`);
        // console.log(w_CmdUserResult);
        
        if(w_CmdUserResult.status == 1){
            addCredentialUserFromServer(w_user_id, w_company_id, w_PortInfoyData.credential_type, w_PortInfoyData.target, w_listen_port, w_KenanUserName, w_Credential_PASSWD , "", 0, Date.now(), 1);
            if(w_ownerChangePasswd == 1) 
                setChangePasswdFromServer(w_company_id, w_listen_port, w_Credential_PASSWD, "");

            return { status: 1, username: w_KenanUserName, password: w_Credential_PASSWD, key : "" , message: "create user ok." };
        }
        else{
            return { status: 0, message: "useradd createRDPUser error." };
        }
    }
    else if(w_userOpt == "userdel"){

        // await winrmmng.deleteRDPUserAndSession(w_KenanUserName);
        // delCredentialUserFromServer(w_KenanUserName, w_listen_port, 1);
        // return { status: 1, username: w_KenanUserName, message: "delete user ok." };

    }
    else{
        return { status: 0, message: "input praam error." };
    }    

}


//.  SSH 
async function AutoCreateAndDelUser(parsedData) 
{
    try {

        lv_fCreateUser_Start = true;
        //. 
        let w_listen_port = parsedData.listen_port; 
        let w_company_id = parsedData.company_id;
        let w_user_id = parsedData.user_id;
        let w_userOpt = parsedData.userOpt;
        let w_CreateUser_Method = "";

        logger.status(`AutoCreateAndDelUser w_PortInfoyData start  ${w_listen_port} `);

        let   w_KenanUserName = generateUserName(w_listen_port, w_company_id, w_user_id);
        const w_PortInfoyData = lv_policy_data.find(policy => policy.listen_port == w_listen_port && policy.is_direct == 0);
        if (!w_PortInfoyData) {
            logger.status(`AutoCreateAndDelUser can not find data from lv_policy_data  `);
            lv_fCreateUser_Start = false;
            return { status: 0, message: "can not find data from lv_policy_data" };
        }

        logger.status(`AutoCreateAndDelUser w_PortInfoyData ok  `);

        let w_ownerChangePasswd = w_PortInfoyData.tmp_type;
        if(w_ownerChangePasswd == 1){
            w_KenanUserName = w_PortInfoyData.tmp_username;
        }

        logger.status(`AutoCreateAndDelUser w_ownerChangePasswd = ${w_ownerChangePasswd} , w_PortInfoyData.credential_type = ${w_PortInfoyData.credential_type}`);

        //. check RDP
        if(w_PortInfoyData.credential_type == 1)
        {
            let w_ret = await AutoCreateAndDelUser_RDP(parsedData);
            lv_fCreateUser_Start = false;
            return w_ret;
        }

        //console.log(w_PortInfoyData);
        //. Login to Server
        logger.status(`AutoCreateAndDelUser new SSHMng start`);

        let sshmng ;
        if(w_ownerChangePasswd == 1){
            sshmng = new SSHMng(w_PortInfoyData.target, w_PortInfoyData.target_port, w_PortInfoyData.tmp_username , w_PortInfoyData.tmp_password, w_PortInfoyData.tmp_key);
        }
        else{
            sshmng = new SSHMng(w_PortInfoyData.target, w_PortInfoyData.target_port, w_PortInfoyData.credential_username , w_PortInfoyData.credential_password, w_PortInfoyData.credential_key);
        }

        let connResult = null;
        if(w_PortInfoyData.credential_key.length > 0){
            connResult = await sshmng.connectServerPEM();
            w_CreateUser_Method = "PEM";
        }
        else{
            // connResult = await sshmng.connectServerPW();
            // w_CreateUser_Method = "PASSWD";
            logger.status(`AutoCreateAndDelUser can not work do it by password`);
            lv_fCreateUser_Start = false;
            return { status: 0, message: "can not work do it by password." };
        }


        if(connResult == null || connResult.status == 0 ){
            logger.status(`AutoCreateAndDelUser new SSHMng faild ....`);
            lv_fCreateUser_Start = false;
            return { status: 0, message: "backend server connection error." };
        }

        logger.status(`AutoCreateAndDelUser new SSHMng ok....`);

        let     w_user_timeout = convertUserTimeout(w_PortInfoyData.tmp_validate_time);
        let     w_Credential_PASSWD = "";
        let     w_Credential_KEY = "";
        let     w_CreateUserResult;

        //.
        if(w_userOpt == "useradd"){

            logger.status(`AutoCreateAndDelUser useradd .... command sudo pkill -9 -u `);

            let w_sCreateUserCMD = "sudo pkill -9 -u " + w_KenanUserName;
            await sshmng.runCommand(w_sCreateUserCMD, "/var");

            if(w_ownerChangePasswd != 1){
                w_sCreateUserCMD = `sudo deluser --remove-home ${w_KenanUserName}`;
                await sshmng.runCommand(w_sCreateUserCMD, "/var");
            }
            //. 
            logger.status(`AutoCreateAndDelUser useradd .... delCredentialUserFromServer w_KenanUserName = ${w_KenanUserName}`);
            delCredentialUserFromServer(w_KenanUserName, w_listen_port, 1);

            //. 
            if(w_CreateUser_Method == "PASSWD"){
                //. create user 
                // sudo useradd -m -s /bin/bash ${newUsername} && echo ${newUsername}:${newPassword} | sudo chpasswd
                w_Credential_PASSWD = generateSecurePassword();
                if(w_ownerChangePasswd == 1){
                    w_sCreateUserCMD = `echo ${w_KenanUserName}:${w_Credential_PASSWD} | sudo chpasswd`;
                }
                else{
                    w_sCreateUserCMD = `sudo useradd -m ${w_KenanUserName} && echo ${w_KenanUserName}:${w_Credential_PASSWD} | sudo chpasswd`;
                }
                w_CreateUserResult = await sshmng.runCommand(w_sCreateUserCMD, "/var");

                if(w_CreateUserResult.message.includes("exist")){
                    //. 


                    //. disconnect to server
                    await sshmng.disconnectServer();
                    lv_fCreateUser_Start = false;
                    return { status: 0, message: "user already exists" };
                }
            }
            //. w_CreateUser_Method = "PEM"
            else{
                w_Credential_PASSWD = generateSecurePassword();

                w_sCreateUserCMD = `id -u ${w_KenanUserName} 2>/dev/null`;
                w_CreateUserResult = await sshmng.runCommand(w_sCreateUserCMD, "/var");
                
                if (w_CreateUserResult.stdout.length > 0 && w_ownerChangePasswd == 1) {

                    logger.status(`w_CreateUserResult.stdout.length > 0 && w_ownerChangePasswd == 1, ${w_KenanUserName}`);
                    
                    w_sCreateUserCMD = `rm -f /home/${w_KenanUserName}/.ssh/*`;
                    w_CreateUserResult = await sshmng.runCommand(w_sCreateUserCMD, "/var");

                    w_sCreateUserCMD = `ssh-keygen -t ed25519 -f /home/${w_KenanUserName}/.ssh/temp_key -N "" -q`;
                    w_CreateUserResult = await sshmng.runCommand(w_sCreateUserCMD, "/var");

                    w_sCreateUserCMD = `touch /home/${w_KenanUserName}/.ssh/authorized_keys && chmod 700 /home/${w_KenanUserName}/.ssh && chmod 600 /home/${w_KenanUserName}/.ssh/authorized_keys`;
                    w_CreateUserResult = await sshmng.runCommand(w_sCreateUserCMD, "/var");

                    w_sCreateUserCMD = `cat /home/${w_KenanUserName}/.ssh/temp_key.pub | tee -a /home/${w_KenanUserName}/.ssh/authorized_keys >/dev/null`;
                    w_CreateUserResult = await sshmng.runCommand(w_sCreateUserCMD, "/var");

                    w_sCreateUserCMD = `cat /home/${w_KenanUserName}/.ssh/temp_key`;
                    w_CreateUserResult = await sshmng.runCommand(w_sCreateUserCMD, "/var");
        
                    logger.status(`w_CreateUserResult.stdout.length > 0 && w_ownerChangePasswd == 1 end`);

                    if(w_CreateUserResult.status == 1){
                        w_Credential_KEY = w_CreateUserResult.stdout + "\n";
        
                        if(w_CreateUserResult.stdout.length < 10 ){
                            w_CreateUserResult.status = 0;
                        }
                    } 
                
                } 
                else if((w_CreateUserResult.stdout == null || w_CreateUserResult.stdout.length <= 0) && w_ownerChangePasswd == 1){
                    logger.status(`(w_CreateUserResult.stdout == null || w_CreateUserResult.stdout.length <= 0) && w_ownerChangePasswd == 1`);
                    w_CreateUserResult.status = 0;
                }
                else if(w_ownerChangePasswd == 0) {
                    logger.status(`w_ownerChangePasswd == 0`);

                    w_sCreateUserCMD = `sudo useradd -m ${w_KenanUserName}`;
                    w_CreateUserResult = await sshmng.runCommand(w_sCreateUserCMD, "/var");
        
                    if(w_CreateUserResult.message.includes("exist")){
                        //. disconnect to server
                        // await sshmng.disconnectServer();
                        // return { status: 0, message: "user already exists" };
                    }
                    else{
                        //. 
                        w_sCreateUserCMD = `sudo -u ${w_KenanUserName} mkdir -p /home/${w_KenanUserName}/.ssh`;
                        w_CreateUserResult = await sshmng.runCommand(w_sCreateUserCMD, "/var");
            
                        w_sCreateUserCMD = `sudo ssh-keygen -t ed25519 -f /home/${w_KenanUserName}/.ssh/temp_key -N \"\" -q`;
                        w_CreateUserResult = await sshmng.runCommand(w_sCreateUserCMD, "/var");
            
                        w_sCreateUserCMD = `sudo -u ${w_KenanUserName} touch /home/${w_KenanUserName}/.ssh/authorized_keys && sudo chmod 700 /home/${w_KenanUserName}/.ssh && sudo chmod 600 /home/${w_KenanUserName}/.ssh/authorized_keys`;
                        w_CreateUserResult = await sshmng.runCommand(w_sCreateUserCMD, "/var");
            
                        w_sCreateUserCMD = `sudo cat /home/${w_KenanUserName}/.ssh/temp_key.pub | sudo tee -a /home/${w_KenanUserName}/.ssh/authorized_keys >/dev/null`;
                        w_CreateUserResult = await sshmng.runCommand(w_sCreateUserCMD, "/var");
                        
                    }
        
                    w_sCreateUserCMD = `sudo cat /home/${w_KenanUserName}/.ssh/temp_key`;
                    w_CreateUserResult = await sshmng.runCommand(w_sCreateUserCMD, "/var");
        
                    if(w_CreateUserResult.status == 1){
                        w_Credential_KEY = w_CreateUserResult.stdout + "\n";
        
                        if(w_CreateUserResult.stdout.length < 10 ){
                            w_CreateUserResult.status = 0;
                        }
                    }           
                }
                else{
                    logger.status(`param error w_ownerChangePasswd == 0`);
                    w_CreateUserResult.status = 0;
                }
            }
            //. 
            if(w_CreateUserResult.status == 1){
                //. disconnect to server
                await sshmng.disconnectServer();
                //.
                addCredentialUserFromServer(w_user_id, w_company_id, w_PortInfoyData.credential_type, w_PortInfoyData.target, w_listen_port, w_KenanUserName, w_Credential_PASSWD , w_Credential_KEY, 0, Date.now() , 1);
                if(w_CreateUser_Method == "PASSWD"){
                    lv_fCreateUser_Start = false;
                    if(w_ownerChangePasswd == 1) 
                        setChangePasswdFromServer(w_company_id, w_listen_port, w_Credential_PASSWD, "");
                    
                    return { status: 1, username: w_KenanUserName, password: w_Credential_PASSWD, key : "" , message: "create user ok." };
                }
                else{
                    lv_fCreateUser_Start = false;
                    if(w_ownerChangePasswd == 1) 
                        setChangePasswdFromServer(w_company_id, w_listen_port, "", w_Credential_KEY);
                    
                    return { status: 1, username: w_KenanUserName, password: "", key : w_Credential_KEY , message: "create user ok." };
                }
            }
            else{
                //. disconnect to server
                await sshmng.disconnectServer();
                lv_fCreateUser_Start = false;
                return { status: 0, message: "create user error." };
            }
        }
        else if(w_userOpt == "userdel"){
            //. delete user on backend server
            // let w_sCheckUserCMD = "sudo pkill -9 -u " + w_KenanUserName;
            // await sshmng.runCommand(w_sCheckUserCMD, "/var");
            
            // if(w_ownerChangePasswd != 1){
            //     w_sCheckUserCMD = "sudo deluser --remove-home " + w_KenanUserName;
            //     await sshmng.runCommand(w_sCheckUserCMD, "/var");
            // }
            // //. 
            // delCredentialUserFromServer(w_KenanUserName, w_listen_port, 1);
            // //. disconnect to server
            // await sshmng.disconnectServer();

            // lv_fCreateUser_Start = false;
            // return { status: 1, username: w_KenanUserName, message: "delete user ok." };
        }
        else{
            logger.status(`AutoCreateAndDelUser input praam error. `);
            lv_fCreateUser_Start = false;
            return { status: 0, message: "input praam error." };
        }

    } catch (error) {
        logger.status(`AutoCreateAndDelUser catch error. `);
        return { status: 0, message: `catch error ... AutoCreateAndDelUser : ${error.message}` };
    }
}

async function checkSSHUsers(credential_entry){

    try {
        //.
        w_listen_port = credential_entry.listen_port;
        const w_PortInfoyData = lv_policy_data.find(policy => policy.listen_port == w_listen_port && policy.is_direct == 0);
        if (!w_PortInfoyData) {
            return;
        }

//        let w_ownerChangePasswd = w_PortInfoyData.tmp_type;

        //. Login to Server
        let sshmng = new SSHMng(w_PortInfoyData.target, w_PortInfoyData.target_port, w_PortInfoyData.credential_username , w_PortInfoyData.credential_password, w_PortInfoyData.credential_key);

        let connResult = null;
        if(w_PortInfoyData.credential_key.length > 0){
            connResult = await sshmng.connectServerPEM();
        }
        else{
            //connResult = await sshmng.connectServerPW();
            return;
        }
        if(connResult == null || connResult.status == 0 ){
            return;
        }
        
        // //. getent passwd kenan06666002533 
        // let w_sCheckUserCMD = "sudo getent passwd " + credential_entry.name;
        // let w_ret = await sshmng.runCommand(w_sCheckUserCMD, "/var");
        // if(w_ret.status == 1 && w_ret.stdout.includes(credential_entry.name)){
        // }
        // else if(w_ret.status == 1 ){
        //     //. delete user (credential_entry.name)
        //     console.log(`checkSSHUsers delCredentialUserFromServer credential_entry.name : ${credential_entry.name}`);
        //     delCredentialUserFromServer(credential_entry.name, w_listen_port, 1);
        // }

        //let w_sCheckUserCMD;
        //let w_ret;

        let w_CurTime = Date.now() ;
        let w_nEndTime = parseInt(w_PortInfoyData.tmp_validate_time, 10) * 1000 + parseInt(credential_entry.local_created_at, 10);

        if(parseInt(w_nEndTime, 10) < parseInt(w_CurTime, 10) && lv_fCreateUser_Start == false){
            logger.status(`checkSSHUsers w_nEndTime < w_CurTime credential_entry.name : ${credential_entry.name}`);
            lv_fCreateUser_Start = true;
            let w_sCheckUserCMD = "sudo pkill -9 -u " + credential_entry.name;
            await sshmng.runCommand(w_sCheckUserCMD, "/var");

            let w_retCheckUserName = parseUserName(credential_entry.name);
            if(w_retCheckUserName.status == 1){
                w_sCheckUserCMD = `sudo deluser --remove-home ${credential_entry.name}`;
                await sshmng.runCommand(w_sCheckUserCMD, "/var");
                //.
                await sshmng.disconnectServer();
            }
            //. change password(key) information and send it to server
            else{
                await sshmng.disconnectServer();

                let temp_sshmng = new SSHMng(w_PortInfoyData.target, w_PortInfoyData.target_port, w_PortInfoyData.tmp_username , w_PortInfoyData.tmp_password, w_PortInfoyData.tmp_key);

                let connResult = await temp_sshmng.connectServerPEM();
                if(connResult.status == 1){
                    let w_KenanUserName = credential_entry.name;
                    let w_sCreateUserCMD = `rm -f /home/${w_KenanUserName}/.ssh/*`;
                    let w_CreateUserResult = await temp_sshmng.runCommand(w_sCreateUserCMD, "/var");
    
                    w_sCreateUserCMD = `ssh-keygen -t ed25519 -f /home/${w_KenanUserName}/.ssh/temp_key -N "" -q`;
                    w_CreateUserResult = await temp_sshmng.runCommand(w_sCreateUserCMD, "/var");
    
                    w_sCreateUserCMD = `touch /home/${w_KenanUserName}/.ssh/authorized_keys && chmod 700 /home/${w_KenanUserName}/.ssh && chmod 600 /home/${w_KenanUserName}/.ssh/authorized_keys`;
                    w_CreateUserResult = await temp_sshmng.runCommand(w_sCreateUserCMD, "/var");
    
                    w_sCreateUserCMD = `cat /home/${w_KenanUserName}/.ssh/temp_key.pub | tee -a /home/${w_KenanUserName}/.ssh/authorized_keys >/dev/null`;
                    w_CreateUserResult = await temp_sshmng.runCommand(w_sCreateUserCMD, "/var");
    
                    w_sCreateUserCMD = `cat /home/${w_KenanUserName}/.ssh/temp_key`;
                    w_CreateUserResult = await temp_sshmng.runCommand(w_sCreateUserCMD, "/var");
        
                    logger.status(`checkSSHUsers .... change password(key) information and send it to server`);
    
                    if(w_CreateUserResult.status == 1){
                        let w_Credential_KEY = w_CreateUserResult.stdout + "\n";
                        setChangePasswdFromServer(lv_company_id, credential_entry.listen_port, "", w_Credential_KEY);
                    } 
    
                    await temp_sshmng.disconnectServer();
                }
            }

            delCredentialUserFromServer(credential_entry.name, w_listen_port, 1);
            lv_fCreateUser_Start = false;
        }

        
        //. getent passwd | grep '^kenan'
        // w_sCheckUserCMD = `sudo getent passwd | grep \"^kenan\"`;
        // w_ret = await sshmng.runCommand(w_sCheckUserCMD, "/var");
        // if(w_ret.status == 1 ){
        //     const os_kenanusers = w_ret.stdout.split('\n').map(line => line.split(':')[0]);
        //     for (let i = os_kenanusers.length - 1; i >= 0; i--) {
        //         const os_kenanuser = os_kenanusers[i];
        //         //.
        //         if(os_kenanuser == null || os_kenanuser == ""){
        //             continue;
        //         }
        //         if(os_kenanuser.length < 14){
        //             continue;
        //         }
        //         if(lv_fCreateUser_Start == true){
        //             break;
        //         }
        //         lv_fCreateUser_Start = true;
        //         let w_credential_user = lv_credential_user_list.find(credential_user => credential_user.name == os_kenanuser);
        //         if(!w_credential_user){
        //             //. delete user (os_kenanuser)
        //             console.log(`checkSSHUsers os_kenanuser : ${os_kenanuser}`);
        //             // delCredentialUserFromServer(os_kenanuser);
        //             {
        //                 let w_sCheckUserCMD = "sudo pkill -9 -u " + os_kenanuser;
        //                 await sshmng.runCommand(w_sCheckUserCMD, "/var");
        //                 // if(w_ownerChangePasswd != 1){
        //                 //     w_sCheckUserCMD = `sudo deluser --remove-home ${os_kenanuser}`;
        //                 //     await sshmng.runCommand(w_sCheckUserCMD, "/var");
        //                 // }
        //             }
        //             lv_fCreateUser_Start = false;
        //             continue;
        //         }
        //         else{
        //             //. ok
        //         }
        //         lv_fCreateUser_Start = false;
        //     }
        // }


        //. pinky
        w_sCheckUserCMD = `sudo pinky`;
        w_ret = await sshmng.runCommand(w_sCheckUserCMD, "/var");
        if(w_ret.status == 1 ){
            const lines = w_ret.stdout.trim().split('\n');
            // Extract the Login column
            const pinky_users = lines.slice(1).map(line => {
                const columns = line.split(/\s+/);
                return {
                    Login: columns[0],
                    TTY: columns[1],
                    con_ip: columns[4],
                };
            });

            //. check multi-session
            for (let i = lv_credential_user_list.length - 1; i >= 0; i--) {
                const credential_user = lv_credential_user_list[i];
                //. 
                if(credential_user.listen_port != w_listen_port){
                    continue;
                }

                let   w_sFindName = credential_user.name;
                let   w_nFindCnt = 0;  
                for (let i = pinky_users.length - 1; i >= 0; i--) {
                    const pinky_user = pinky_users[i];
                    if(pinky_user.Login == w_sFindName){
                        w_nFindCnt++;
                    }
                }

                if(w_nFindCnt > 1){
                    let w_cmd = "sudo pkill -9 -u " + w_sFindName;
                    w_ret = await sshmng.runCommand(w_cmd, "/var");
                    //. report_tmp_user to server
                    console.log(`checkSSHUsers pinky multi-session : ${w_sFindName}`);
                    reportCredentialUserFromServer(lv_company_id, credential_entry.listen_port, credential_entry.target_ip, credential_entry.type , credential_entry.user_id, "", "multi-session")

                }

            }

            //const pinky_users = lines.slice(1).map(line => line.split(/\s+/)[0]);
            for (let i = pinky_users.length - 1; i >= 0; i--) {
                const pinky_user = pinky_users[i];
                if(pinky_user.Login.includes("kenan") && pinky_user.Login.length > 14){
                    //. Extract the user name and determine if the user is included in the currently logged in user_id, company_id
                    const w_ConUserName = lv_con_server_user_list.find(entry => entry.username == pinky_user.Login && entry.listen_port == w_listen_port)
                    if(!w_ConUserName){
                        //. sudo pkill -9 -u username
                        let w_cmd = "sudo pkill -9 -u " + pinky_user.Login;// del_pinky_user_command(pinky_user.Login, pinky_users);
                        w_ret = await sshmng.runCommand(w_cmd, "/var");
                        //. report_tmp_user to server
                        console.log(`checkSSHUsers pinky report_tmp_user to server : ${pinky_user.Login}`);
                        reportCredentialUserFromServer(lv_company_id, credential_entry.listen_port, credential_entry.target_ip, credential_entry.type , credential_entry.user_id, pinky_user.con_ip, "incorrect connection")

                    }
                    else{
                    }
                }
            }
        }

        //. disconnect to server
        await sshmng.disconnectServer();
    } catch (error) {
        return;
    }
}

async function checkRDPUsers(credential_entry){

    w_listen_port = credential_entry.listen_port;
    const w_PortInfoyData = lv_policy_data.find(policy => policy.listen_port == w_listen_port && policy.is_direct == 0);
    if (!w_PortInfoyData) {
        return;
    }
    // if(w_PortInfoyData.credential_username == null || w_PortInfoyData.credential_username.length <= 0 ){
    //     return;
    // }

    //let w_ownerChangePasswd = w_PortInfoyData.tmp_type;
    let w_retCheckUserName = parseUserName(credential_entry.name);

    let winrmmng;
    if(w_retCheckUserName.status == 0){
        winrmmng = new WinRMMng(w_PortInfoyData.target, w_PortInfoyData.target_port, w_PortInfoyData.tmp_username , w_PortInfoyData.tmp_password);
    }
    else{
        winrmmng = new WinRMMng(w_PortInfoyData.target, w_PortInfoyData.target_port, w_PortInfoyData.credential_username , w_PortInfoyData.credential_password);
    }

    let w_ret;
    let w_CurTime = Date.now() ;
    let w_nEndTime = parseInt(w_PortInfoyData.tmp_validate_time, 10) * 1000 + parseInt(credential_entry.local_created_at, 10);

    if(parseInt(w_nEndTime, 10) < parseInt(w_CurTime, 10)  && lv_fCreateUser_Start == false){
        logger.status(`checkRDPUsers w_nEndTime < w_CurTime ${credential_entry.name}`);
        lv_fCreateUser_Start = true;
        if(w_retCheckUserName.status == 0){
            await winrmmng.deleteRDPSession(credential_entry.name);
            //. change password(key) information and send it to server
            let w_Credential_PASSWD = generateSecurePassword();
            let w_CmdUserResult = await winrmmng.changeRDPUserPasswd(credential_entry.name, w_Credential_PASSWD);

            if(w_CmdUserResult.status == 1){
                setChangePasswdFromServer(lv_company_id, w_listen_port, w_Credential_PASSWD, "");
                logger.status(`checkSSHUsers .... change password(key) information and send it to server`);
            }
            else{
                logger.status(`checkRDPUsers w_nEndTime < w_CurTime changeRDPUserPasswd error `);
            }
        }
        else{
            await winrmmng.deleteRDPUserAndSession(credential_entry.name);
        }
        delCredentialUserFromServer(credential_entry.name, w_listen_port, 1);
        lv_fCreateUser_Start = false;
    }

    //. 
    // w_ret = await winrmmng.checkUserAtiveSession(credential_entry.name);
    // if(w_ret.status == 1){
    //     const w_ConUserName = lv_con_server_user_list.find(entry => entry.username == credential_entry.name)
    //     if(!w_ConUserName){

    //         let w_cmd = `logoff ${w_ret.id} /server:localhost`;
    //         await winrmmng.runCommand(w_cmd);

    //         //. report_tmp_user to server
    //         console.log(`checkRDPUsers checkUserAtiveSession : ${credential_entry.name}`);
    //         //reportCredentialUserFromServer(lv_company_id, credential_entry.listen_port, credential_entry.target_ip, credential_entry.type , credential_entry.user_id, "", "incorrect connection")
    //     }
    // }

}

let lv_credential_user_check_start = false;
function checkCredentialUsers(){

    if(lv_credential_user_check_start == true){
        return;
    }
    if(lv_get_credential_users_ok == false){
        return;
    }

    lv_credential_user_check_start = true;

    //. 
    for (let i = lv_credential_user_list.length - 1; i >= 0; i--) {
        const entry = lv_credential_user_list[i];
        
        if(entry.local_created_at == null || entry.local_created_at == ""){
            continue; 
        }


        generator_type = entry.generator_type; //. 0: KConnect, 1: KPrivate
        if(generator_type != 0){
            continue;
        }
        //. 
        login_type = entry.type; //. 1 : RDP , 2 : SSH
        if(login_type == 1){
            checkRDPUsers(entry);
        }
        else if(login_type == 2){
            checkSSHUsers(entry);
        }
        else{
            continue;
        }
    }

    lv_credential_user_check_start = false;

}

//. Main 
async function main() {
    try {
        //.
        LoopBackGetPolicyServer();
        WSS_ADMIN_Check_Login(43211);
        loginToAdminserver();
        setInterval(loginToAdminserver, 5000);
        getPortPolicyData();
        setInterval(getPortPolicyData, 5000);

        //.
        WSS_ADMIN_CONNECT_HTTPS(-1, -1, admin_port, gw_port, "10.6.0.16", 443, 0);
        WSS_SERVER_PRIVATE(private_listen_port);
        //INTERFACE_MAIN_ADMIN_HTTPS();

        //startServer();
        Init_GW_WSS_CONNECT();
        setInterval(Init_GW_WSS_CONNECT, LOOP_INIT_KCONNET_WS_TIME);
        //.
        setInterval(Ping_GW_WSS_CONNECT, PING_PONG_TIME_OUT);
        //.
        checkCredentialUsers();
        setInterval(checkCredentialUsers, 2000);

    } catch (error) {
        console.error(`Error in main: ${error.message}`);
    }
}

// Call the main function
main();
