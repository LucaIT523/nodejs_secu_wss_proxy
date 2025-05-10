const fs = require('fs');
const net = require('net');
const ini = require('ini');
const Logger = require('./Logger');
const WebSocket = require('ws');
const https = require('https');
const { exec, execSync } = require('child_process');
const replace = require('buffer-replace');

// Read config.ini file
const config = ini.parse(fs.readFileSync('config_client.ini', 'utf-8'));
const gw_ip = config.settings.gw_ip; // Get policy_url from config
const gw_port = config.settings.gw_port;
const log_level = config.settings.logLevel;
const logFile = config.settings.logFile;
const token_string = "_kenan_header_";
const logger = new Logger(log_level, logFile);

let global_ip = "";
let session_id = "";
let user_id = -1;

let lv_GW_Cert_OK = false;

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
function getDataFromLauncher() {

    try {
        // Read encrypted data from a file synchronously
        const data = fs.readFileSync('kclient_param.dat', 'utf8');

        // Decrypt the data
        const key = "_kenan-client-Param-2025-01-15_"; // Use the same key used for encryption
        const decrypted = XORCipher(data, key);
        
        const jsonData = JSON.parse(decrypted);
        if (jsonData.sign != "kenan_client_param"){
            return;
        }
        
        global_ip = jsonData.global_ip;
        session_id = jsonData.session_id;
        user_id = jsonData.user_id;

        //logger.status(` global_ip = ${global_ip},  session_id = ${session_id},  user_id = ${user_id},`);

        if(user_id == null || user_id == "" ){
            //logger.status(` user_id = -1`);
            user_id = -1;
        }
    } catch (err) {
        console.error('Error:', err);
    }
    //fs.unlinkSync('kclient_param.dat');
}
getDataFromLauncher();
setInterval(getDataFromLauncher, 1000);

//.
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
//.
function WSS_ConServer(listen_port){
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
        const ws = new WebSocket(`wss://${gw_ip}:${gw_port}/gw`, {
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
            //logger.status(`WSS_ConServer  global_ip = ${global_ip},  session_id = ${session_id},  user_id = ${user_id},`);

            const header = token_string + `{\"ip\":\"${global_ip}\",\"user_id\":\"${user_id}\",\"machine_id\":\"2222\",\"listen_port\":\"${listen_port}\", \"session_id\":\"${session_id}\" , \"company_id\":\"-111\"}`;
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

        from.on('error', (err) => {
            ws.close(); // Close WebSocket connection on error
        });

        // Handle client disconnection
        from.on('close', () => {
            ws.close();  // Close WebSocket connection
        });

        // Handle client and WebSocket connection errors
        ws.on('error', (err) => {
            from.end(); // Close client connection on error
        });
        // Handle WebSocket server disconnection
        ws.on('close', () => {
            from.end();
        });

    }).listen(listen_port, '0.0.0.0', () => {
        //logger.status(`Client started on port ${listen_port}`);
    });

    // Handle server errors
    server.on('error', (err) => {
        //logger.error(`Client error on port ${listen_port}:`, err.message);
    });
}

//. Policy Admin Server 
WSS_ConServer(43210);

startServer_agent_to_router();
//.
startServer_agent_direct();

//. 
function startServer_agent_to_router() {
    
    let target = gw_ip;
    let listen_port = 16443;
    let target_port = gw_port;

    // Create a TCP proxy server
    const server = net.createServer((from) => {
        const clientIP = from.remoteAddress;
        const localIP = from.localAddress;
        const clientPort = from.remotePort;
        
        //logger.status(`Client connected from IP: ${clientIP}:${clientPort} , VM Agent ${listen_port}`);
        //. 
        if(clientIP == localIP){
        }
        else{
            from.end(); 
            return;
        }

        // Connect to the target server
        const to = net.createConnection({
            host: target,
            port: target_port
        }, () => {
            if(lv_GW_Cert_OK == false){
                const ws_gw = new WebSocket(`wss://${gw_ip}:${gw_port}/gw`, {
                    rejectUnauthorized: false,
                });
                ws_gw.on('open', () => {
                    
                    const serverCertificate = ws_gw._socket.getPeerCertificate();
                    if(serverCertificate.fingerprint256 != g_gwCert256){
                        ws_gw.close();
                        to.end();
                        from.end();
                        return;
                    }
                    else{
                        lv_GW_Cert_OK = true;
                    }
                    ws_gw.close();
                });
                // Handle client and WebSocket connection errors
                ws_gw.on('error', (err) => {
                    console.log(`----- ${err.message}----`)
                });
                // Handle WebSocket server disconnection
                ws_gw.on('close', () => {
                });
            }
        });

        // // Forward data from client to target server
        // from.on('data', (chunk) => {
        //     to.write(chunk);
        // });
        // // Forward data from target server back to client
        // to.on('data', (chunk) => {
        //     from.write(chunk);
        // });
        from.pipe(to);
        to.pipe(from);

        // Handle client and target connection errors
        to.on('error', (err) => {
            from.end(); // Close client connection on error
        });
        from.on('error', (err) => {
            to.end(); // Close target connection on error
        });
        // Handle client disconnection
        from.on('close', () => {
            to.end();
        });
        // Handle target server disconnection
        to.on('close', () => {
            from.end();
        });

    }).listen(listen_port, '0.0.0.0', () => {
//        logger.status(`VM Agent server started on port ${listen_port} -> ${target}:${target_port}`);
    });

    // Handle server errors
    server.on('error', (err) => {
//        logger.status(`VM Agent server server error on port ${listen_port}:`, err.message);
    });

}

function ProxyEngine(realClientIP, target, target_port, ws, extractedPort, left, reqActive, user_id, machine_id, session_id){


    // Create a TCP connection to the target server
    const targetSocket = net.createConnection({
        host: target,
        port: target_port
    }, () => {
//        logger.status(`Connected to target ${target}:${target_port}, client ${extractedPort}`);
    });

    if (left) {
        targetSocket.write(Buffer.from(left));
    }

    // Forward WebSocket data to target server
    ws.on('message', (chunk) => {
        targetSocket.write(chunk);
    });

    // Forward target server data to WebSocket client
    targetSocket.on('data', (chunk) => {
        ws.send(chunk);
    });
    //targetSocket.pipe(ws);

    // Handle errors and disconnections
    targetSocket.on('error', (err) => {
        ws.close(); // Close WebSocket connection on error
    });

    ws.on('error', (err) => {
        targetSocket.end(); // Close target connection on error
    });
    // Handle WebSocket client disconnection
    ws.on('close', () => {
        targetSocket.end();
    });
    // Handle target server disconnection
    targetSocket.on('close', () => {
        ws.close();
    });
}

function startServer_agent_direct() {

    const   direct_listen_port = 16444;
    const serverOptions = {
        key: fs.readFileSync('certs/launcher.key'),   // Path to your private key file
        cert: fs.readFileSync('certs/launcher.crt'),  // Path to your certificate file
    };

    // Create an HTTPS server with SSL options
    const server = https.createServer(serverOptions);


    // Create WebSocket server
    const wss = new WebSocket.Server({ server });

    // Handle WebSocket connection
    wss.on('connection', (ws, req) => {
        const clientIP = req.socket.remoteAddress;
 
        // Handle incoming data from the WebSocket client
        ws.once('message', (message) => {
            message=message.toString();
  
            const regex = /_kenan_header_(\{.*?\})/; // Regex to capture the JSON object part
            const matchJson = message.match(regex);
            let left = null;
            let extractedPort = null;
            let realClientIP = "";
            let user_id = 0;
            let machine_id = "";
            let session_id = "";
            let direct_url = "";
            let direct_port = "";

            if (matchJson && matchJson[1]) {
                const parsedData = JSON.parse(matchJson[1]);
                extractedPort = parsedData.listen_port; // Extract the port field
                realClientIP = parsedData.ip;
                user_id = parsedData.user_id;
                machine_id = parsedData.machine_id;
                session_id = parsedData.session_id;
                direct_url = parsedData.policy_url;
                direct_port = parsedData.policy_port;

                message = message.replace(regex, "");  // Clean the message
                if (message.length > 0) 
                    left = message.substring(matchJson[1].length);
                
            } else {
                ws.close(); // Close connection if parsing fails
                return;
            }
            ProxyEngine(realClientIP, direct_url, direct_port, ws, extractedPort, left, 0, user_id, machine_id, session_id);

        });
    });

    // Start the server
    server.listen(direct_listen_port, '0.0.0.0', () => {
        logger.status(`WebSocket server started on port ${direct_listen_port}`);
    });

    // Handle server errors
    server.on('error', (err) => {
//        logger.error(`Server error on port ${direct_listen_port}:`, err.message);
    });
}