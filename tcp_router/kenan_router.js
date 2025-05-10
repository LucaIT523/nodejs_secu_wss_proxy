const net = require('net');
const http = require('http'); // Ensure http is imported
const ini = require('ini'); // Import the ini package
const fs = require('fs'); // Required to read the config file
const replace = require('buffer-replace'); // Required to read the config file
const Logger = require('./Logger');
const WebSocket = require('ws');
const https = require('https');
const internal = require('stream');
//const { console } = require('inspector');
//const Throttle = require('throttle');
//const ntpClient = require('ntp-client');

// Read config.ini file
const config = ini.parse(fs.readFileSync('config_router.ini', 'utf-8'));
const policy_url = config.settings.policy_ip; // Get policy_url from config
const policy_port = config.settings.policy_port; // Get policy_url from config
const listen_port = config.settings.listen_port;
const log_level = config.settings.logLevel;
const logFile = config.settings.logFile;
const update_time = config.settings.update_time;
const token_end = "_kenan_agent_end_";

//. 
const LOOP_SKIP_CNT = 100;
const token_string = "_kenan_header_";
const logger = new Logger(log_level, logFile);


let StatusList = [];
function upsertUserSession(userId, sessionId) {
    const index = StatusList.findIndex(entry => entry.user_id === userId);
    
    if (index !== -1) {
        StatusList[index].session_id = sessionId;
    } else {
        StatusList.push({ user_id: userId, session_id: sessionId });
    }
}

function getSessionId(userId) {
    const entry = StatusList.find(entry => entry.user_id === userId);
    if (entry) {
        return entry.session_id;
    } else {
        return null;
    }
}


let policy_data = `[]`;
let m_devices = `[]`;
makeRequest();
startServer();
setInterval(makeRequest, update_time);


function getListenPortFromURLInfo(full_url) {
    try {
        for (let entry of policy_data) {
            if (full_url.includes(entry.target)) {
                return entry.listen_port;  //
            }
        }
        return -1;  
    } catch (err) {
        return -1;  
    }
}


function makeRequest() {
	const options = {
	    hostname: policy_url,
	    port: policy_port,
	    path: '/api/network/routing-rules',
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
                policy_data = responseJsonData.data.ports;
                m_devices = responseJsonData.data.mobile_devices;
                //console.log(m_devices);
            } catch (err) {
//                logger.error(`Failed to parse response from ${policy_url}:${policy_port}`);
//                logger.debug(policy_data.toString());
            }
        });
    });

    req.on('error', (error) => {
    });

    // End request
    req.end();
}


function getUtcTime() {
    const now = new Date();
    return now.toISOString(); 
}

// Periodic cleanup function
// function cleanupMemory() {
//     logger.status('Running periodic memory cleanup...');

//     // Log current memory usage
//     const memoryUsage = process.memoryUsage();
//     logger.status(`Memory usage before cleanup - RSS: ${memoryUsage.rss}, Heap: ${memoryUsage.heapUsed}/${memoryUsage.heapTotal}`);

//     // Force garbage collection (only if `--expose-gc` is enabled)
//     if (global.gc) {
//         global.gc();
//         logger.status('Garbage collection triggered.');
//     } else {
//         logger.status('Garbage collection not exposed. Run Node.js with the --expose-gc flag.');
//     }

//     // Log memory usage after cleanup
//     const updatedMemoryUsage = process.memoryUsage();
//     logger.status(`Memory usage after cleanup - RSS: ${updatedMemoryUsage.rss}, Heap: ${updatedMemoryUsage.heapUsed}/${updatedMemoryUsage.heapTotal}`);
// }

// // Set up periodic cleanup every 1 minutes (60000 ms)
// setInterval(cleanupMemory, 60000);

function ActiveStatusToAdminServer(realClientIP, user_id, machine_id, extractedPort, session_id, bps_speed, connect_status, delayTime, subTarget) {
    //. Testing
    if(extractedPort == 18889){
        return;
        extractedPort = 0;
    }

	const options = {
	    hostname: policy_url,
	    port: policy_port,
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
    });

    // Send the JSON data in the request body
    req.write(JSON.stringify(requestData));  // Convert the JS object to JSON string
//    console.log(requestData);
    // End request
    req.end();
}

function ProxyEngine(realClientIP, target, target_port, is_https, ws, extractedPort, left, reqActive, user_id, machine_id, session_id, bps_speed, delayTime){

    let     w_nConnectLoopCnt = LOOP_SKIP_CNT;  
    let     w_nRecvTarget_OK = 0;


    //logger.status(`ProxyEngine Start ${target} , ${target_port}`);

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


    // Throttling variables
    // const sendQueue = [];
    // let isProcessingQueue = false;
    // const sendInterval = 5; // 

    // Function to process the send queue
    // function processQueue() {
    //     if (isProcessingQueue || sendQueue.length === 0) return;

    //     isProcessingQueue = true;
    //     const chunk = sendQueue.shift();

    //     logger.status(`Sending chunk of size ${chunk.length} to WebSocket client`);
    //     ws.send(chunk);

    //     setTimeout(() => {
    //         isProcessingQueue = false;
    //         processQueue(); // Continue processing the queue
    //     }, sendInterval);
    // }

    // function flushQueue() {
    //     while (sendQueue.length > 0) {
    //         const chunk = sendQueue.shift();
    //         ws.send(chunk);
    //         //logger.status(`Flushed remaining chunk of size ${chunk.length}`);
    //     }
    // }

//    const throttle = new Throttle(1024 * 500);
//    targetSocket.pipe(throttle).on('data', (chunk) => {
    targetSocket.on('data', (chunk) => {
            //.
        if(reqActive == 1){
            //. running  
            if((w_nConnectLoopCnt % LOOP_SKIP_CNT) == 0){
                setImmediate(() => {
                    ActiveStatusToAdminServer(realClientIP, user_id, machine_id, extractedPort, session_id, bps_speed, 2, delayTime, target);
                });
                w_nConnectLoopCnt = 1;
            }
            else{
                w_nConnectLoopCnt = w_nConnectLoopCnt + 1;
            }
        }
        //.
        // sendQueue.push(chunk); // Add data to the queue
        // processQueue(); // Start processing the queue
        ws.send(chunk);
        w_nRecvTarget_OK = 1;
    });
    // .on('end', () => {
    //     logger.status(`Target socket ended. Flushing remaining data.`);
    //     flushQueue();
    // });

    // Handle errors and disconnections
    targetSocket.on('error', (err) => {
        //. if connect aaa.bbb.com 
        if(reqActive == 1 && w_nRecvTarget_OK == 0){
            setImmediate(() => {
                ActiveStatusToAdminServer(realClientIP, user_id, machine_id, extractedPort, session_id, bps_speed, 3, delayTime, target);
            });
        }      
        //  flushQueue();
        if(reqActive == 1){
            ws.close(); 
        }
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
        // flushQueue();
        if(reqActive == 1 /*&& is_https == 0*/){
            setImmediate(() => {
                ActiveStatusToAdminServer(realClientIP, user_id, machine_id, extractedPort, session_id, bps_speed, 0, delayTime, target);
            });
        }
        if(reqActive == 1){
            ws.close(); 
        }
    });
}

function startServer() {
    // Create an HTTP server to upgrade the connection to WebSocket

    const serverOptions = {
        key: fs.readFileSync('certs/kenan-tcp-router-wss.key'),   // Path to your private key file
        cert: fs.readFileSync('certs/kenan-tcp-router-wss.crt'),  // Path to your certificate file
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
            let bps_speed = 0;
            let delayTime = 0;
            let clientGlobalTime;
            let w_policy_url;
            let w_policy_port;
            let w_is_https;

            if (matchJson && matchJson[1]) {
                const parsedData = JSON.parse(matchJson[1]);
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

                w_is_https = parseInt(w_is_https, 10)
                extractedPort = parseInt(extractedPort, 10)
                //.
                message = message.replace(regex, "");  // Clean the message
                if (message.length > 0) 
                    left = message.substring(matchJson[1].length);

            } else {
                ws.close(); // Close connection if parsing fails
                return;
            }

            //. get policy data for Admin server on launcher
            if(extractedPort == 43210){
                //logger.status(`parseInt(user_id, 10) user_id = ${user_id}`);
                if(parseInt(user_id, 10) >= 0){
                    upsertUserSession(user_id, session_id);
                    //logger.status(`upsertUserSession user_id = ${user_id} , session_id = ${session_id}`);

                } 
                //. 
                ProxyEngine(realClientIP, policy_url, policy_port, 1, ws, extractedPort, left, 0, user_id, machine_id, session_id, bps_speed, delayTime);
            }
            //. from connecter to admin server in order to connect_admin
            else if(extractedPort == 8443){
                //. 
                ProxyEngine(realClientIP, w_policy_url, w_policy_port, 1, ws, extractedPort, left, 0, user_id, machine_id, session_id, bps_speed, delayTime);
            }
            else{
                //. only get data from kagent ( is not 43210)
                const clientUtcTime = new Date(clientGlobalTime); // 
                const serverUtcTime = new Date(getUtcTime()); // 
                delayTime = serverUtcTime - clientUtcTime; // 
                if(delayTime < 0){
                    delayTime = 0;
                }


                if(w_is_https == 0){
                    if(extractedPort == 18889){
                        logger.status(`extractedPort == 18889 Start`);
                        //. target port
                        const matchingMobilePolicy = m_devices.find(m_device => m_device.port == w_policy_port);
                        if (!matchingMobilePolicy) {
                            logger.status(`No matching matchingMobilePolicy ${w_policy_port}`);
                            ws.close(); // Close connection if no matching policy
                            return;
                        }
                        const { ip, port} = matchingMobilePolicy;
                        w_policy_url = ip;
                        w_policy_port = port;

                        //logger.status(`extractedPort == 18889 Start ${w_policy_url} , ${w_policy_port}`);

                    }
                    else{
                        // Find the matching policy entry based on the extracted port
                        const matchingPolicy = policy_data.find(policy => policy.listen_port == extractedPort);
                        if (!matchingPolicy) {
                            logger.error(`No matching policy found for client port ${extractedPort}`);
                            ws.close(); // Close connection if no matching policy
                            return;
                        }
                        const { target, target_port} = matchingPolicy;
                        w_policy_url = target;
                        w_policy_port = target_port;
                    }
                }
                else{
                    //. check extractedPort value
                    extractedPort = getListenPortFromURLInfo(w_policy_url);
                    if(extractedPort == -1){
                        ws.close(); // Close connection if no matching policy
                        return;
                    }
                }
                //.
                const nowSessionID = getSessionId(user_id);
                if(nowSessionID == null){
                    logger.status(`ProxyEngine nowSessionID == null user_id = ${user_id}`);
                    ws.close(); // Close connection if no matching policy
                    return;
                }
                if(nowSessionID != session_id){
                    logger.status(`ProxyEngine ${nowSessionID} != ${session_id} `);
                    ws.close(); // Close connection if no matching policy
                    return;
                }
                // Connect to the specified target server using the target and target_port from the matching policy
                logger.status(`ProxyEngine extractedPort == 18889 Start ${w_policy_url} , ${w_policy_port}`);
                ProxyEngine(realClientIP, w_policy_url, w_policy_port, w_is_https, ws, extractedPort, left, 1, user_id, machine_id, session_id, bps_speed, delayTime);

            }

        });
    });

    // Start the server
    server.listen(listen_port, '0.0.0.0', () => {
        logger.status(`111 WebSocket server started on port ${listen_port}`);
    });

    // Handle server errors
    server.on('error', (err) => {
        logger.error(`Server error on port ${listen_port}:`, err.message);
    });
    
}
