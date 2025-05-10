const net = require('net');
const ini = require('ini');
const Logger = require('./Logger');
const WebSocket = require('ws');
const https = require('https');
const { exec, execSync } = require('child_process');
const replace = require('buffer-replace');
const fs = require('fs'); // Required to read the config file
const SSHMng = require('./SSHMng');
const WinRMMng = require('./WinRMMng');
const { generateSecurePassword, parseUserName, generateUserName } = require('./Util.js');


// Read config.ini file
const config = ini.parse(fs.readFileSync('config_private.ini', 'utf-8'));
const kconnect_server = config.settings.kconnect_server; // Get policy_url from config
const kconnect_port = config.settings.kconnect_port;
const log_level = config.settings.logLevel;
const logFile = config.settings.logFile;
const token_string = "_kenan_header_";
const logger = new Logger(log_level, logFile);

let lv_policy_data = [];
let lv_credential_user_list = [];
let lv_get_credential_users_ok = false;
let lv_con_server_user_list = [];


let lv_company_token = config.settings.company_token;


function ProxyEngine(realClientIP, target, target_port, ws, extractedPort, left, reqActive, user_id, machine_id, session_id, is_https){

    if(is_https == 0 ){
        const matchingPolicy = lv_policy_data.find(policy => policy.listen_port == extractedPort);
        if(matchingPolicy && (matchingPolicy.credential_type == 1 || matchingPolicy.credential_type == 2)){
            addConServerUserInfo(user_id, matchingPolicy.company_id, matchingPolicy.listen_port);
        }
    }

    // Create a TCP connection to the target server
    const targetSocket = net.createConnection({
        host: target,
        port: target_port
    }, () => {
        logger.status(`ProxyEngine Connected to target ${target}:${target_port}, client ${extractedPort}`);
    });

    if (left) {
        targetSocket.write(Buffer.from(left));
    }

    // Forward WebSocket data to target server
    ws.on('message', async(chunk) => {
        targetSocket.write(chunk);
    });

    // Forward target server data to WebSocket client
    targetSocket.on('data', async(chunk) => {
        //. 
        ws.send(chunk);
    });

    // Handle errors and disconnections
    targetSocket.on('error', (err) => {
        if(is_https == 0 ){
            const matchingPolicy = lv_policy_data.find(policy => policy.listen_port == extractedPort);
            if(matchingPolicy && (matchingPolicy.credential_type == 1 || matchingPolicy.credential_type == 2)){
                delConServerUserInfo(user_id, matchingPolicy.company_id, matchingPolicy.listen_port);
            }
        }
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
        if(is_https == 0 ){
            const matchingPolicy = lv_policy_data.find(policy => policy.listen_port == extractedPort);
            if(matchingPolicy && (matchingPolicy.credential_type == 1 || matchingPolicy.credential_type == 2)){
                delConServerUserInfo(user_id, matchingPolicy.company_id, matchingPolicy.listen_port);
            }
        }
        ws.close();
    });
}


async function private_startServer() {

    const listen_port = 443;
    const serverOptions = {
        key: fs.readFileSync('certs/kenan-private-wss.key'),   // Path to your private key file
        cert: fs.readFileSync('certs/kenan-private-wss.crt'),  // Path to your certificate file
    };

    // Create an HTTPS server with SSL options
    const server = https.createServer(serverOptions);


    // Create WebSocket server
    const wss = new WebSocket.Server({ server });

    // Handle WebSocket connection
    wss.on('connection', (ws, req) => {
        const clientIP = req.socket.remoteAddress;
 
        // Handle incoming data from the WebSocket client
        ws.once('message', async(message) => {
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
            let w_is_https;

            if (matchJson && matchJson[1]) {
                const parsedData = JSON.parse(matchJson[1]);

                if ('userOpt' in parsedData) {
                    w_userOpt = parsedData.userOpt;
                    logger.status(`private_startServer userOpt ----- ${w_userOpt}`);
                    //. 
                    let w_ret = await processUserCreation(parsedData);
                    if(w_ret == null){
                        w_ret = { status: 0, message: "processUserCreation return null." };
                    }
                    let w_data = JSON.stringify(w_ret);
                    ws.send(w_data);
                    //. 
                    return;
                } 
                else{
                    extractedPort = parsedData.listen_port; // Extract the port field
                    realClientIP = parsedData.ip;
                    user_id = parsedData.user_id;
                    machine_id = parsedData.machine_id;
                    session_id = parsedData.session_id;
                    direct_url = parsedData.policy_url;
                    direct_port = parsedData.policy_port;
                    w_is_https = parsedData.is_https;
        
                    message = message.replace(regex, "");  // Clean the message
                    if (message.length > 0) 
                        left = message.substring(matchJson[1].length);
                }
                
            } else {
                ws.close(); 
                return;
            }

            //. check policy data
            let w_policy_url = "";
            let w_policy_port = 443;

            if(w_is_https == 0){
                const matchingPolicy = lv_policy_data.find(policy => policy.listen_port == extractedPort);
                if (!matchingPolicy) {
                    logger.status(`private_startServer matchingPolicy error : ${extractedPort}  `);
                    ws.close(); 
                    return;
                }
                const { target, target_port} = matchingPolicy;
                w_policy_url = target;
                w_policy_port = target_port;
            }
            else{
                // extractedPort = getListenPortFromURLInfo(direct_url);
                // if(extractedPort == -1){
                //     logger.status(`private_startServer getListenPortFromURLInfo error : ${direct_url}  `);
                //     ws.close(); 
                //     return;
                // }
                w_policy_url = direct_url;
                w_policy_port = direct_port;
            }

            //. 
            logger.status(`private_startServer ProxyEngine w_policy_url : ${w_policy_url} `);
            ProxyEngine(realClientIP, w_policy_url, w_policy_port, ws, extractedPort, left, 0, user_id, machine_id, session_id, w_is_https);

        });
    });

    // Start the server
    server.listen(listen_port, '0.0.0.0', () => {
        logger.status(`private_startServer server started on port ${listen_port}`);
    });

    // Handle server errors
    server.on('error', (err) => {
        logger.error(`private_startServer error on port ${listen_port}:`, err.message);
    });
}
//.
function getPrivatePortPolicyData() 
{

    if (kconnect_server == null || kconnect_server == "") {
        logger.status(`getPrivatePortPolicyData error kconnect_server == null`);
        return;
    }

    const kconnectWS = new WebSocket(`wss://${kconnect_server}:${kconnect_port}`, {
        rejectUnauthorized: false,
    });

    //. 
    kconnectWS.on('open', () => {
        //. 
        // if(lv_GW_Cert_OK == false){
        //     const serverCertificate = ws._socket.getPeerCertificate();
        //     if(serverCertificate.fingerprint256 != g_gwCert256){
        //         ws.close();
        //         return;
        //     }
        //     else{
        //         lv_GW_Cert_OK = true;
        //     }
        // }
        let header = token_string + `{\"company_token\":\"${lv_company_token}\"}`;
        kconnectWS.send(header);
    });

    //.
    kconnectWS.on('message', (data) => {
        //. 
        const { clientId, payload } = JSON.parse(data.toString());
        if(clientId == "policy_data"){
            lv_policy_data = payload;
            // console.log('lv_policy_data ... ok');
            // console.log(lv_policy_data);

            //. 
            kconnectWS.send("_get_credential_user_lists_");  
        }
        else if(clientId == "credential_data"){
            lv_credential_user_list = payload;
            lv_get_credential_users_ok = true;

            // console.log('lv_credential_user_list ... ok');
            // console.log(lv_credential_user_list);

            kconnectWS.close();
        }

    });

    kconnectWS.on('error', (err) => {
        //logger.status(`getPrivatePortPolicyData kconnectWS error ${kconnect_server}:${kconnect_port} : ${err.message}`);
        kconnectWS.close();
    });

    kconnectWS.on('close', () => {
        //logger.status(`getPrivatePortPolicyData kconnectWS close ${kconnect_server}:${kconnect_port}`);
    });

}
////////////////////////////////////////////////////////////////////////////////////////
function setChangePasswdFromServer(company_id, listen_port, tmp_password, tmp_key){

    if (kconnect_server == null || kconnect_server == "") {
        logger.status(`setChangePasswdFromServer error kconnect_server == null`);
        return;
    }
    const kconnectWS = new WebSocket(`wss://${kconnect_server}:${kconnect_port}`, {
        rejectUnauthorized: false,
    });

    //. 
    kconnectWS.on('open', () => {
        //. 
        let header = token_string + `{\"company_token\":\"${lv_company_token}\", \"private_log\":\"1\"}`;
        kconnectWS.send(header);
    });

    kconnectWS.on('message', (data) => {
        let recv_msg = data.toString();
        if(recv_msg.includes("_recv_log_data_")){
            //. send log data
            const w_sendData = { company_id:company_id, listen_port: listen_port, tmp_password: tmp_password, tmp_key: tmp_key};
            //. 
            const send_message = {clientId:"change_pw",  payload: JSON.stringify(w_sendData)};
            kconnectWS.send((JSON.stringify(send_message)));

            //.
            //. update tmp_password, tmp_key of lv_policy_data
            const index = lv_policy_data.findIndex(entry => entry.listen_port == listen_port);
            if (index != -1) {
                lv_policy_data[index].tmp_password = tmp_password;
                lv_policy_data[index].tmp_key = tmp_key;

            } else {
            }
        }
    });

    kconnectWS.on('error', (err) => {
        kconnectWS.close();
    });

    kconnectWS.on('close', () => {
    });
}

function delCredentialUserFromServer(kenan_username, listen_port, kconnect_log) {

    if (kconnect_server == null || kconnect_server == "") {
        logger.status(`delCredentialUserFromServer error kconnect_server == null`);
        return;
    }

    let w_credential_user = lv_credential_user_list.find(credential_user => credential_user.name == kenan_username && credential_user.listen_port == listen_port);
    if(w_credential_user == null){
        logger.status(`delCredentialUserFromServer error w_credential_user == null , ${kenan_username}, ${listen_port}`);
        return;
    }

    const kconnectWS = new WebSocket(`wss://${kconnect_server}:${kconnect_port}`, {
        rejectUnauthorized: false,
    });

    //. 
    kconnectWS.on('open', () => {
        //. 
        let header = token_string + `{\"company_token\":\"${lv_company_token}\", \"private_log\":\"1\"}`;
        kconnectWS.send(header);
    });

    kconnectWS.on('message', (data) => {
        let recv_msg = data.toString();
        if(recv_msg.includes("_recv_log_data_")){
            //. send log data
            const w_sendData = { listen_port: listen_port, name: kenan_username};

            const send_message = {clientId:"delete_user",  payload: JSON.stringify(w_sendData)};
            kconnectWS.send((JSON.stringify(send_message)));

            //lv_credential_user_list = lv_credential_user_list.filter(credential_user => credential_user.name != kenan_username);
            lv_credential_user_list = lv_credential_user_list.filter(credential_user => !(credential_user.name == kenan_username && credential_user.listen_port == listen_port));
        }
    });

    kconnectWS.on('error', (err) => {
        kconnectWS.close();
    });

    kconnectWS.on('close', () => {
    });
}

function addCredentialUserFromServer(user_id, company_id, RDP_SSH_Type, target, listen_port, username, password , key, generator_type, local_created_at, kconnect_log) 
{
    if (kconnect_server == null || kconnect_server == "") {
        logger.status(`addCredentialUserFromServer error kconnect_server == null`);
        return;
    }
    const kconnectWS = new WebSocket(`wss://${kconnect_server}:${kconnect_port}`, {
        rejectUnauthorized: false,
    });

    //. 
    kconnectWS.on('open', () => {
        //. 
        let header = token_string + `{\"company_token\":\"${lv_company_token}\", \"private_log\":\"1\"}`;
        kconnectWS.send(header);
    });

    kconnectWS.on('message', (data) => {
        let recv_msg = data.toString();
        if(recv_msg.includes("_recv_log_data_")){
            //. send log data
            const w_sendData = { user_id: user_id, company_id:company_id, type: RDP_SSH_Type, target_ip: target, listen_port: listen_port, name: username, password: password, key: key, generator_type: generator_type, local_created_at: local_created_at};
            //. 
            const send_message = {clientId:"add_user",  payload: JSON.stringify(w_sendData)};
            kconnectWS.send((JSON.stringify(send_message)));

            //lv_credential_user_list = lv_credential_user_list.filter(credential_user => credential_user.name != username);
            lv_credential_user_list = lv_credential_user_list.filter(credential_user => !(credential_user.name == username && credential_user.listen_port == listen_port));
            lv_credential_user_list.push({ user_id: user_id, type: RDP_SSH_Type, target_ip: target, listen_port: listen_port, name: username, password: password, key: key, generator_type: generator_type, local_created_at: local_created_at});

        }
    });

    kconnectWS.on('error', (err) => {
        kconnectWS.close();
    });

    kconnectWS.on('close', () => {
    });

}
function reportCredentialUserFromServer(company_id, listen_port, target_ip, type , user_id, ip, description) {

    if (kconnect_server == null || kconnect_server == "") {
        logger.status(`reportCredentialUserFromServer error kconnect_server == null`);
        return;
    }
    const kconnectWS = new WebSocket(`wss://${kconnect_server}:${kconnect_port}`, {
        rejectUnauthorized: false,
    });

    //. 
    kconnectWS.on('open', () => {
        //. 
        let header = token_string + `{\"company_token\":\"${lv_company_token}\", \"private_log\":\"1\"}`;
        kconnectWS.send(header);
    });

    kconnectWS.on('message', (data) => {
        let recv_msg = data.toString();
        if(recv_msg.includes("_recv_log_data_")){
            //. send log data
            const w_sendData = { user_id: user_id, company_id:company_id, type: type, target_ip: target_ip, listen_port: listen_port, ip: ip, description: description};
            //. 
            const send_message = {clientId:"report_user",  payload: JSON.stringify(w_sendData)};
            kconnectWS.send((JSON.stringify(send_message)));

        }
    });

    kconnectWS.on('error', (err) => {
        kconnectWS.close();
    });

    kconnectWS.on('close', () => {
    });

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

    const index = lv_con_server_user_list.findIndex(entry => entry.username == w_ConUserName);
    if (index != -1) {
    } else {
        lv_con_server_user_list.push({ username: w_ConUserName});
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

    lv_con_server_user_list = lv_con_server_user_list.filter(entry => entry.username !== w_ConUserName);
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
    const w_PortInfoyData = lv_policy_data.find(policy => policy.listen_port == w_listen_port);
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
        if(w_ownerChangePasswd == 1){
            await winrmmng.deleteRDPSession(w_KenanUserName);
        }
        else{
            await winrmmng.deleteRDPUserAndSession(w_KenanUserName);
        }
        delCredentialUserFromServer(w_KenanUserName, w_listen_port, 0);

        //.
        let w_Credential_PASSWD = generateSecurePassword();
        if(w_ownerChangePasswd == 1){
            w_CmdUserResult = await winrmmng.changeRDPUserPasswd(w_KenanUserName, w_Credential_PASSWD);
        }
        else{
            w_CmdUserResult = await winrmmng.createRDPUser(w_KenanUserName, w_Credential_PASSWD);
        }
        if(w_CmdUserResult.status == 1){
            addCredentialUserFromServer(w_user_id, w_company_id, w_PortInfoyData.credential_type, w_PortInfoyData.target, w_listen_port, w_KenanUserName, w_Credential_PASSWD , "", 1, Date.now() , 0);
            if(w_ownerChangePasswd == 1) 
                setChangePasswdFromServer(w_company_id, w_listen_port, w_Credential_PASSWD, "");

            return { status: 1, username: w_KenanUserName, password: w_Credential_PASSWD, key : "" , message: "create user ok." };
        }
        else{
            return { status: 0, message: "useradd createRDPUser error." };
        }
    }
    else if(w_userOpt == "userdel"){

        //  await winrmmng.deleteRDPUserAndSession(w_KenanUserName);
        // delCredentialUserFromServer(w_KenanUserName, 0);
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
        const w_PortInfoyData = lv_policy_data.find(policy => policy.listen_port == w_listen_port);
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

        logger.status(`AutoCreateAndDelUser new SSHMng start`);
        
        //. Login to Server
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


            logger.status(`AutoCreateAndDelUser useradd .... delCredentialUserFromServer w_KenanUserName = ${w_KenanUserName}`);
            //. 
            delCredentialUserFromServer(w_KenanUserName, w_listen_port, 0);
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

                console.log(`w_CreateUser_Method = PEM 1  `);
                console.log(w_CreateUserResult);

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

                    console.log(`w_CreateUserResult.stdout.length > 0 && w_ownerChangePasswd == 1`);
                    
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
        
                    if(w_CreateUserResult.status == 1){
                        w_Credential_KEY = w_CreateUserResult.stdout + "\n";
        
                        if(w_CreateUserResult.stdout.length < 10 ){
                            w_CreateUserResult.status = 0;
                        }
                    } 
                
                } 
                else if((w_CreateUserResult.stdout == null || w_CreateUserResult.stdout.length <= 0) && w_ownerChangePasswd == 1){
                    console.log(`(w_CreateUserResult.stdout == null || w_CreateUserResult.stdout.length <= 0) && w_ownerChangePasswd == 1`);
                    w_CreateUserResult.status = 0;
                }
                else if(w_ownerChangePasswd == 0) {
                    console.log(`w_ownerChangePasswd == 0`);

                    w_sCreateUserCMD = `sudo useradd -m ${w_KenanUserName}`;
                    w_CreateUserResult = await sshmng.runCommand(w_sCreateUserCMD, "/var");
        
                    console.log(`w_CreateUser_Method = PEM 1  `);
                    console.log(w_CreateUserResult);
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
        
                    // console.log(`w_CreateUser_Method = PEM 7  `);
                    // console.log(w_CreateUserResult);
        
                    if(w_CreateUserResult.status == 1){
                        w_Credential_KEY = w_CreateUserResult.stdout + "\n";
        
                        if(w_CreateUserResult.stdout.length < 10 ){
                            w_CreateUserResult.status = 0;
                        }
                    }           
                }
                else{
                    console.log(`param error w_ownerChangePasswd == 0`);
                    w_CreateUserResult.status = 0;
                }
            }
            //. 
            if(w_CreateUserResult.status == 1){
                //. disconnect to server
                await sshmng.disconnectServer();
                //.
                addCredentialUserFromServer(w_user_id, w_company_id, w_PortInfoyData.credential_type, w_PortInfoyData.target, w_listen_port, w_KenanUserName, w_Credential_PASSWD , w_Credential_KEY, 1, Date.now(), 0);
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
            let w_sCheckUserCMD = "sudo pkill -9 -u " + w_KenanUserName;
            await sshmng.runCommand(w_sCheckUserCMD, "/var");
            
            if(w_ownerChangePasswd != 1){
                w_sCheckUserCMD = "sudo deluser --remove-home " + w_KenanUserName;
                await sshmng.runCommand(w_sCheckUserCMD, "/var");
            }
            //. 
            delCredentialUserFromServer(w_KenanUserName, w_listen_port, 0);
            //. disconnect to server
            await sshmng.disconnectServer();

            lv_fCreateUser_Start = false;
            return { status: 1, username: w_KenanUserName, message: "delete user ok." };
        }
        else{
            lv_fCreateUser_Start = false;
            return { status: 0, message: "input praam error." };
        }
    } catch (error) {
        logger.status(`AutoCreateAndDelUser catch error. `);
        return { status: 0, message: `catch error ... AutoCreateAndDelUser : ${error.message}` };
    }
}

async function checkSSHUsers(credential_entry){

    try{
        //.
        w_listen_port = credential_entry.listen_port;
        const w_PortInfoyData = lv_policy_data.find(policy => policy.listen_port == w_listen_port);

        if (!w_PortInfoyData) {
            return;
        }

        //let w_ownerChangePasswd = w_PortInfoyData.tmp_type;
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
        //     delCredentialUserFromServer(credential_entry.name, 1);
        // }
        let w_sCheckUserCMD;
        let w_ret;

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
                        setChangePasswdFromServer("", credential_entry.listen_port, "", w_Credential_KEY);
                    } 

                    await temp_sshmng.disconnectServer();
                }
            }

            delCredentialUserFromServer(credential_entry.name, w_listen_port, 0);
            lv_fCreateUser_Start = false;
        }

        // //. getent passwd | grep '^kenan'
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

        //                 // w_sCheckUserCMD = `sudo systemctl stop ${os_kenanuser}-delete.timer`;
        //                 // await sshmng.runCommand(w_sCheckUserCMD, "/var");
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
        // w_sCheckUserCMD = `sudo pinky`;
        // w_ret = await sshmng.runCommand(w_sCheckUserCMD, "/var");
        // if(w_ret.status == 1 ){
        //     const lines = w_ret.stdout.trim().split('\n');
        //     // Extract the Login column
        //     const pinky_users = lines.slice(1).map(line => {
        //         const columns = line.split(/\s+/);
        //         return {
        //             Login: columns[0],
        //             TTY: columns[1],
        //             con_ip: columns[4],
        //         };
        //     });

        //     //. check multi-session
        //     for (let i = lv_credential_user_list.length - 1; i >= 0; i--) {
        //         const credential_user = lv_credential_user_list[i];
        //         let   w_sFindName = credential_user.name;
        //         let   w_nFindCnt = 0;  
        //         for (let i = pinky_users.length - 1; i >= 0; i--) {
        //             const pinky_user = pinky_users[i];
        //             if(pinky_user.Login == w_sFindName){
        //                 w_nFindCnt++;
        //             }
        //         }

        //         if(w_nFindCnt > 1){
        //             let w_cmd = "sudo pkill -9 -u " + w_sFindName;
        //             w_ret = await sshmng.runCommand(w_cmd, "/var");
        //             //. report_tmp_user to server
        //             console.log(`checkSSHUsers pinky multi-session : ${w_sFindName}`);
        //             reportCredentialUserFromServer(lv_company_id, credential_entry.listen_port, credential_entry.target_ip, credential_entry.type , credential_entry.user_id, "", "multi-session")
        //         }

        //     }

        //     //const pinky_users = lines.slice(1).map(line => line.split(/\s+/)[0]);
        //     for (let i = pinky_users.length - 1; i >= 0; i--) {
        //         const pinky_user = pinky_users[i];
        //         if(pinky_user.Login.includes("kenan") && pinky_user.Login.length > 14){
        //             //. Extract the user name and determine if the user is included in the currently logged in user_id, company_id
        //             const w_ConUserName = lv_con_server_user_list.find(entry => entry.username == pinky_user.Login)
        //             if(!w_ConUserName){
        //                 //. sudo pkill -9 -u username
        //                 let w_cmd = "sudo pkill -9 -u " + pinky_user.Login;// del_pinky_user_command(pinky_user.Login, pinky_users);
        //                 w_ret = await sshmng.runCommand(w_cmd, "/var");
        //                 //. report_tmp_user to server
        //                 console.log(`checkSSHUsers pinky report_tmp_user to server : ${pinky_user.Login}`);
        //                 reportCredentialUserFromServer(lv_company_id, credential_entry.listen_port, credential_entry.target_ip, credential_entry.type , credential_entry.user_id, pinky_user.con_ip, "incorrect connection")

        //             }
        //             else{
        //             }
        //         }
        //     }
        // }

        //. disconnect to server
        await sshmng.disconnectServer();
    } catch (error) {
        return;
    }
}


async function checkRDPUsers(credential_entry){

    w_listen_port = credential_entry.listen_port;
    const w_PortInfoyData = lv_policy_data.find(policy => policy.listen_port == w_listen_port);
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
                setChangePasswdFromServer("", w_listen_port, w_Credential_PASSWD, "");
            }
            else{
                logger.status(`checkRDPUsers w_nEndTime < w_CurTime changeRDPUserPasswd error `);
            }
        }
        else{
            await winrmmng.deleteRDPUserAndSession(credential_entry.name);
        }

        delCredentialUserFromServer(credential_entry.name, w_listen_port, 0);
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

    // console.log(`checkCredentialUsers start  `);
    // console.log(lv_credential_user_list);
    //. 
    for (let i = lv_credential_user_list.length - 1; i >= 0; i--) {
        const entry = lv_credential_user_list[i];

        if(entry.local_created_at == null || entry.local_created_at == ""){
            continue; 
        }

        generator_type = entry.generator_type; //. 0: KConnect, 1: KPrivate
        if(generator_type != 1){
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
        private_startServer();

        getPrivatePortPolicyData();
        setInterval(getPrivatePortPolicyData, 5000);
        //.
        checkCredentialUsers();
        setInterval(checkCredentialUsers, 2000);

    } catch (error) {
        console.error(`Private Error in main: ${error.message}`);
    }
}

// Call the main function
main();