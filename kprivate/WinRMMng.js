
const { exec, execSync } = require("child_process");

class WinRMMng {

    constructor(host, port, rootuser, rootpw) {
        this.host = host;
        this.port = port;
        this.rootuser = rootuser;
        this.rootpw = rootpw;
        this.max_timeout = 10000; 

    }

    async createRDPUser(username, passwd) {
        try {

            let w_cmd = `net user '${username}' '${passwd}' /add /fullname:'RDP Kenan User' /comment:'Kenan User for RDP access' /EXPIRES:NEVER`;
            let w_ret = await this.runCommand(w_cmd);
            if(w_ret.status == 1){
                w_cmd = `net localgroup 'Remote Desktop Users' ${username} /add`;
                w_ret = await this.runCommand(w_cmd);
                if(w_ret.status == 1){
                    // w_cmd = `WMIC USERACCOUNT WHERE Name='${username}' SET PasswordExpires=FALSE`;
                    // w_ret = await this.runCommand(w_cmd);
                    // if(w_ret.status == 1){
                        return { status: 1, message: `create user ok` };
                    // }
                    // else{
                    //     return { status: 0, message: `create user passwd change error` };
                    // }
                }
                else{
                    return { status: 0, message: `create user group error` };
                }
            }
            else{
                return { status: 0, message: `create user error` };
            }

        } catch (error) {
            return { status: 0, message: `create user catch error` };
        }
    }

    async changeRDPUserPasswd(username, passwd) {
        try {

            let w_cmd = `dir`;
            let w_ret = await this.runCommand(w_cmd);
            if(w_ret.status == 1){

                w_cmd = `net user '${username}' '${passwd}'`;
                w_ret = await this.runCommand(w_cmd);
    
                return { status: 1, message: `create user ok` };

            }
            else{
                return { status: 0, message: `change user runCommand error ` };
            }

        } catch (error) {
            return { status: 0, message: `catch user passwd error` };
        }
    }

    // 
    async deleteRDPUser(username) {
        try {

            let w_cmd = `net user ${username} /delete`;
            let w_ret = await this.runCommand(w_cmd);
            if(w_ret.status == 1){
                return { status: 1, message: `delete user ok` };
            }
            else{
                return { status: 0, message: `delete user error` };
            }
        } catch (error) {
            return { status: 0, message: `delete user catch error` };
        }
    }

    async deleteRDPUserAndSession(username) {
        try {

            let w_cmd = `net user ${username} /delete`;
            let w_ret = await this.runCommand(w_cmd);

            if(w_ret.status == 1){
                //. if user is exist, delete all session
                //. logoff <session ID> /server:localhost
                //console.log('user is exist, delete all session');

                let w_cmd = `query session /server:localhost`;
                let w_ret = await this.runCommand(w_cmd);

                // console.log("query session /server:localhost");
                // console.log(w_ret);
                //. 

                const lines = w_ret.stdout.split('\n');
                const activeSessions = lines
                    .map(line => line.trim().split(/\s+/)) 
                    .filter(columns => columns.length >= 4 && columns[3] === 'Active'); 
            
                if (activeSessions.length > 0) {
                    //. 
                    activeSessions.forEach(async (session) => {
                        if(session[1] == username){
                            w_cmd = `logoff ${session[2]} /server:localhost`;
                            await this.runCommand(w_cmd);
                        }
                    });
    
                }
                //. OK
                return { status: 1, message: `delete user ok` };
            }
            else{
                return { status: 0, message: `delete user error` };
            }
        } catch (error) {
            return { status: 0, message: `delete user catch error` };
        }
    }

    async deleteRDPSession(username) {
        try {

            let w_cmd = `query session /server:localhost`;
            let w_ret = await this.runCommand(w_cmd);

            const lines = w_ret.stdout.split('\n');
            const activeSessions = lines
                .map(line => line.trim().split(/\s+/)) 
                .filter(columns => columns.length >= 4 && columns[3] === 'Active'); 
        
            if (activeSessions.length > 0) {
                //. 
                activeSessions.forEach(async (session) => {
                    if(session[1] == username){
                        w_cmd = `logoff ${session[2]} /server:localhost`;
                        await this.runCommand(w_cmd);
                    }
                });

            }
            //. OK
            return { status: 1, message: `delete user ok` };
        } catch (error) {
            return { status: 0, message: `delete user catch error` };
        }
    }


    async checkUserAtiveSession(username) {
        try{
            let w_cmd = `query session /server:localhost`;
            let w_ret = await this.runCommand(w_cmd);
    
            // console.log("checkUserAtiveSession");
            // console.log(w_ret);
    
            //. 
            const lines = w_ret.stdout.split('\n');
            const activeSessions = lines
                .map(line => line.trim().split(/\s+/)) 
                .filter(columns => columns.length >= 4 && columns[3] === 'Active'); 
        
            if (activeSessions.length > 0) {
                //. 
                let w_bfind = 0;
                let w_nSeesion = -1;
                activeSessions.forEach(async (session) => {
                    if(session[1] == username){
                        w_bfind = 1;
                        w_nSeesion = session[2];
                    }
                });
    
                if(w_bfind == 1){
                    return { status: 1, id: w_nSeesion };
                }
                else{
                    return { status: 0, message: `no active session` };
                }
            }
            else{
                return { status: 0, message: `no active session` };
            }
        }
        catch (error) {
            return { status: 0, message: `checkUserAtiveSession catch` };
        }
    }



    async runCommand(command) {
        return new Promise((resolve, reject) => {
            const rdp_command = `kwinrm.exe ${this.host} ${this.rootuser} ${this.rootpw} \"${command}\"`;
            const child = exec(rdp_command, { encoding: 'utf8' }); // Use async exec
    
            let stdout = '';
            let stderr = '';
            let timeoutTriggered = false;
    
            // Set timeout control
            const timeoutId = setTimeout(() => {
                timeoutTriggered = true;
                child.kill(); // Terminate process
                reject(new Error(`Command timed out after ${this.max_timeout}ms`));
            }, this.max_timeout);
    
            // Stream handling
            child.stdout.on('data', (data) => stdout += data);
            child.stderr.on('data', (data) => stderr += data);
    
            // Process completion handler
            child.on('exit', (code) => {
                clearTimeout(timeoutId);
                if (timeoutTriggered) return; // Already handled by timeout

                // console.log(stdout);
                // console.log(stderr);
                if (stdout.includes("StatusCode: 0")) {
                    const rows = stdout.trim().split('\n'); 
                    const result = rows.slice(1).join('\n'); 
                    resolve({
                        status: 1,
                        stdout: result,
                        message: "Command executed successfully"
                    });
                } else {
                    const rows = stdout.trim().split('\n'); 
                    const result = rows.slice(1).join('\n'); 
                    resolve({
                        status: 0,
                        stdout: result,
                        message: `Command failed with code ${code}`
                    });
                }
            });
    
            child.on('error', (err) => {
                clearTimeout(timeoutId);
                reject({
                    status: 0,
                    stdout: "",
                    message: `Process error: ${err.message}`
                });
            });
        }).catch(error => ({
            status: 0,
            stdout: "",
            message: `catch error: ${error.message}`
        }));
    }
}

module.exports = WinRMMng;