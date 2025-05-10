const { NodeSSH } = require('node-ssh');

class SSHMng {

    constructor(host, port, rootuser, rootpw, pemData) {
        this.host = host;
        this.port = port;
        this.rootuser = rootuser;
        this.rootpw = rootpw;
        this.pemData = pemData;
        this.max_timeout = 3000; 

        this.ssh = new NodeSSH();
        this.is_connected = false;
    }


    async connectServerPW() {
        const timeout = this.max_timeout; 
        let timeoutId;
    
        try {
            const connectionPromise = this.ssh.connect({
                host: this.host,
                port: this.port,
                username: this.rootuser,
                password: this.rootpw
            });
    
            // Create timeout rejector
            const timeoutPromise = new Promise((_, reject) => {
                timeoutId = setTimeout(() => {
                    this.ssh.dispose(); // Cleanup connection
                    reject(new Error("Connection timeout"));
                }, timeout);
            });
    
            // Race between connection and timeout
            await Promise.race([connectionPromise, timeoutPromise]);
            
            clearTimeout(timeoutId);
            this.is_connected = true;
            return { status: 1, message: "Connected successfully" };
    
        } catch (error) {
            this.is_connected = false;
            clearTimeout(timeoutId);
            return { status: 0, message: `${error.message}` };
        }
    }

    async connectServerPEM() {
        const timeout = this.max_timeout; 
        let timeoutId;
    
        try {
            const connectionPromise = this.ssh.connect({
                host: this.host,
                port: this.port,
                username: this.rootuser,
                privateKey: this.pemData
            });
    
            // Create timeout rejector
            const timeoutPromise = new Promise((_, reject) => {
                timeoutId = setTimeout(() => {
                    this.ssh.dispose(); // Cleanup connection
                    reject(new Error("Connection timeout"));
                }, timeout);
            });
    
            // Race between connection and timeout
            await Promise.race([connectionPromise, timeoutPromise]);
            
            clearTimeout(timeoutId);
            this.is_connected = true;
            return { status: 1, message: "Connected successfully" };
    
        } catch (error) {
            this.is_connected = false;
            clearTimeout(timeoutId);
            return { status: 0, message: `${error.message}` };
        }
    }
    //.
    async disconnectServer() {
        try {
            this.ssh.dispose();
            this.is_connected = false;
            return { status: 1, message: "Disconnected successfully" };
        } catch (error) {
            return { status: 0, message: `Disconnected failed: : ${error.message}` };

        }
    }

    async LoginAndRunCommand(p_command) {
        let connResult = await this.connectServerPW();
        if(connResult.status == 1){
    
            connResult = await this.runCommand(p_command, "/root");
            if(connResult.status == 1){
                this.disconnectServer();
                return { status: 1, message: `${connResult.stdout}` };
            }
            else{
                this.disconnectServer();
                return { status: 0, message: `${connResult.message}` };
            }
            
        }
        else{
            return { status: 0, message: `LoginAndRunCommand error : ${connResult.message}` };
        }
    }

    async LoginPEMAndRunCommand(p_command) {
        let connResult = await this.connectServerPEM();
        if(connResult.status == 1){
    
            connResult = await this.runCommand(p_command, "/root");
            if(connResult.status == 1){
                this.disconnectServer();
                return { status: 1, message: `${connResult.stdout}` };
            }
            else{
                this.disconnectServer();
                return { status: 0, message: `${connResult.message}` };
            }
            
        }
        else{
            return { status: 0, message: `LoginPEMAndRunCommand error : ${connResult.message}` };
        }
    }

    async runCommand(p_command, cwd_opt) {
        if (!this.is_connected) {
            return { status: 0, message: "Not connected to server" };
        }
    
        let timeoutId;
        try {
            const commandPromise = this.ssh.execCommand(p_command, {
                cwd: cwd_opt,
                execOptions: { timeout: this.max_timeout } // Set native timeout
            });
    
            // Create separate timeout controller
            const timeoutPromise = new Promise((_, reject) => {
                timeoutId = setTimeout(() => {
                    reject(new Error("Command execution timeout "));
                }, this.max_timeout);
            });
    
            // Race between command and timeout
            const result = await Promise.race([commandPromise, timeoutPromise]);
            
            clearTimeout(timeoutId);
            return {
                status: 1,
                code: result.code,
                stdout: result.stdout,
                message: result.stderr
            };
    
        } catch (error) {
            clearTimeout(timeoutId);
            return { 
                status: 0, 
                message: error.message.includes("timeout") 
                    ? `Command timed out after ${this.max_timeout}ms`
                    : `Execution failed: ${error.message}`
            };
        }
    }

}

module.exports = SSHMng;