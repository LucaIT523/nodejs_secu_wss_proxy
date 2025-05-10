<div align="center">
   <h1>nodejs_secu_wss_proxy</h1>
</div>


### **Description**



<div align="center">
   <img src=https://github.com/LucaIT523/nodejs_secu_wss_proxy/blob/main/images/1.png>
</div>



This project is an SSL-enabled WebSocket server application designed to manage client connections and route messages between clients and target servers.

The server uses SSL certificates for secure connections and processes client data based on certain criteria such as company ID and tokens.

The `client.js` file uses the configuration information in `config_agent.ini` to establish a WebSocket connection to the gateway server.

It manages the connection between the client and the WebSocket server and passes data.

This file manages the connection between the client and the WebSocket server and passes data.

This server application is designed to run as a service in a Linux environment and supports automatic restart and production setup configuration.

The HTTPS parking flow using WSS is as follows:

1. user, policy -> kagent -> kclient -> gw -> tcp router -> my security server

2. https browser -> kagent -> kclient -> gw -> kconnect , kprivate -> HTTPS Server

3. Moblie Browser -> mobile_proxy -> tcp router -> HTTPS Server



The above program will help you build an HTTPS proxy and secure transport using wss.

In order to adapt the communication method of kconnect and gw to IP changes using nginx, wss communication was performed with multiple session management by a single channel.



### **Contact Us**

For any inquiries or questions, please contact us.

telegram : @topdev1012

email :  skymorning523@gmail.com

Teams :  https://teams.live.com/l/invite/FEA2FDDFSy11sfuegI