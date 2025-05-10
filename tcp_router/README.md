
# kenan2 router server

-- prepare

$ cd src/server

$ nano config_router.ini

set the API server here(10.6.0.14) for policy_ip

then type Ctrl+O(For saving), enter and then Ctrl+X(For exit)

$ sudo apt update

$ sudo apt install dos2unix


-- install kenan_router service

$ dos2unix ./*.sh

$ chmod +x *.sh

$ cp /etc/ssl/wss/* ./certs/


$ sudo ./linux_install.sh

$ systemctl status kenan_router

-- uninstall kenan_router service

$ sudo ./linux_uninstall.sh


-- start kenan_router service

$ sudo systemctl start kenan_router.service


-- stop kenan_router service

$ sudo systemctl stop kenan_router.service




