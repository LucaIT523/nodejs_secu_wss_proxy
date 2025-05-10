# kenan mobile_proxy server

-- prepare

$ cd src/mobile_proxy

$ nano config_mobile.ini

set the Kenan Server TCP server here(router_server=10.6.0.12)

then type Ctrl+O(For saving), enter and then Ctrl+X(For exit)

$ sudo apt update

$ sudo apt install dos2unix


-- install kenan_mobile service

$ dos2unix ./*.sh

$ chmod +x *.sh


$ sudo ./linux_install.sh


$ systemctl status kenan_mobile


-- uninstall kenan_mobile service

$ sudo ./linux_uninstall.sh


-- start kenan_mobile service

$ sudo systemctl start kenan_mobile.service


-- stop kenan_mobile service

$ sudo systemctl stop kenan_mobile.service

