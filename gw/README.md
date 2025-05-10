
# kenan2 gw server

-- prepare

$ cd src/gw

$ nano config_gw.ini

set the nginx proxy for TCP server here(10.0.0.7)

then type Ctrl+O(For saving), enter and then Ctrl+X(For exit)

$ sudo apt update

$ sudo apt install dos2unix


-- install kenan_gw service

$ dos2unix ./*.sh

$ chmod +x *.sh

$ cp /etc/ssl/wss/* ./certs/


$ sudo ./linux_install.sh

$ systemctl status kenan_gw



-- uninstall kenan_gw service

$ sudo ./linux_uninstall.sh


-- start kenan_gw service

$ sudo systemctl start kenan_gw.service


-- stop kenan_gw service

$ sudo systemctl stop kenan_gw.service

