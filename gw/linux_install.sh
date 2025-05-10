#!/bin/bash

mkdir /opt/gw

cp -rf ./* /opt/gw

cd /opt/gw

chmod -R 775 ./

cp -rf ./kenan_gw.service /etc/systemd/system/

./node_install.sh

sudo systemctl daemon-reload

sudo systemctl enable kenan_gw.service


sudo systemctl start kenan_gw.service
