#!/bin/bash

mkdir /opt/mobile

cp -rf ./* /opt/mobile

cd /opt/mobile

chmod -R 775 ./

cp -rf ./kenan_mobile.service /etc/systemd/system/

./node_install.sh

sudo systemctl daemon-reload

sudo systemctl enable kenan_mobile.service


sudo systemctl start kenan_mobile.service
