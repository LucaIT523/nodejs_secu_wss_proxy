#!/bin/bash

mkdir /opt/router

cp -rf ./* /opt/router

cd /opt/router

chmod -R 775 ./

cp -rf ./kenan_router.service /etc/systemd/system/

./node_install.sh

sudo systemctl daemon-reload

sudo systemctl enable kenan_router.service


sudo systemctl start kenan_router.service
