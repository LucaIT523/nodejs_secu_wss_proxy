#!/bin/bash

sudo systemctl stop kenan_router.service 

sudo systemctl disable kenan_router.service

rm -rf /opt/router
