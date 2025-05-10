#!/bin/bash

sudo systemctl stop kenan_gw.service 

sudo systemctl disable kenan_gw.service

rm -rf /opt/gw
