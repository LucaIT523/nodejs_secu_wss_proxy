#!/bin/bash

sudo systemctl stop kenan_mobile.service 

sudo systemctl disable kenan_mobile.service

rm -rf /opt/mobile
