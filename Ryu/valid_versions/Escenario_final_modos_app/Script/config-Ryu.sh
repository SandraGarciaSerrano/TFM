#!/bin/bash

######################################################

######################################
# Script for execution of the Ryu app choosing controller mode #
######################################

#Name:        config-Ryu.sh

#Description:  When executing and choosing the mode, it deploys 
#				the correspondent application				

#Author:      Sandra Garcia
######################################################

#Libraries
import sys
import os

#Choose the mode
if sys.argv[1]=='SSM':
	os.system("ryu-manager --verbose TFM_app3_SSM.py")
if sys.argv[1]=='ASM':
	os.system("ryu-manager --verbose TFM_app3_ASM.py")
if sys.argv[1]=='Client':
	os.system("ryu-manager --verbose TFM_app3_client.py")
if sys.argv[1]=='Source':
	os.system("ryu-manager --verbose TFM_app3_source.py")
else:
	print("Choose the correct mode")

