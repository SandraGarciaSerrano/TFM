#!/bin/bash

import sys
import os

if sys.argv[1]=='SSM':
	os.system("ryu-manager --verbose IGMPv3/SSM/TFM_app3_SSM.py")
if sys.argv[1]=='ASM':
	os.system("ryu-manager --verbose IGMPv3/ASM/TFM_app3_ASM.py")
if sys.argv[1]=='Client':
	os.system("ryu-manager --verbose IGMPv3/Client/TFM_app3_client.py")
if sys.argv[1]=='Source':
	os.system("ryu-manager --verbose IGMPv3/Source/TFM_app3_source.py")

#Por defecto, IGMPv3. Pero, si se tuviese un equipo no compatible, se puede ejecutar IGMPv2.
#Poniendo otro parámetro extra $2
if sys.argv[1]=="IGMPv2":
	if sys.argv[2]=='ASM':
		#print('Hello')
		os.system("ryu-manager --verbose IGMPv2/TFM_app_ASM.py")
	if sys.argv[2]=='Client':
		os.system("ryu-manager --verbose IGMPv2/TFM_app_client.py")