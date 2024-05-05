#!/bin/bash
# Please use ./build.sh with the Firmware version ie. 900/1100 etc.
make -C stage1 FW=1100 clean && make -C stage1 FW=$1
make -C stage2 FW=1100 clean && make -C stage2 FW=$1
