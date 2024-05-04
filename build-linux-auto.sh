#!/bin/bash

# Supported Firmware 
FWS=( 850 900 903 904 950 960 1000 1001 1050 1070 1071 1100 )

# PARAM FW: "Firmware without '.'" or "all"
FW="all"

# PARAM OUT: PATH TO stage files (stageOut= "(PATHOUT)"/"(FIRMWARE with ".")"/"(stage1.bin/stage2.bin")
OUT="Stages"

# PARAM LOG ( "-d" "-1" )
# 1: "-d": Enable log "": Disable log
# 2: If 1=="-d" then if 2: "-1": log in 1 file or 1 log by Firmware
# 3: don't touch it must be empty
declare LOG=( "-d" "-1" "" )

# Function to Build stage1 and stage2 with the selected firmware version
build_stages() {
	FWOUT=${1}
        if [ ${#1} == 3 ];then
  		FWPOINT="${1:0:1}.${1:1}"
	elif [ ${#1} == 4 ];then
  		FWPOINT="${1:0:2}.${1:2}"
  	fi
	echo "FWPOINT = $FWPOINT"
	if [[ ! -e $OUT ]]; then
		mkdir $OUT
	fi
	if [[ ! -e "$OUT/$FWPOINT" ]]; then
		mkdir "$OUT/$FWPOINT"
	fi
	echo "Building stage1 with FW=${FWPOINT}..."
	if [[ "${LOG[0]}" == "-d" ]]; then
		if [[ "${LOG[1]}" == "-1" ]]; then
		  	LOGFILE=$OUT/build-linux-auto.log
		  	if [ -z "${LOG[2]}" ]; then
		  		make -C stage1 FW=$FWOUT clean && make -C stage1 FW=$FWOUT>$LOGFILE
		  		LOG[2]="true"
		  	else
		  		make -C stage1 FW=$FWOUT clean && make -C stage1 FW=$FWOUT>>$LOGFILE
		  	fi
		else
			LOGFILE=$OUT/${FWPOINT}/$FWOUT.log
			make -C stage1 FW=$FWOUT clean && make -C stage1 FW=$FWOUT>$LOGFILE
		fi
		echo "Building stage2 with FW=${FWPOINT}..."
		make -C stage2 FW=$FWOUT clean && make -C stage2 FW=$FWOUT>>$LOGFILE
	else
		make -C stage1 FW=$FWOUT clean && make -C stage1 FW=$FWOUT
		echo "Building stage2 with FW=${FWPOINT}..."
		make -C stage2 FW=$FWOUT clean && make -C stage2 FW=$FWOUT
	fi
	# Check for successful builds
	check_build "stage1/stage1.bin" $FWPOINT
	check_build "stage2/stage2.bin" $FWPOINT
	
	# Move to FW Directory
	echo "Move ${FWPOINT} stage1 to ${OUT}/${FWPOINT}/..."
	cp stage1/stage1.bin "$OUT/$FWPOINT/stage1.bin"
	echo "Move ${FWPOINT} stage2 to /${OUT}/${FWPOINT}/..."
	cp stage2/stage2.bin "$OUT/$FWPOINT/stage2.bin"
}

# Function to check file size greater than zero
check_build() {
    if [ -s "$1" ]; then
        echo "$2 $1 build successful."
    else
        echo "$2 $1 build failed or file is empty."
		read -p "Press enter key to continue..."
        exit 1
    fi
}


# Function to check if FW is in FWS
check_firmware(){
	for (( i=0;i<${#FWS[@]};i++ ));
	do
		if [[ ${1} == ${FWS[$i]} ]]; then
			return 0
		fi
	done
    	return -1
}

# Function to check if GCC is installed
check_gcc_installed() {
    	if ! command -v gcc &>/dev/null; then
        	echo "GCC is not installed. Please install GCC to continue."
        	echo "On Ubuntu/Debian: sudo apt-get install gcc"
        	echo "On Fedora: sudo dnf install gcc"
        	echo "On CentOS: sudo yum install gcc"
        	read -p "Press any key to continue..."
        	exit 1
        else
        	echo "GCC is installed."
    	fi
}

# Function to find Python 3 executable
find_python3() {
    	if command -v python3 &>/dev/null; then
        	echo "python3"
    	elif command -v python &>/dev/null; then
        	PYTHON_VERSION=$(python -c 'import platform; print(platform.python_version())' | cut -d '.' -f1)
        	if [ "$PYTHON_VERSION" -eq 3 ]; then
            		echo "python"
        	else
            		echo ""
        	fi
    	else
        	echo ""
    	fi
}

# Function to ensure Python 3 and Scapy are installed
ensure_python_and_scapy_installed() {
    	PYTHON=$(find_python3)

    	if [ -z "$PYTHON" ]; then
        	echo "Python 3 is not installed or not found. Please install Python 3."
        	echo "Download Python 3 from https://www.python.org/downloads/"
        	read -p "Press enter key to continue..."
        	exit 1
    	fi

    	# Check and install Scapy if not present
    	$PYTHON -c "import scapy" 2>/dev/null
    	if [ $? -ne 0 ]; then
		echo $?
        	echo "Scapy is not installed."
		echo "Installing Scapy..."
        	pip install scapy
        	# Double-check if Scapy installation succeeded
        	$PYTHON -c "import scapy" 2>/dev/null
        	if [ $? -ne 0 ]; then
        		echo "Failed to install Scapy."
			echo "Please check your Python/pip configuration."
			read -p "Press enter key to continue..."
            		exit 1
        	fi
    	fi
    	echo "Scapy is installed."
}

# Check if GCC is installed
check_gcc_installed

# Ensure Python 3 and Scapy are installed
ensure_python_and_scapy_installed

# Determine the firmware version based on $FW
if [ "$FW" == "all" ]; then
    for (( i=0;i<${#FWS[@]};i++ ));
	do
		build_stages ${FWS[$i]}
	done
else
	check_firmware $FW
	if [[ $1 == 1 ]]; then
		build_stages $FW
    	else
    		echo "Invalid Firmware : '${FW}'."
    		read -p "Press enter key to continue..."
    		exit 1
    	fi
fi

if [[ $FW == "all" ]];then
	echo "All builds completed successfully."
else
	echo "${FW} builds completed successfully."
fi
read -p "Press enter key to continue..."
exit 0
