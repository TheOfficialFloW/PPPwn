opkg install python3 make
sudo pip install -r requirements.txt
read -p 'fw version ' fw
make -C stage1 FW=$fw clean && make -C stage1 FW=$fw
make -C stage2 $fw clean && make -C stage2 FW=$fw
sudo python3 pppwn.py --interface=lan --fw=$fw