#!/bin/sh
make -j4 || exit
make modules -j4 || exit
sudo make install || exit
sudo make modules_install || exit
#sudo update-initramfs -u -k all || exit
#sudo /etc/kernel/postinst.d/zz-update-efistub || exit
#sudo reboot
