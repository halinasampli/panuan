#!/bin/bash

# Update dan instalasi paket
apt update -y
apt install unzip -y
apt install ubuntu-desktop -y
apt install xrdp -y
systemctl restart xrdp
apt-get install -qq -o=Dpkg::Use-Pty=0 openssh-server pwgen

# Menambahkan user
useradd -m Gilakau
adduser Gilakau sudo
echo Gilakau:SapuLidi10 | sudo chpasswd

# Ubah shell default ke bash
sed -i 's/\/bin\/sh/\/bin\/bash/g' /etc/passwd

# Konfigurasi SSH
mkdir -p /var/run/sshd
echo "PermitRootLogin yes" >> sudo /etc/ssh/sshd_config
echo "PasswordAuthentication yes" >> sudo /etc/ssh/sshd_config

# Konfigurasi library NVIDIA
echo "LD_LIBRARY_PATH=/usr/lib64-nvidia" >> sudo /root/.bashrc
echo "export LD_LIBRARY_PATH" >> sudo /root/.bashrc

# Jalankan SSH daemon
/usr/sbin/sshd -D &

# File setup
unzip a.zip
chmod u+x *
./loki authtoken 2fclAdTGUx9EWqgwyi7lOS3NTRG_7e36VvuPfVt5uvj8F8Z9c
./loki tcp 3389 &>/dev/null &

# Tunggu dan ambil data tunnel
sleep 5s
curl --silent --show-error http://127.0.0.1:4040/api/tunnels | sed -nE 's/.*public_url":"tcp:..([^"]*).*/\1/p'
sleep 20s

# Counter loop
counter=1
while [ $counter -le 21000 ]; do
    echo $counter
    sleep 1s
    ((counter++))
done
