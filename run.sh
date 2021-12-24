cd /home/ubuntu/FileHosting/
sudo cat /etc/letsencrypt/live/nikitacartes.xyz/fullchain.pem > certs/cert_key.pem
sudo cat /etc/letsencrypt/live/nikitacartes.xyz/privkey.pem >> certs/cert_key.pem
sudo setcap CAP_NET_BIND_SERVICE=+eip /usr/bin/python3.9
python3 src --directory files --certificate certs/cert_key.pem 443