sudo iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner 1000 -j RETURN
sudo iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-port 3000
