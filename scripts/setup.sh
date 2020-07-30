sudo useradd -M -s /sbin/nologin anyproxy
sudo iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner anyproxy -j RETURN
sudo iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-port 3000
