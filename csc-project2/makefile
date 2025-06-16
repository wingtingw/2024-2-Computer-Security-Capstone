# Compiler and flags
CXX = g++
CXXFLAGS = -g -std=c++17 -Wall

# Targets and source files
TARGETS = icmp_redirect pharm_attack

# Default rule: build all targets and run setup
all: $(TARGETS)
	@echo "[+] Running setup..."
	sudo sysctl -w net.ipv4.conf.all.rp_filter=0
	sudo sysctl -w net.ipv4.conf.all.accept_local=1
	sudo sysctl -w net.ipv4.ip_forward=1
	sudo iptables -t raw -I PREROUTING 1 -p udp -s 192.168.64.24 --dport 53 -j NFQUEUE --queue-num 1

icmp_redirect: icmp_redirect.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

pharm_attack: pharm_attack.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< -lpcap -lnetfilter_queue -lnfnetlink

# Clean rule
clean:
	rm -f $(TARGETS)
