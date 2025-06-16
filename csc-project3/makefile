.PHONY: all crack_attack attack_server clean

CRACK_ATTACK = crack_attack
ATTACK_SERVER = attack_server
BUILD_SCRIPT = build_echo.py
CRACK_SCRIPT = crack_attack.py
SIGN_KEY = dilithium3_priv.pem
ECHO_BINARY = happy_echo
SIGNATURE = signature.sig


all: $(CRACK_ATTACK) $(ATTACK_SERVER)

$(CRACK_ATTACK): $(CRACK_SCRIPT) $(BUILD_SCRIPT) $(SIGN_KEY)
	@echo "[+] Building happy_echo"
	python3 $(BUILD_SCRIPT)
	cp $(CRACK_SCRIPT) $(CRACK_ATTACK)
	chmod +x $(CRACK_ATTACK)

$(ATTACK_SERVER): 
	echo -e '#!/bin/sh\nwhile true; do echo "Fake server"; sleep 100; done' > $(ATTACK_SERVER)
	chmod +x $(ATTACK_SERVER)

clean:
	rm -f $(CRACK_ATTACK) $(ATTACK_SERVER) $(ECHO_BINARY) $(SIGNATURE) tmp_unsigned
