# WebShield AI — Termux & Linux Troubleshooting Guide

### 1. `pkg update` or repository lock errors in Termux
**Symptom**: `E: Could not get lock /data/data/com.termux/files/usr/var/lib/dpkg/lock`  
**Fix**:
```bash
# Terminate any hung background pkg processes
pkill -f apt
pkill -f dpkg
# Clear lock files safely if process is gone
rm -f $PREFIX/var/lib/dpkg/lock*
dpkg --configure -a
```

### 2. `pip install` fails with `externally-managed-environment`
**Symptom**: Modern Python distributions (Debian 12+ / Android Termux PEP 668) prevent raw `pip install`.  
**Fix**:
Use the `--break-system-packages` flag:
```bash
pip install -r requirements.txt --break-system-packages
```
Or use a Python virtual environment:
```bash
python3 -m venv ~/webshield-env
source ~/webshield-env/bin/activate
pip install -r requirements.txt
```

### 3. Permission denied when running `./run.sh` or `./install.sh`
**Fix**:
Ensure execution bits are set on all shell and python entry points:
```bash
chmod +x run.sh install.sh main.py
```

### 4. Viewing HTML Reports on your Android Phone
**Fix**:
Grant Termux storage permission so you can copy reports to your internal storage:
```bash
termux-setup-storage
cp reports/*.html ~/storage/shared/Download/
```
You can now open the `.html` report directly in Chrome, Firefox, or any phone browser from your `Downloads` folder!

### 5. `DNS Resolution failed` or socket timeout
**Cause**: The domain is either non-existent, has misconfigured nameservers, or your mobile network blocks external DNS requests.  
**Fix**:
- Test with Google Public DNS or Cloudflare DNS:
  `dig @1.1.1.1 your-domain.example`
- Verify your Wi-Fi or cellular connection has active internet access.
