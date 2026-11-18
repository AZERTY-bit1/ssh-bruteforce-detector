# 🚨 SSH Brute-Force Detector

![tests](https://github.com/AZERTY-bit1/ssh-bruteforce-detector/actions/workflows/tests.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.8%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

Reads your Linux server's `auth.log` and finds IP addresses that tried to guess SSH passwords. It even warns you if an attacking IP **managed to log in**!

## ✨ Features

- Counts failed SSH logins per IP
- Lists the usernames each IP tried
- Warns when a suspicious IP later logged in successfully
- Prints suggested `ufw` block rules (`--ufw`)
- Comes with a `sample_auth.log` to try it safely

## 🚀 Usage

No installation needed - only Python 3.8+.

```bash
git clone https://github.com/AZERTY-bit1/ssh-bruteforce-detector.git
cd ssh-bruteforce-detector
python ssh_detector.py sample_auth.log --ufw
sudo python ssh_detector.py /var/log/auth.log -t 10
```

## 📸 Example output

```
IP                                       FAILS  USERS TRIED
203.0.113.5                                  6  admin, oracle, root, test
192.0.2.44                                   5  bob
   !!! WARNING: 192.0.2.44 also logged in successfully as bob - check this account!

sudo ufw deny from 203.0.113.5
```

## 🧪 Tests

```bash
python -m unittest discover -s tests -v
```

## ⚠️ Disclaimer

This is a **defensive / educational** tool. Only use it on systems and data you own or are allowed to check.

## 📄 License

MIT - see [LICENSE](LICENSE).
