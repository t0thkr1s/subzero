# subzero

[![made-with-python](http://forthebadge.com/images/badges/made-with-python.svg)](https://www.python.org/)
[![built-with-love](http://forthebadge.com/images/badges/built-with-love.svg)](https://github.com/t0thkr1s/)

subzero is a standalone passive subdomain enumeration tool that uses various sources to gather data.

## Download

```
git clone https://github.com/t0thkr1s/subzero
```

## Install

The script has only one dependency:

*   [rich](https://pypi.org/project/rich/)

You can install it by typing:

```
python3 setup.py install
```

## Run

```
python3 subzero.py [domain]
```

To save the results into a file, you can run it like this:

```
python3 subzero.py [domain] -o [file] 
```

## Screenshot


## APIs Used

- [Certspotter](https://sslmate.com/certspotter/api)
- [Shodan](https://shodan.io)
- [Omnisint](https://sonar.omnisint.io)
- [Hacker Target](https://hackertarget.com)
- [DNS Bufferover](https://dns.bufferover.run)
- [TLS Bufferover](https://tls.bufferover.run)
- [Sublist3r](https://github.com/aboul3la/Sublist3r)
- [VirusTotal](https://www.virustotal.com)
- [ThreatCrowd](https://www.threatcrowd.org)
- [SecurityTrails](https://securitytrails.com)
- [ThreatMiner](https://www.threatminer.org)
- [AlienVault](https://otx.alienvault.com)
- [UrlScan](https://urlscan.io)
- [Crt.sh](https://crt.sh)
- [Anubis](https://jldc.me)
- [DnsDB](https://api.dnsdb.info)
- [Recon.dev](https://recon.dev)
- [PassiveTotal](https://api.passivetotal.org)
- [Censys](https://censys.io)
- [Riddler](https://riddler.io)
- [Facebook](https://developers.facebook.com)
- [Binaryedge](https://binaryedge.io)
- [WhoisXMLAPI](https://www.whoisxmlapi.com)
- [Spyse](https://spyse.com)

### Disclaimer

> This tool is only for testing and academic purposes and can only be used where strict consent has been given. Do not use it for illegal purposes! It is the end user’s responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this tool and software.

## License

This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE) file for details
