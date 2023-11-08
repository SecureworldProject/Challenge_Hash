# Challenges

Repository for the challenges within Secureworld project

## Some files that can be hashed

### SMB Protocol

RDBSS.sys
MRXSMB.sys
MRXSMB10.sys
MRXSMB20.sys
MUP.sys
SMBdirect.sys
SRVNET.sys
SRV.sys
SRV2.sys
SMBdirect.sys
En %windir%\system32:
srvsvc.dll

### SSH protocol:

C:\Users\Tecnalia\.ssh\known_hosts


### Windows Defender:

C:\Program Files\Windows Defender\*


ejemplo de configuracion json
```json
{
	"FileName": "hash_challenge.dll",
	"Description": "This is a challenge that verifies the integrity of a file by checking its hash against a known value",
	"Props": {
		"validity_time": 3600,
		"refresh_time": 3000
	},
	"Requirements": "none"
}
```
