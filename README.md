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


Ejemplo de configuracion json
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

### Funcionamiento

Evitar la modificación de ficheros sensibles o críticos en el equipo. Se hace uso de la librería Wincrypt para aplicar una función hash MD5 al contenido de una serie de ficheros. Este se compara con un hash original, que se considera válido, y si son diferentes, es posible afirmar que se ha producido una modificación.

Todas las funciones se encuentran en el fichero dll_main.cpp (aparte de las de context_challenge.h):
- init()
- executeChallenge()
- getChallengeParameters()
- check_if_same_hash(LPCWSTR filename, const char* original_hash)
La última es que la que se encarga de realizar la comparativa del hash original con el hash calculado en ese momento.

Inicialmente se concibió como un programa en C no parametrizable precisamente con el fin de dificultar su modificación; más difícil modificar un ejecutable C que un fichero de parámetros, aunque este esté permisionado (consideramos incluso que el atacante tenga permisos de superusuario).
No sería un challenge estrictamente hablando según la definición de Secureworld. No obstante, creemos que es interesante como herramienta para detectar intrusiones y encaja bien dentro del objetivo de Secureworld.
