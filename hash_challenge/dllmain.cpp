// dllmain.cpp : Defines the entry point for the DLL application.
/*
This is the expected json associated to the challenge:
{
	"FileName": "hash_challenge.dll",
	"Description": "This is a challenge that verifies the integrity of a file by checking its hash against a known value",
	"Props": {
		"validity_time": 3600,
		"refresh_time": 3000
	},
	"Requirements": "none"
}
*/


/////  FILE INCLUDES  /////

#include "pch.h"
#include "context_challenge.h"
#include <stdio.h>
#include <stdlib.h>
#include <string>

#include <Wincrypt.h>




/////  GLOBAL VARIABLES  /////



/////  FUNCTION DEFINITIONS  /////

void getChallengeProperties();

/////  CUSTOM FUNCTIONS /////

#define BUFSIZE 1024
#define MD5LEN  16

//LPCWSTR filename = L"filename.txt";
const int len = 5;
LPCWSTR filenames[len] = { L"test.txt", L"test2.txt", L"test3.txt", L"test4.txt", L"test5.txt" };
const char* original_hashes[len] = { "d23bc0j7c6d15edf5", "d23bc07c6d15edf5","d23bc07c6d15edf5","d23bc07c6d15edf5","d23bc07c6d15edf5" };

DWORD check_if_same_hash(LPCWSTR filename, const char* original_hash) {
    DWORD result;
    BOOL bResult = FALSE;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;
    BYTE rgbFile[BUFSIZE];
    DWORD cbRead = 0;
    BYTE rgbHash[MD5LEN];
    DWORD cbHash = 0;
    CHAR rgbDigits[] = "0123456789abcdef";
    char* dst_hash = (char*)malloc(MD5LEN);
    char* first_position = dst_hash;
    // Logic to check usage goes here.

    hFile = CreateFile(filename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);

    if (INVALID_HANDLE_VALUE == hFile)
    {
        printf("Error opening file %s\nError: %d\n", filename,
            -1);
        return -1;
    }

    // Get handle to the crypto provider
    if (!CryptAcquireContext(&hProv,
        NULL,
        NULL,
        PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT))
    {
        printf("CryptAcquireContext failed: %d\n", -1);
        CloseHandle(hFile);
        return -1;
    }

    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
        printf("CryptAcquireContext failed: %d\n", -1);
        CloseHandle(hFile);
        CryptReleaseContext(hProv, 0);
        return -1;
    }
    
    while (bResult = ReadFile(hFile, rgbFile, BUFSIZE,&cbRead, NULL))
    {
        if (0 == cbRead)
        {
            break;
        }

        if (!CryptHashData(hHash, rgbFile, cbRead, 0))
        {
            printf("CryptHashData failed: %d\n", -1);
            CryptReleaseContext(hProv, 0);
            CryptDestroyHash(hHash);
            CloseHandle(hFile);
            return -1;
        }
    }

    if (!bResult)
    {
        printf("ReadFile failed: %d\n", -1);
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        CloseHandle(hFile);
        return -1;
    }

    cbHash = MD5LEN;
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        for (DWORD i = 0; i < cbHash; i++)
        {
            sprintf(dst_hash,"%c%c", rgbDigits[rgbHash[i] >> 4],
                rgbDigits[rgbHash[i] & 0xf]);
            dst_hash = dst_hash + 1;
        }
        first_position[(int)cbHash] = '\0';
        dst_hash = first_position;
        //printf("Destination hash %s", dst_hash);
        //printf("\n");
    }
    else
    {
        printf("CryptGetHashParam failed: %d\n", -1);
    }
    //printf("\n%s\n", dst_hash);
    if (strcmp(dst_hash, original_hash) == 0) // if they are equal compare returns 0
    {
        result= 0; //if equals return 0
    }
    else
    {
        result= 1; //if not equals return 1
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);

    return result;
}



/////  FUNCTION IMPLEMENTATIONS  /////

int init(struct ChallengeEquivalenceGroup* group_param, struct Challenge* challenge_param){

	int result = 0;


	// It is mandatory to fill these global variables
	group = group_param;
	challenge = challenge_param;
	if (group == NULL || challenge == NULL) {
		printf("---  Group or challenge are NULL \n");
		return -1;
	}
	printf("---  Initializing (%ws) \n", challenge->file_name);

	// Process challenge parameters
	getChallengeProperties();

	// It is optional to execute the challenge here
	result = executeChallenge();

	// It is optional to launch a thread to refresh the key here, but it is recommended
	if (result == 0) {
		launchPeriodicExecution();
	}

	return result;
}

int executeChallenge() {
    //int desired_array_results[len];
    int result;
    char* key = (char*)malloc(len+1);
    byte* new_key_data = (byte*)malloc(len+1);
    if (new_key_data == NULL)
    {
        return -1;
    }
    /*
    //initialize results array
    for (int i = 0; i < len; i++)
    {
        desired_array_results[i] = 0;
    }
    */
	printf("---  Executing challenge (%ws)\n", challenge->file_name);

	// Nullity check
	if (group == NULL || challenge == NULL)
		return -1;

    // Calculate new key (size, data and expire date)
    int new_size = sizeof(len);

    for (int i = 0; i < len; i++)
    {
        result = check_if_same_hash(filenames[i], original_hashes[i]); //OK
        /*
        if (result == 1)
        {
            key[i] = '1';
        }
        else
        {
            key[i] = '0';
        }
        printf("Key[%d] = %c\n", i, key[i]);
        */
    }
    //key[len] = '\0';
    //printf("\nkey: %s", key);
    if (0!=memcpy_s(new_key_data, (int)(len), (void*)key, (int)(len)))
    {
        free(new_key_data);
    }
    //printf("\nNew key data: %s", new_key_data);
    //printf("\n\n Challenge result: %d \n\n",result);

	time_t new_expires = time(NULL) + validity_time;

	// Update KeyData inside critical section
	EnterCriticalSection(&(group->subkey->critical_section));
	if ((group->subkey)->data != NULL) {
		free((group->subkey)->data);
	}
	group->subkey->data = new_key_data;
	group->subkey->expires = new_expires;
	group->subkey->size = new_size;
	LeaveCriticalSection(&(group->subkey->critical_section));
	return 0;	// Always 0 means OK.
}


void getChallengeProperties() {
	printf("---  Getting challenge parameters\n");
	json_value* value = challenge->properties;
	for (int i = 0; i < value->u.object.length; i++) {
		if (strcmp(value->u.object.values[i].name, "validity_time") == 0) {
			validity_time = (int)(value->u.object.values[i].value->u.integer);
		}
		else if (strcmp(value->u.object.values[i].name, "refresh_time") == 0) {
			refresh_time = (int)(value->u.object.values[i].value->u.integer);
		}
		else fprintf(stderr, "---  WARNING: the field '%s' included in the json configuration file is not registered and will not be processed.\n", value->u.object.values[i].name);
	}
	printf("---  Challenge properties: \n  validity_time = %d \n  refresh_time = %d \n ",
		validity_time, refresh_time);
}


BOOL APIENTRY DllMain( HMODULE hModule,
					   DWORD  ul_reason_for_call,
					   LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
