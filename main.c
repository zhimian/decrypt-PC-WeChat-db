#include<stdio.h>
#include "crypto/pbkdf2_hmac.h"
#include "crypto/sha.h"
#include "crypto/aes.h"

#undef _UNICODE
#define SQLITE_FILE_HEADER "SQLite format 3" 
#define IV_SIZE 16
#define HMAC_SHA1_SIZE 20
#define KEY_SIZE 32

#define SL3SIGNLEN 20

#ifndef ANDROID_WECHAT
//4048数据 + 16IV + 20 HMAC + 12
#define DEFAULT_PAGESIZE 4096      
#define DEFAULT_ITER 64000
#else
#define NO_USE_HMAC_SHA1
#define DEFAULT_PAGESIZE 1024
#define DEFAULT_ITER 4000
#endif


//pc端密码是经过OllyDbg得到的32位pass。
BYTE pass[] = { 0x22,0xEB,0xED, 0xDD, 0x33, 0x27, 0x49, 0x3E,
				0x8D, 0x5F,0x8B, 0xD7, 0xFF, 0x02, 0x3D, 0x23, 
				0x5B, 0x0B, 0x53, 0xE6, 0x88, 0x7F, 0x43, 0x14,
				0x9A, 0x06, 0x80, 0x94, 0x7E, 0x50, 0x98, 0xC9 };
char dbfilename[50] = "ChatMsg.db";
int Decryptdb();

int main(int argc, char* argv[])
{
	/*
	if (argc >= 2)    //第二个参数argv[1]是文件名
		strcpy_s(dbfilename, argv[1]);  //复制    
										//没有提供文件名，则提示用户输入
	else {
		cout << "请输入文件名:" << endl;
		cin >> dbfilename;
	}*/
	//dbfilename = "ChatMsg.db";
	Decryptdb();
	return 0;
}

size_t open_file(BYTE ** pDbBuffer) {
	FILE* fpdb;
	fopen_s(&fpdb, dbfilename, "rb+");
	if (!fpdb)
	{
		printf("打开文件出错!");
		getchar();
		return 0;
	}

	fseek(fpdb, 0, SEEK_END);
	size_t nFileSize = ftell(fpdb);
	fseek(fpdb, 0, SEEK_SET);

	*pDbBuffer = (BYTE*)malloc(sizeof(BYTE)*nFileSize);
	fread(*pDbBuffer, 1, nFileSize, fpdb);
	fclose(fpdb);
	return nFileSize;
};

int Decryptdb()
{
	BYTE* pDbBuffer = NULL;
	size_t nFileSize = open_file(&pDbBuffer);
	

	BYTE salt[16] = { 0 };
	memcpy(salt, pDbBuffer, 16);

#ifndef NO_USE_HMAC_SHA1
	BYTE mac_salt[16] = { 0 };
	memcpy(mac_salt, salt, 16);
	for (int i = 0; i < sizeof(salt); i++)
		mac_salt[i] ^= 0x3a;
#endif

	int reserve = IV_SIZE;      //校验码长度,PC端每4KB有48B
#ifndef NO_USE_HMAC_SHA1
	reserve += HMAC_SHA1_SIZE;
#endif
	reserve = ((reserve % AES_BLOCK_SIZE) == 0) ? reserve : ((reserve / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;

	BYTE key[KEY_SIZE] = { 0 };
	BYTE mac_key[KEY_SIZE] = { 0 };
	PKCS5_PBKDF2_HMAC((const BYTE*)pass, sizeof(pass), 
		salt, sizeof(salt), DEFAULT_ITER, sizeof(key), key);
#ifndef NO_USE_HMAC_SHA1
	PKCS5_PBKDF2_HMAC((const BYTE*)key, sizeof(key), 
		mac_salt, sizeof(mac_salt), 2, sizeof(mac_key), mac_key);
#endif

	BYTE* pTemp = pDbBuffer;
	BYTE pDecryptPerPageBuffer[DEFAULT_PAGESIZE];
	int nPage = 1;
	int offset = 16;
	while (pTemp < pDbBuffer + nFileSize)
	{
		printf("解密数据页:%d/%d \n", nPage, nFileSize / DEFAULT_PAGESIZE);

#ifndef NO_USE_HMAC_SHA1
		BYTE hash_mac[HMAC_SHA1_SIZE] = { 0 };
		sha1_context hctx;
		SHA_Init(&hctx.ctx);
		sha1_hmac_starts(&hctx, mac_key, sizeof(mac_key));
		sha1_hmac_update(&hctx, pTemp + offset, DEFAULT_PAGESIZE - reserve - offset + IV_SIZE);//4096-48-16+16
		sha1_hmac_update(&hctx, (const BYTE*)& nPage, sizeof(nPage));
		sha1_hmac_finish(&hctx, hash_mac);
		BYTE* pHMAC = pTemp + DEFAULT_PAGESIZE - reserve + IV_SIZE;
		if (0 != memcmp(hash_mac, pHMAC, sizeof(hash_mac)))
		{
			printf("\n 哈希值错误! \n");
			getchar();
			return 0;
		}
#endif
		
		if (nPage == 1)
			memcpy(pDecryptPerPageBuffer, SQLITE_FILE_HEADER, offset);

		BYTE key_schedule[40];
		aes_key_setup(key, key_schedule, 256);
		aes_decrypt_cbc(
			pTemp + offset, DEFAULT_PAGESIZE - reserve - offset,
			pDecryptPerPageBuffer + offset,
			key_schedule, 256,
			pTemp + (DEFAULT_PAGESIZE - reserve)
		);

		
		memcpy(pDecryptPerPageBuffer + DEFAULT_PAGESIZE - reserve,
			pTemp + DEFAULT_PAGESIZE - reserve, 
			reserve);
		
		char decFile[1024] = { 0 };
		sprintf_s(decFile, 1024,"dec_%s", dbfilename);
		FILE * fp;
		fopen_s(&fp, decFile, "ab+");
		fwrite(pDecryptPerPageBuffer, 1, DEFAULT_PAGESIZE, fp);
		fclose(fp);
		

		nPage++;
		offset = 0;
		pTemp += DEFAULT_PAGESIZE;
	}
	printf("\n 解密成功! \n");
	getchar();
	return 0;
}