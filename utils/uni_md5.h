#ifndef __UNI_MD5_H  
#define __UNI_MD5_H  

#define MD5_DECRYPT_LEN   16

typedef struct  
{  
    unsigned int count[2];  
    unsigned int state[4];  
    unsigned char buffer[64];     
}UNI_MD5_CTX_S;  

void uni_md5_init(UNI_MD5_CTX_S *context);
void uni_md5_update(UNI_MD5_CTX_S *context,const unsigned char *input,const unsigned int inputlen);
void uni_md5_final(UNI_MD5_CTX_S *context,unsigned char digest[16]);
void uni_md5_digest_tolal(const unsigned char *input, const unsigned int ilen, unsigned char output[16]);

#endif 