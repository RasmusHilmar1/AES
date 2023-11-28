#include "AES.h"

//AES encryption function
int encrypt(const char *jsonFile, const char *key, const char *iv, const char *encryptedFile) {
    // Open json file
    FILE *fp = fopen(jsonFile, "rb");
    if (fp == NULL) {
        printf("Error opening file\n");
        return 1;
    }

    //Read json file into buffer
    char buffer[MAXBUFLEN];
    int n = fread(buffer, 1, MAXBUFLEN, fp);
    if (n == 0) {
        printf("Error reading file\n");
        fclose(fp);
        return 1;
    }

    //Close json file
    fclose(fp);

    //Set up AES key and IV
    AES_KEY aesKey;
    if (AES_set_encrypt_key((unsigned char *)key, 128, &aesKey) < 0) {
        printf("Error setting AES key\n");
        return 1;
    }

    unsigned char aesIv[MAXIVLEN];
    memcpy(aesIv, iv, MAXIVLEN);

    //Encrypt buffer
    AES_cbc_encrypt((unsigned char *)buffer, (unsigned char *)buffer, n, &aesKey, aesIv, AES_ENCRYPT);

    //Open encrypted file
    fp = fopen(encryptedFile, "wb");
    if (fp == NULL) {
        printf("Error opening file\n");
        return 1;
    }

    //Write encrypted buffer to encrypted file
    fwrite(buffer, 1, n, fp);

    //Close encrypted file
    fclose(fp);

    printf("File encrypted successfully.\n");
    return 0;
}

//AES decryption function
int decrypt(const char *encryptedFile, const char *key, const char *iv, const char *jsonFile) {
    //Open encrypted file
    FILE *fp = fopen(encryptedFile, "rb");
    if (fp == NULL) {
        printf("Error opening file\n");
        return 1;
    }

    //Read encrypted file into buffer
    char buffer[MAXBUFLEN];
    int n = fread(buffer, 1, MAXBUFLEN, fp);
    if (n == 0) {
        printf("Error reading file\n");
        fclose(fp);
        return 1;
    }

    //Close encrypted file
    fclose(fp);

    //Set up AES key and IV
    AES_KEY aesKey;
    if (AES_set_decrypt_key((unsigned char *)key, 128, &aesKey) < 0) {
        printf("Error setting AES key\n");
        return 1;
    }

    unsigned char aesIv[MAXIVLEN];
    memcpy(aesIv, iv, MAXIVLEN);

    //Decrypt buffer
    AES_cbc_encrypt((unsigned char *)buffer, (unsigned char *)buffer, n, &aesKey, aesIv, AES_DECRYPT);

    //Open json file
    fp = fopen(jsonFile, "wb");
    if (fp == NULL) {
        printf("Error opening file\n");
        return 1;
    }

    //Write decrypted buffer to json file
    fwrite(buffer, 1, n, fp);

    //Close json file
    fclose(fp);

    printf("File decrypted successfully.\n");
    return 0;
}

//Function that generates a random 128-bit key
int generateKey(char *key) {
    if (RAND_bytes((unsigned char *)key, MAXKEYLEN) != 1) {
        printf("Error generating key\n");
        return 1;
    }
    
    return 0;
}

//Function that generates a random 128-bit IV
int generateIV(char *iv) {
    if (RAND_bytes((unsigned char *)iv, MAXIVLEN) != 1) {
        printf("Error generating IV\n");
        return 1;
    }

    return 0;
}

int main() {
    // Generate random key
    char key[MAXKEYLEN];
    generateKey(key);

    // Generate random IV
    char iv[MAXIVLEN];
    generateIV(iv);

    // Encrypt json file
    char jsonFile[] = "input.json";
    char encryptedFile[] = "encrypted.bin";
    encrypt(jsonFile, key, iv, encryptedFile);

    // Decrypt encrypted file
    char decryptedFile[] = "decrypted.json";
    decrypt(encryptedFile, key, iv, decryptedFile);

    return 0;
}
