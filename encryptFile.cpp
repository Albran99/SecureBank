#include "cryptoUtility.h"

int main(int argc, char ** argv){
    EVP_PKEY* pubKey = readPublicKey("./server/server_rsa_pubkey.pem");
    if(!pubKey){
        cerr<<"Error in getting the public key for file enc\n";
        return false;
    }
    string clearFilePath = argv[1];
    int FileOrString = atoi(argv[2]);
    int len=0;
    unsigned char * clear_buf;
    if(FileOrString==0){
        clear_buf = readBinaryFile(clearFilePath, &len);
    }
    else{
        string f = argv[3];
        len=f.size()+1;
        clear_buf = (unsigned char *)malloc(len);
        memcpy(clear_buf,(unsigned char *)f.c_str(),f.size()+1);
    }
    int ciphlen=0;
    unsigned char * cptxt=createDigitalEnvelope(pubKey,"ENC",clear_buf, len, 0, ciphlen);

    DEBUG_PRINT(("CT in base64 %s", Base64Encode(cptxt, ciphlen).c_str()));

    writeBinaryFile(clearFilePath+".enc", cptxt, ciphlen);
    securefree(cptxt, ciphlen);
}