#include <windows.h>
#include <assert.h>
#include <vector>
#include <Bcrypt.h>
#include <tchar.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#pragma comment(lib, "bcrypt.lib")


std::string hexToASCII(std::string hex)
{
    // initialize the ASCII code string as empty.
    std::string ascii = "";
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        // extract two characters from hex string
        std::string part = hex.substr(i, 2);

        // change it into base 16 and
        // typecast as the character
        char ch = stoul(part, nullptr, 16);

        // add this char to final ASCII string
        if(ch != '\0')
            ascii += ch;
    }
    return ascii;
}

int _tmain(int argc, _TCHAR* argv[])
{
    NTSTATUS bcryptResult = 0;
    DWORD bytesDone = 0;

    static const BYTE malNonce[] =
    {
        0x3B, 0x8A, 0x08, 0xED, 0x0F, 0x9E, 0x08, 0xCA, 0x57, 0x21, 0x09, 0xEF
    };
    static const BYTE malTag[] =
    {
        0xA3, 0xBE, 0xB4, 0x73, 0x64, 0x01, 0x09, 0xDF, 0xC4, 0x23, 0xF9, 0x82, 0xB7, 0xC6, 0xDB, 0x57
    };
    static const BYTE malKey[] =
    {
        0x21, 0xA1, 0xAC, 0xE1, 0xE6, 0x63, 0xBA, 0x45, 0x86, 0x4D, 0xF4, 0x57, 0xB2, 0x09, 0x18, 0x1E,
        0xBD, 0x90, 0x10, 0x1B, 0x4A, 0x51, 0x28, 0x40, 0x38, 0x7C, 0xD2, 0x10, 0xE5, 0x8F, 0xA3, 0xF1
    };
    static const BYTE malData[] =
    {
        0xa4,0xc1,0x05,0xb3,0x85,0xae,0xac,0xc5,0x0a,0xed,0xcc,0x5a,0x37,0xa0,0xf4,0x9e,0x90,0xce,
        0x2a,0xd1,0x7d,0xb8,0xfa,0xc2,0xa2,0xbf,0x4d,0xbe,0x08,0xc8,0x60,0x8c,0x6b,0x07,0x11,0xf7,
        0xfe,0xe3,0x41,0xa2,0x96,0xa6,0xa9,0xeb,0x80,0x07,0xa9,0xaf,0x35,0xea,0x1c,0xe2,0x82,0xf6,
        0x67,0xb3,0x10,0x77,0xdf,0x10,0x59,0x69,0xd2,0x49,0xde,0x11,0x95,0xd9,0xdd,0x72,0x20,0x63,
        0x20,0x49,0x54,0x62,0x49,0x48,0x65,0x1e,0x4f,0x5f,0xc0,0x25,0x67,0xc0,0x2b,0x52,0x37,0x57
    };
    

    BCRYPT_ALG_HANDLE algHandle = 0;
    bcryptResult = BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_AES_ALGORITHM, 0, 0);
    assert(BCRYPT_SUCCESS(bcryptResult) || !"BCryptOpenAlgorithmProvider");

    bcryptResult = BCryptSetProperty(algHandle, BCRYPT_CHAINING_MODE, (BYTE*)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    assert(BCRYPT_SUCCESS(bcryptResult) || !"BCryptSetProperty(BCRYPT_CHAINING_MODE)");

    BCRYPT_AUTH_TAG_LENGTHS_STRUCT authTagLengths;
    bcryptResult = BCryptGetProperty(algHandle, BCRYPT_AUTH_TAG_LENGTH, (BYTE*)&authTagLengths, sizeof(authTagLengths), &bytesDone, 0);
    assert(BCRYPT_SUCCESS(bcryptResult) || !"BCryptGetProperty(BCRYPT_AUTH_TAG_LENGTH)");

    DWORD blockLength = 0;
    bcryptResult = BCryptGetProperty(algHandle, BCRYPT_BLOCK_LENGTH, (BYTE*)&blockLength, sizeof(blockLength), &bytesDone, 0);
    assert(BCRYPT_SUCCESS(bcryptResult) || !"BCryptGetProperty(BCRYPT_BLOCK_LENGTH)");

    std::vector<BYTE> macContext(authTagLengths.dwMaxLength);
    

    BCRYPT_KEY_HANDLE malKeyHandle = 0;
    {
        bcryptResult = BCryptGenerateSymmetricKey(algHandle, &malKeyHandle, 0, 0, (PUCHAR)&malKey[0], sizeof(malKey), 0);
        assert(BCRYPT_SUCCESS(bcryptResult) || !"BCryptGenerateSymmetricKey");
    }
    DWORD malPartSize = sizeof(malData) / 2;
        
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO malInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(malInfo);
    malInfo.pbNonce = (PUCHAR)&malNonce[0];
    malInfo.cbNonce = sizeof(malNonce);
    malInfo.pbTag = (PUCHAR)&malTag[0];
    malInfo.cbTag = sizeof(malTag);
    malInfo.pbMacContext = &macContext[0];
    malInfo.cbMacContext = macContext.size();
        
        
    //Null IV value
    std::vector<BYTE> contextIV(blockLength);
    PBYTE pbPlainText = NULL;
    DWORD cbPlainOut = sizeof(malData);
    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainOut);
    ULONG bytesOut;
    bcryptResult = BCryptDecrypt
    (
        malKeyHandle,
        (PUCHAR)&malData,
        sizeof(malData),
        &malInfo,
        &contextIV[0],
        contextIV.size(),
        pbPlainText,
        cbPlainOut,
        &bytesOut, 0
    );
    assert(BCRYPT_SUCCESS(bcryptResult) || !"BCryptDecrypt");
    assert(bytesOut == cbPlainOut);

    std::stringstream cipherOut;
    //convert decrpyted bytes for return
    for (unsigned int i = 0; i < cbPlainOut; i++)
    {
        unsigned char c = ((char*)pbPlainText)[i];
        cipherOut << std::hex << std::setw(2) << std::setfill('0') << (0xff & c);

    }
    std::cout << "The Decrypted Content is: " << hexToASCII(cipherOut.str());


    // Cleanup
    BCryptDestroyKey(malKeyHandle);
    BCryptCloseAlgorithmProvider(algHandle, 0);

    return 0;
}
