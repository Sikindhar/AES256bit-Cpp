#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <cstring>
#include <cstdint>


// dint use namespace std ... as we are having so many other librariess too 


const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

const uint8_t Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};


constexpr int Nb = 4;         
constexpr int Nk = 8;        
constexpr int Nr = 14;        

uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    uint8_t high_bit;
    
    for (int i = 0; i < 8; i++) {
        if (b & 1)
            p ^= a;
            
        high_bit = (a & 0x80);
        a <<= 1;
        if (high_bit)
            a ^= 0x1b; 
            
        b >>= 1;
    }
    
    return p;
}


typedef uint8_t State[4][4];


void SubBytes(State state) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = sbox[state[i][j]];
        }
    }
}


void InvSubBytes(State state) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = inv_sbox[state[i][j]];
        }
    }
}


void ShiftRows(State state) {
    uint8_t temp;
    

    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;
    

    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;
    

    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

void InvShiftRows(State state) {
    uint8_t temp;
    

    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;
    

    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;


    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}


void MixColumns(State state) {
    uint8_t a[4];
    uint8_t b[4];
    
    for (int c = 0; c < 4; c++) {
        for (int i = 0; i < 4; i++) {
            a[i] = state[i][c];
            b[i] = (state[i][c] << 1) ^ (0x1B & -(state[i][c] >> 7));
        }
        
        state[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
        state[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
        state[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
        state[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3];
    }
}


void InvMixColumns(State state) {
    uint8_t a[4];
    
    for (int c = 0; c < 4; c++) {
        for (int i = 0; i < 4; i++) {
            a[i] = state[i][c];
        }
        
        state[0][c] = gmul(a[0], 0x0e) ^ gmul(a[1], 0x0b) ^ gmul(a[2], 0x0d) ^ gmul(a[3], 0x09);
        state[1][c] = gmul(a[0], 0x09) ^ gmul(a[1], 0x0e) ^ gmul(a[2], 0x0b) ^ gmul(a[3], 0x0d);
        state[2][c] = gmul(a[0], 0x0d) ^ gmul(a[1], 0x09) ^ gmul(a[2], 0x0e) ^ gmul(a[3], 0x0b);
        state[3][c] = gmul(a[0], 0x0b) ^ gmul(a[1], 0x0d) ^ gmul(a[2], 0x09) ^ gmul(a[3], 0x0e);
    }
}


void AddRoundKey(State state, const uint32_t* roundKey) {
    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            state[r][c] ^= (roundKey[c] >> (8 * (3 - r))) & 0xFF;
        }
    }
}


void KeyExpansion(const uint8_t* key, uint32_t* expandedKey) {
    uint32_t temp;
    int i = 0;
    
    while (i < Nk) {
        expandedKey[i] = ((uint32_t)key[4*i] << 24) | 
                         ((uint32_t)key[4*i+1] << 16) | 
                         ((uint32_t)key[4*i+2] << 8) | 
                         ((uint32_t)key[4*i+3]);
        i++;
    }
    
    i = Nk;
    

    while (i < Nb * (Nr + 1)) {
        temp = expandedKey[i-1];
        
        if (i % Nk == 0) {

            temp = ((temp << 8) | (temp >> 24));
            
            temp = ((uint32_t)sbox[(temp >> 24) & 0xFF] << 24) |
                   ((uint32_t)sbox[(temp >> 16) & 0xFF] << 16) |
                   ((uint32_t)sbox[(temp >> 8) & 0xFF] << 8) |
                   ((uint32_t)sbox[temp & 0xFF]);
            
            
            temp ^= ((uint32_t)Rcon[i/Nk] << 24);
        } else if (Nk > 6 && i % Nk == 4) {
            
            temp = ((uint32_t)sbox[(temp >> 24) & 0xFF] << 24) |
                   ((uint32_t)sbox[(temp >> 16) & 0xFF] << 16) |
                   ((uint32_t)sbox[(temp >> 8) & 0xFF] << 8) |
                   ((uint32_t)sbox[temp & 0xFF]);
        }
        
        expandedKey[i] = expandedKey[i-Nk] ^ temp;
        i++;
    }
}


void AES_encrypt(const uint8_t* input, uint8_t* output, const uint32_t* roundKeys) {
    State state;
    
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            state[r][c] = input[r + 4*c];
        }
    }
    

    AddRoundKey(state, roundKeys);
    

    for (int round = 1; round < Nr; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * 4);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + Nr * 4);
    

    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            output[r + 4*c] = state[r][c];
        }
    }
}


void AES_decrypt(const uint8_t* input, uint8_t* output, const uint32_t* roundKeys) {
    State state;
    

    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            state[r][c] = input[r + 4*c];
        }
    }
    

    AddRoundKey(state, roundKeys + Nr * 4);
    

    for (int round = Nr - 1; round > 0; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys + round * 4);
        InvMixColumns(state);
    }
    

    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys);
    

    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            output[r + 4*c] = state[r][c];
        }
    }
}


std::vector<uint8_t> padInput(const std::string& input) {
    size_t inputLength = input.length();
    size_t paddedLength = ((inputLength + 15) / 16) * 16;  
    uint8_t padValue = paddedLength - inputLength;
    
    std::vector<uint8_t> paddedInput(paddedLength);
    

    for (size_t i = 0; i < inputLength; i++) {
        paddedInput[i] = input[i];
    }
    

    for (size_t i = inputLength; i < paddedLength; i++) {
        paddedInput[i] = padValue;
    }
    
    return paddedInput;
}


std::string removePadding(const std::vector<uint8_t>& paddedData) {
    if (paddedData.empty()) {
        return "";
    }
    
    uint8_t padValue = paddedData.back();
    
    if (padValue > 16 || padValue == 0) {
        return std::string(paddedData.begin(), paddedData.end());
    }
    
    for (int i = 0; i < padValue; i++) {
        if (paddedData[paddedData.size() - 1 - i] != padValue) {
            return std::string(paddedData.begin(), paddedData.end());
        }
    }
    
    return std::string(paddedData.begin(), paddedData.end() - padValue);
}

std::vector<uint8_t> encryptAES256(const std::string& plaintext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {

    std::vector<uint8_t> paddedInput = padInput(plaintext);
    
    std::vector<uint8_t> ciphertext(paddedInput.size());
    
    uint32_t expandedKey[Nb * (Nr + 1)];
    KeyExpansion(key.data(), expandedKey);
    
    std::vector<uint8_t> prevBlock = iv;
    
    for (size_t i = 0; i < paddedInput.size(); i += 16) {
        for (int j = 0; j < 16; j++) {
            paddedInput[i + j] ^= prevBlock[j];
        }
        
        AES_encrypt(&paddedInput[i], &ciphertext[i], expandedKey);
        
        for (int j = 0; j < 16; j++) {
            prevBlock[j] = ciphertext[i + j];
        }
    }
    
    return ciphertext;
}

std::string decryptAES256(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
    std::vector<uint8_t> plaintext(ciphertext.size());
    
    uint32_t expandedKey[Nb * (Nr + 1)];
    KeyExpansion(key.data(), expandedKey);
    
    std::vector<uint8_t> prevBlock = iv;
    
    for (size_t i = 0; i < ciphertext.size(); i += 16) {
        uint8_t temp[16];
        
        AES_decrypt(&ciphertext[i], temp, expandedKey);
        
        for (int j = 0; j < 16; j++) {
            plaintext[i + j] = temp[j] ^ prevBlock[j];
        }

        for (int j = 0; j < 16; j++) {
            prevBlock[j] = ciphertext[i + j];
        }
    }
    
    return removePadding(plaintext);
}

void printHex(const std::vector<uint8_t>& data, const std::string& label) {
    std::cout << label << " (hex): ";
    for (const auto& byte : data) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl;
}


std::vector<uint8_t> generateIV() {
    std::vector<uint8_t> iv(16, 0);
    for (int i = 0; i < 16; i++) {
        iv[i] = (std::rand() % 256);
    }
    return iv;
}

int main() {
    
    std::vector<uint8_t> key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    
    std::srand(static_cast<unsigned int>(std::time(nullptr)));
    
    std::vector<uint8_t> iv = generateIV();
    
    std::string plaintext;
    std::cout << "Enter text to encrypt: ";
    std::getline(std::cin, plaintext);
    

    auto ciphertext = encryptAES256(plaintext, key, iv);
    
    std::cout << "\nOriginal text: " << plaintext << std::endl;
    printHex(ciphertext, "Encrypted text");
    
    std::string decrypted = decryptAES256(ciphertext, key, iv);

    std::cout << "Decrypted text: " << decrypted << std::endl;
    
    return 0;
}