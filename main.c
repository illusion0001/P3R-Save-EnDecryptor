#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

unsigned char* read_file(const char* file_name, size_t* size) {
    FILE* file = fopen(file_name, "rb");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* data = (unsigned char*)malloc(*size);
    if (!data) {
        perror("Error allocating memory");
        exit(EXIT_FAILURE);
    }

    fread(data, 1, *size, file);
    fclose(file);

    return data;
}

void write_file(const char* file_name, const unsigned char* data, size_t size) {
    FILE* file = fopen(file_name, "wb");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    fwrite(data, 1, size, file);
    fclose(file);
}

// 0x14106A7D0 bytes 32 CA 0F B6 C1 0F B6 D1 C0 E8 04 80 E2 03 24 03 C0 E2 04 0A C2 80 E1 CC 0A C1 C3
unsigned char decrypt_byte(unsigned char data, unsigned char key) {
    unsigned char bVar1 = data ^ key;
    return (bVar1 >> 4 & 3 | (bVar1 & 3) << 4 | bVar1 & 0xcc);
}

// 0x14106A7F0 bytes 0F B6 C1 44 0F B6 C1 C0 E8 04 41 80 E0 03 24 03 41 C0 E0 04 41 0A C0 80 E1 CC 0A C1 32 C2 C3
unsigned char encrypt_byte(unsigned char data, unsigned char key) {
    return ((((data & 0xff) >> 4) & 3 | (data & 3) << 4 | data & 0xcc) ^ key);
}

int main() {
    size_t size = 0;
    unsigned char* test_data = read_file("decrypt.sav", &size);
    unsigned char* test_data2 = read_file("encrypt.sav", &size);
    const char* key = "ae5zeitaix1joowooNgie3fahP5Ohph";

    size_t key_idx = 0;
    unsigned char* encrypted_data = (unsigned char*)malloc(size);
    if (!encrypted_data) {
        perror("Error allocating memory");
        exit(EXIT_FAILURE);
    }

    for (size_t i = 0; i < size; ++i) {
        if (key_idx >= strlen(key)) {
            // reset index
            key_idx = 0;
        }
        encrypted_data[i] = encrypt_byte(test_data[i], key[key_idx]);
        key_idx++;
    }

    write_file("encrypt_out.sav", encrypted_data, size);

    unsigned char* decrypted_data = (unsigned char*)malloc(size);
    if (!decrypted_data) {
        perror("Error allocating memory");
        exit(EXIT_FAILURE);
    }

    key_idx = 0;
    for (size_t i = 0; i < size; ++i) {
        if (key_idx >= strlen(key)) {
            // reset index
            key_idx = 0;
        }
        decrypted_data[i] = decrypt_byte(test_data2[i], key[key_idx]);
        key_idx++;
    }

    write_file("decrypt_out.sav", decrypted_data, size);

    free(test_data);
    free(test_data2);
    free(encrypted_data);
    free(decrypted_data);

    return 0;
}
