#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char* read_file(const char* file_name, size_t* size) {
    FILE* file = NULL;
    if (fopen_s(&file, file_name, "rb") != 0)
    {
        printf_s("Error opening file\n");
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* data = (unsigned char*)malloc(*size);
    if (!data) {
        printf_s("Error allocating memory\n");
        exit(EXIT_FAILURE);
    }

    if (fread(data, 1, *size, file) != *size) {
        printf_s("Error reading file\n");
        exit(EXIT_FAILURE);
    }

    fclose(file);
    printf_s("read data from \"%s\" %lld bytes at 0x%p\n", file_name, *size, data);
    return data;
}

void write_file(const char* file_name, const unsigned char* data, size_t size) {
    FILE* file = NULL;
    if (fopen_s(&file, file_name, "wb") != 0) {
        printf_s("Error opening file\n");
        exit(EXIT_FAILURE);
    }

    if (fwrite(data, 1, size, file) != size) {
        printf_s("Error writing to file\n");
        exit(EXIT_FAILURE);
    }
    printf_s("write data from 0x%p to \"%s\" %lld bytes\n", data, file_name, size);
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

static void show_invalid_arg(const char* program_name)
{
        printf_s("Invalid arguments\n"
                 "Usage: %s decrypt <file> OR p3r-save encrypt <file>\n", program_name);
        exit(EXIT_FAILURE);
}

const char* g_OrSaveKey = "ae5zeitaix1joowooNgie3fahP5Ohph";

int main(int argc, char **argv)
{
    printf_s("p3r-save: Built " __DATE__ " @ " __TIME__ "\n");
    if (argc < 3)
    {
        show_invalid_arg(argv[0]);
    }

    size_t filesize = 0;    
    if (strcmp(argv[1], "decrypt") == 0 || strcmp(argv[1], "-d") == 0)
    {
        unsigned char* test_data = read_file(argv[2], &filesize);
        unsigned char* decrypted_data = (unsigned char*)malloc(filesize);
        if (!decrypted_data) {
            printf_s("Error allocating memory\n");
            exit(EXIT_FAILURE);
        }

        size_t keylen = strlen(g_OrSaveKey);
        size_t key_idx = 0;

        for (size_t i = 0; i < filesize; ++i) {
            if (key_idx >= strlen(g_OrSaveKey)) {
                // reset index
                key_idx = 0;
            }
            decrypted_data[i] = decrypt_byte(test_data[i], g_OrSaveKey[key_idx]);
            key_idx++;
        }

        write_file("decrypt_out.sav", decrypted_data, filesize);

        if (test_data)
        {
            printf_s("free test_data: 0x%p\n", test_data);
            free(test_data);
        }
        else
        {
            printf_s("failed to free test_data: 0x%p\n", test_data);
        }
        if (decrypted_data)
        {
            printf_s("free decrypted_data: 0x%p\n", decrypted_data);
            free(decrypted_data);
        }
        else
        {
            printf_s("failed to free decrypted_data: 0x%p\n", decrypted_data);
        }
    }
    else if (strcmp(argv[1], "encrypt") == 0 || strcmp(argv[1], "-e") == 0)
    {
        unsigned char* test_data = read_file(argv[2], &filesize);
        unsigned char* encrypted_data = (unsigned char*)malloc(filesize);

        if (!encrypted_data) {
            printf_s("Error allocating memory\n");
            exit(EXIT_FAILURE);
        }

        size_t keylen = strlen(g_OrSaveKey);
        size_t key_idx = 0;

        for (size_t i = 0; i < filesize; ++i)
        {
            if (key_idx >= strlen(g_OrSaveKey))
            {
                // reset index
                key_idx = 0;
            }
            encrypted_data[i] = encrypt_byte(test_data[i], g_OrSaveKey[key_idx]);
            key_idx++;
        }

        write_file("encrypt_out.sav", encrypted_data, filesize);

        if (test_data)
        {
            printf_s("free test_data: 0x%p\n", test_data);
            free(test_data);
        }
        else
        {
            printf_s("failed to free test_data: 0x%p\n", test_data);
        }
        if (encrypted_data)
        {
            printf_s("free encrypted_data: 0x%p\n", encrypted_data);
            free(encrypted_data);
        }
        else
        {
            printf_s("failed to free encrypted_data: 0x%p\n", encrypted_data);
        }
    }
    else
    {
        show_invalid_arg(argv[0]);
    }
    return 0;
}
