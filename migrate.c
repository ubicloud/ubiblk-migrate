#define _LARGEFILE64_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <yaml.h>

#define UBI_METADATA_SIZE (8 * 1024 * 1024)
#define UBI_MAX_STRIPES (2 * 1024 * 1024)
#define UBI_MAGIC_SIZE 9
#define UBI_MAGIC "BDEV_UBI"

#define KEY_LENGTH 32
#define IV_LENGTH 12
#define AUTH_TAG_LENGTH 16
#define SECTOR_SIZE 512
#define KEY_AUTH_TAG_LENGTH (KEY_LENGTH + AUTH_TAG_LENGTH)

typedef struct {
    EVP_CIPHER_CTX *ctx;
    unsigned char keys[64];  // Combined key1 and key2
} xts_decrypt_ctx_t;

typedef struct {
    unsigned char *key;
    size_t key_len;
    unsigned char *iv;
    size_t iv_len;
    unsigned char *auth_data;
    size_t auth_data_len;
} key_encryption_cipher_t;

struct ubi_metadata {
    uint8_t magic[UBI_MAGIC_SIZE];
    uint8_t versionMajor[2];
    uint8_t versionMinor[2];
    uint8_t stripe_size_kb;
    uint8_t stripe_headers[UBI_MAX_STRIPES][2];
    uint8_t padding[UBI_METADATA_SIZE - UBI_MAGIC_SIZE - UBI_MAX_STRIPES * 2 - 5];
};

int cleanup(char *error_msg, FILE *base_file, FILE *overlay_file, FILE *output_file,
            struct ubi_metadata *metadata, uint8_t *buffer);
int process_decryption_files(const char *kek_file, const char *vhost_backend_conf_file,
                             xts_decrypt_ctx_t *xts_ctx);
int base64_decode(const char *input, unsigned char **output, size_t *output_len);
int parse_kek_file(const char *filename, key_encryption_cipher_t *kek);
int parse_vhost_backend_conf(const char *filename, unsigned char **key1, size_t *key1_len,
                             unsigned char **key2, size_t *key2_len);
int decrypt_keys(const unsigned char *key1, size_t key1_len, const unsigned char *key2,
                 size_t key2_len, const key_encryption_cipher_t *kek, unsigned char *decrypted_key1,
                 size_t *decrypted_key1_len, unsigned char *decrypted_key2,
                 size_t *decrypted_key2_len);
int decrypt_key_aes_gcm(const unsigned char *kek_key, size_t kek_key_len,
                        const unsigned char *kek_iv, size_t kek_iv_len,
                        const unsigned char *auth_data, size_t auth_data_len,
                        const unsigned char *encrypted_key, size_t encrypted_key_len,
                        unsigned char *decrypted_key, size_t *decrypted_key_len);
int init_xts_decrypt_ctx(xts_decrypt_ctx_t *xts_ctx, const unsigned char *key1,
                         const unsigned char *key2);
void cleanup_xts_decrypt_ctx(xts_decrypt_ctx_t *xts_ctx);
int decrypt_xts_data_with_ctx(xts_decrypt_ctx_t *xts_ctx, const unsigned char *encrypted_data,
                              unsigned char *decrypted_data, size_t data_len, size_t sector_offset);
int encrypt_xts_data_with_ctx(xts_decrypt_ctx_t *xts_ctx, const unsigned char *plaintext_data,
                              unsigned char *encrypted_data, size_t data_len, size_t sector_offset);

enum stripe_status { STRIPE_NOT_FETCHED = 0, STRIPE_INFLIGHT, STRIPE_FAILED, STRIPE_FETCHED };

int ubi_get_stripe_status_from_metadata(struct ubi_metadata *metadata, int index) {
    return metadata->stripe_headers[index][0];
}

int flatten_image(const char *base_image_path, const char *overlay_image_path,
                  const char *output_path, xts_decrypt_ctx_t xts_ctx) {
    FILE *base_file = NULL;
    FILE *overlay_file = NULL;
    FILE *output_file = NULL;
    struct ubi_metadata *metadata = NULL;
    uint8_t *buffer = NULL;
    uint8_t *encrypted_metadata = NULL;

    base_file = fopen(base_image_path, "rb");
    if (!base_file)
        return cleanup("Failed to open base image", base_file, overlay_file, output_file, metadata,
                       buffer);
    overlay_file = fopen(overlay_image_path, "rb");
    if (!overlay_file)
        return cleanup("Failed to open overlay image", base_file, overlay_file, output_file,
                       metadata, buffer);
    output_file = fopen(output_path, "wb");
    if (!output_file)
        return cleanup("Failed to create output image", base_file, overlay_file, output_file,
                       metadata, buffer);

    // Read encrypted metadata from the overlay file (first 8MB)
    metadata = calloc(1, sizeof(struct ubi_metadata));
    if (!metadata)
        return cleanup("Failed to allocate memory for metadata", base_file, overlay_file,
                       output_file, metadata, buffer);
    encrypted_metadata = malloc(sizeof(struct ubi_metadata));
    if (!encrypted_metadata)
        return cleanup("Failed to allocate memory for encrypted metadata", base_file, overlay_file,
                       output_file, metadata, buffer);
    if (fseek(overlay_file, 0, SEEK_SET) != 0)
        return cleanup("Failed to seek to beginning of overlay file", base_file, overlay_file,
                       output_file, metadata, buffer);
    if (fread(encrypted_metadata, 1, sizeof(struct ubi_metadata), overlay_file) !=
        sizeof(struct ubi_metadata))
        return cleanup("Failed to read encrypted metadata", base_file, overlay_file, output_file,
                       metadata, buffer);

    // Decrypt the metadata
    if (!decrypt_xts_data_with_ctx(&xts_ctx, encrypted_metadata, (uint8_t *)metadata,
                                   sizeof(struct ubi_metadata), 0))
        return cleanup("Failed to decrypt metadata", base_file, overlay_file, output_file, metadata,
                       buffer);

    if (memcmp(metadata->magic, UBI_MAGIC, UBI_MAGIC_SIZE) != 0)
        return cleanup("Invalid magic bytes in metadata", base_file, overlay_file, output_file,
                       metadata, buffer);

    size_t block_size = 1024 * 1024;
    buffer = malloc(block_size);
    if (!buffer)
        return cleanup("Failed to allocate buffer", base_file, overlay_file, output_file, metadata,
                       buffer);

    printf("Flattening image...\n");

    uint64_t stripe_index = 0;
    size_t overlay_file_size = 0;
    struct stat st;
    if (stat(overlay_image_path, &st) == 0) {
        overlay_file_size = st.st_size;
    } else {
        return cleanup("Failed to get the overlay image size", base_file, overlay_file, output_file,
                       metadata, buffer);
    }
    uint64_t stripe_count = (overlay_file_size - UBI_METADATA_SIZE + block_size - 1) / block_size;

    struct stat base_st;
    if (stat(base_image_path, &base_st) != 0) {
        return cleanup("Failed to get the base image size", base_file, overlay_file, output_file,
                       metadata, buffer);
    }
    uint64_t base_stripe_count = (base_st.st_size + block_size - 1) / block_size;

    while (stripe_index < stripe_count) {
        off_t offset = (stripe_index * block_size);
        // Metadata is 8MB, so we need to offset by that amount
        off_t overlay_offset = UBI_METADATA_SIZE + offset;
        if (fseek(base_file, offset, SEEK_SET) != 0)
            return cleanup("Failed to seek in base image", base_file, overlay_file, output_file,
                           metadata, buffer);
        if (fseek(overlay_file, overlay_offset, SEEK_SET) != 0)
            return cleanup("Failed to seek in overlay image", base_file, overlay_file, output_file,
                           metadata, buffer);
        if (fseek(output_file, offset, SEEK_SET) != 0)
            return cleanup("Failed to seek in output image", base_file, overlay_file, output_file,
                           metadata, buffer);

        size_t bytes_read;
        if (stripe_index >= base_stripe_count ||
            ubi_get_stripe_status_from_metadata(metadata, stripe_index) == 1) {
            bytes_read = fread(buffer, 1, block_size, overlay_file);
            if (bytes_read < block_size && !feof(overlay_file))
                return cleanup("Failed to read from overlay image", base_file, overlay_file,
                               output_file, metadata, buffer);

            if (fwrite(buffer, 1, bytes_read, output_file) != bytes_read)
                return cleanup("Failed to write to output image", base_file, overlay_file,
                               output_file, metadata, buffer);
        } else {
            bytes_read = fread(buffer, 1, block_size, base_file);
            if (bytes_read < block_size && !feof(base_file))
                return cleanup("Failed to read from base image", base_file, overlay_file,
                               output_file, metadata, buffer);

            uint8_t *encrypted_buffer = malloc(block_size);
            if (!encrypted_buffer)
                return cleanup("Failed to allocate encrypted buffer", base_file, overlay_file,
                               output_file, metadata, buffer);

            size_t sectors_per_block = block_size / SECTOR_SIZE;
            size_t sector_offset = stripe_index * sectors_per_block;
            if (!encrypt_xts_data_with_ctx(&xts_ctx, buffer, encrypted_buffer, block_size,
                                           sector_offset)) {
                free(encrypted_buffer);
                return cleanup("Failed to encrypt base block", base_file, overlay_file, output_file,
                               metadata, buffer);
            }

            if (fwrite(encrypted_buffer, 1, block_size, output_file) != block_size) {
                free(encrypted_buffer);
                return cleanup("Failed to write to output image", base_file, overlay_file,
                               output_file, metadata, buffer);
            }
            free(encrypted_buffer);
        }

        stripe_index++;
    }

    printf("Processed %lu stripes\n", stripe_index);
    return cleanup(NULL, base_file, overlay_file, output_file, metadata, buffer);
}

int process_decryption_files(const char *kek_file, const char *vhost_backend_conf_file,
                             xts_decrypt_ctx_t *xts_ctx) {
    key_encryption_cipher_t kek = {0};
    unsigned char *encrypted_key1 = NULL;
    unsigned char *encrypted_key2 = NULL;
    size_t encrypted_key1_len, encrypted_key2_len;
    int result = 1;  // Default to failure

    if (!parse_kek_file(kek_file, &kek)) {
        fprintf(stderr, "Failed to parse KEK file\n");
        goto cleanup;
    }

    if (!parse_vhost_backend_conf(vhost_backend_conf_file, &encrypted_key1, &encrypted_key1_len,
                                  &encrypted_key2, &encrypted_key2_len)) {
        fprintf(stderr, "Failed to parse vhost-backend-conf file\n");
        goto cleanup;
    }

    unsigned char decrypted_key1[KEY_LENGTH];
    unsigned char decrypted_key2[KEY_LENGTH];
    size_t decrypted_key1_len, decrypted_key2_len;

    if (!decrypt_keys(encrypted_key1, encrypted_key1_len, encrypted_key2, encrypted_key2_len, &kek,
                      decrypted_key1, &decrypted_key1_len, decrypted_key2, &decrypted_key2_len)) {
        fprintf(stderr, "Failed to decrypt keys\n");
        goto cleanup;
    }
    if (!init_xts_decrypt_ctx(xts_ctx, decrypted_key1, decrypted_key2)) {
        fprintf(stderr, "Failed to initialize XTS decryption context\n");
        goto cleanup;
    }
    result = 0;

cleanup:
    if (encrypted_key1) free(encrypted_key1);
    if (encrypted_key2) free(encrypted_key2);
    if (kek.key) free(kek.key);
    if (kek.iv) free(kek.iv);
    if (kek.auth_data) free(kek.auth_data);
    return result;
}

int base64_decode(const char *input, unsigned char **output, size_t *output_len) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr = BUF_MEM_new();
    if (!bufferPtr) {
        fprintf(stderr, "Failed to allocate buffer\n");
        return 1;
    }

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input, -1);
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    if (!BUF_MEM_grow(bufferPtr, strlen(input))) {
        fprintf(stderr, "Failed to grow buffer\n");
        BUF_MEM_free(bufferPtr);
        return 1;
    }
    *output_len = BIO_read(bio, (unsigned char *)bufferPtr->data, strlen(input));

    *output = malloc(*output_len);
    if (!*output) {
        BIO_free_all(bio);
        return 0;
    }

    memcpy(*output, bufferPtr->data, *output_len);

    BIO_free_all(bio);
    BUF_MEM_free(bufferPtr);
    return 1;
}

int parse_kek_file(const char *filename, key_encryption_cipher_t *kek) {
    FILE *file = NULL;
    yaml_parser_t parser;
    yaml_event_t event;
    int done = 0;
    int state = 0;  // 0 = expecting key, 1 = expecting init_vector, 2 = expecting auth_data
    char key_b64[256] = {0};
    char iv_b64[256] = {0};
    char auth_data_b64[256] = {0};

    file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Failed to open KEK file: %s\n", filename);
        return 0;
    }
    if (!yaml_parser_initialize(&parser)) {
        fprintf(stderr, "Failed to initialize YAML parser\n");
        fclose(file);
        return 0;
    }
    yaml_parser_set_input_file(&parser, file);
    while (!done) {
        if (!yaml_parser_parse(&parser, &event)) {
            fprintf(stderr, "Failed to parse YAML\n");
            yaml_parser_delete(&parser);
            fclose(file);
            return 0;
        }

        switch (event.type) {
            case YAML_SCALAR_EVENT:
                if (state == 0 && strcmp((char *)event.data.scalar.value, "key") == 0) {
                    state = 1;
                } else if (state == 1) {
                    strncpy(key_b64, (char *)event.data.scalar.value, sizeof(key_b64) - 1);
                    key_b64[sizeof(key_b64) - 1] = '\0';
                    state = 0;
                } else if (state == 0 &&
                           strcmp((char *)event.data.scalar.value, "init_vector") == 0) {
                    state = 2;
                } else if (state == 2) {
                    strncpy(iv_b64, (char *)event.data.scalar.value, sizeof(iv_b64) - 1);
                    iv_b64[sizeof(iv_b64) - 1] = '\0';
                    state = 0;
                } else if (state == 0 &&
                           strcmp((char *)event.data.scalar.value, "auth_data") == 0) {
                    state = 3;
                } else if (state == 3) {
                    strncpy(auth_data_b64, (char *)event.data.scalar.value,
                            sizeof(auth_data_b64) - 1);
                    auth_data_b64[sizeof(auth_data_b64) - 1] = '\0';
                    state = 0;
                }
                break;
            case YAML_STREAM_END_EVENT:
                done = 1;
                break;
            default:
                break;
        }

        yaml_event_delete(&event);
    }

    yaml_parser_delete(&parser);
    fclose(file);
    if (!base64_decode(key_b64, &kek->key, &kek->key_len)) {
        fprintf(stderr, "Failed to decode key\n");
        return 0;
    }
    if (!base64_decode(iv_b64, &kek->iv, &kek->iv_len)) {
        fprintf(stderr, "Failed to decode init_vector\n");
        return 0;
    }
    if (!base64_decode(auth_data_b64, &kek->auth_data, &kek->auth_data_len)) {
        fprintf(stderr, "Failed to decode auth_data\n");
        return 0;
    }
    return 1;
}

int parse_vhost_backend_conf(const char *filename, unsigned char **key1, size_t *key1_len,
                             unsigned char **key2, size_t *key2_len) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Failed to open vhost-backend-conf file: %s\n", filename);
        return 0;
    }

    char line[512];
    int found_encryption_key = 0;
    char key1_auth_tag_b64[512] = {0};
    char key2_auth_tag_b64[512] = {0};

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0;

        if (strcmp(line, "encryption_key:") == 0) {
            found_encryption_key = 1;
            continue;
        }
        // If we found encryption_key, read the next two lines as keys
        if (found_encryption_key) {
            if (key1_auth_tag_b64[0] == 0) {
                strncpy(key1_auth_tag_b64, line + 2,
                        sizeof(key1_auth_tag_b64) - 1);  // Skip the "- " prefix
                key1_auth_tag_b64[sizeof(key1_auth_tag_b64) - 1] = '\0';
            } else if (key2_auth_tag_b64[0] == 0) {
                strncpy(key2_auth_tag_b64, line + 2,
                        sizeof(key2_auth_tag_b64) - 1);  // Skip the "- " prefix
                key2_auth_tag_b64[sizeof(key2_auth_tag_b64) - 1] = '\0';
                break;
            }
        }
    }
    fclose(file);
    if (key1_auth_tag_b64[0] == 0 || key2_auth_tag_b64[0] == 0) {
        fprintf(stderr, "Failed to find both encryption keys in vhost-backend-conf file\n");
        return 0;
    }
    if (!base64_decode(key1_auth_tag_b64, key1, key1_len)) {
        fprintf(stderr, "Failed to decode key1\n");
        return 0;
    }
    if (!base64_decode(key2_auth_tag_b64, key2, key2_len)) {
        fprintf(stderr, "Failed to decode key2\n");
        return 0;
    }
    return 1;
}

int decrypt_key_aes_gcm(const unsigned char *kek_key, size_t kek_key_len,
                        const unsigned char *kek_iv, size_t kek_iv_len,
                        const unsigned char *auth_data, size_t auth_data_len,
                        const unsigned char *encrypted_key, size_t encrypted_key_len,
                        unsigned char *decrypted_key, size_t *decrypted_key_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len, plaintext_len, ret = 0;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Failed to create EVP_CIPHER_CTX\n");
        goto cleanup;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        fprintf(stderr, "Failed to initialize decryption\n");
        goto cleanup;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, kek_iv_len, NULL)) {
        fprintf(stderr, "Failed to set IV length\n");
        goto cleanup;
    }
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, kek_key, kek_iv)) {
        fprintf(stderr, "Failed to set key and IV\n");
        goto cleanup;
    }
    if (auth_data_len > 0 && !EVP_DecryptUpdate(ctx, NULL, &len, auth_data, auth_data_len)) {
        fprintf(stderr, "Failed to set authenticated data\n");
        goto cleanup;
    }
    if (!EVP_DecryptUpdate(ctx, decrypted_key, &len, encrypted_key,
                           encrypted_key_len - AUTH_TAG_LENGTH)) {
        fprintf(stderr, "Failed to decrypt key\n");
        goto cleanup;
    }
    plaintext_len = len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AUTH_TAG_LENGTH,
                             (void *)(encrypted_key + encrypted_key_len - AUTH_TAG_LENGTH))) {
        fprintf(stderr, "Failed to set expected tag\n");
        goto cleanup;
    }
    if (EVP_DecryptFinal_ex(ctx, decrypted_key + plaintext_len, &len) <= 0) {
        fprintf(stderr, "Failed to finalize decryption\n");
        goto cleanup;
    }
    plaintext_len += len;
    *decrypted_key_len = plaintext_len;
    ret = 1;
cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int decrypt_keys(const unsigned char *key1, size_t key1_len, const unsigned char *key2,
                 size_t key2_len, const key_encryption_cipher_t *kek, unsigned char *decrypted_key1,
                 size_t *decrypted_key1_len, unsigned char *decrypted_key2,
                 size_t *decrypted_key2_len) {
    if (key1_len != KEY_AUTH_TAG_LENGTH || key2_len != KEY_AUTH_TAG_LENGTH) {
        fprintf(stderr, "Key length must be %d bytes\n", KEY_AUTH_TAG_LENGTH);
        return 0;
    }
    if (!kek->key || kek->key_len != 32) {
        fprintf(stderr, "KEK key is required and must be 32 bytes\n");
        return 0;
    }
    if (!kek->iv || kek->iv_len != IV_LENGTH) {
        fprintf(stderr, "KEK IV is required and must be %d bytes\n", IV_LENGTH);
        return 0;
    }
    if (!decrypt_key_aes_gcm(kek->key, kek->key_len, kek->iv, kek->iv_len, kek->auth_data,
                             kek->auth_data_len, key1, key1_len, decrypted_key1,
                             decrypted_key1_len)) {
        fprintf(stderr, "Failed to decrypt key1\n");
        return 0;
    }
    if (!decrypt_key_aes_gcm(kek->key, kek->key_len, kek->iv, kek->iv_len, kek->auth_data,
                             kek->auth_data_len, key2, key2_len, decrypted_key2,
                             decrypted_key2_len)) {
        fprintf(stderr, "Failed to decrypt key2\n");
        return 0;
    }
    return 1;
}

int init_xts_decrypt_ctx(xts_decrypt_ctx_t *xts_ctx, const unsigned char *key1,
                         const unsigned char *key2) {
    xts_ctx->ctx = NULL;
    if (!(xts_ctx->ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Failed to create EVP_CIPHER_CTX\n");
        return 0;
    }
    if (!EVP_DecryptInit_ex(xts_ctx->ctx, EVP_aes_256_xts(), NULL, NULL, NULL)) {
        fprintf(stderr, "Failed to initialize XTS decryption\n");
        EVP_CIPHER_CTX_free(xts_ctx->ctx);
        xts_ctx->ctx = NULL;
        return 0;
    }
    memcpy(xts_ctx->keys, key1, 32);
    memcpy(xts_ctx->keys + 32, key2, 32);
    return 1;
}

void cleanup_xts_decrypt_ctx(xts_decrypt_ctx_t *xts_ctx) {
    if (xts_ctx->ctx) {
        EVP_CIPHER_CTX_free(xts_ctx->ctx);
        xts_ctx->ctx = NULL;
    }
}

int decrypt_xts_data_with_ctx(xts_decrypt_ctx_t *xts_ctx, const unsigned char *encrypted_data,
                              unsigned char *decrypted_data, size_t data_len,
                              size_t sector_offset) {
    int len, plaintext_len;
    unsigned char tweak[16];
    size_t num_sectors = data_len / SECTOR_SIZE;

    for (size_t i = 0; i < num_sectors; i++) {
        // Prepare tweak value (sector number as little-endian in second 8 bytes)
        memset(tweak, 0, 16);
        // Encode the sector number as little-endian into the second 8 bytes
        size_t sector_num = sector_offset + i;
        memcpy(tweak + 8, &sector_num, sizeof(sector_num));

        if (!EVP_DecryptInit_ex(xts_ctx->ctx, NULL, NULL, xts_ctx->keys, tweak)) {
            fprintf(stderr, "Failed to set key and tweak for sector %zu\n", sector_num);
            return 0;
        }
        if (!EVP_DecryptUpdate(xts_ctx->ctx, decrypted_data + (i * SECTOR_SIZE), &len,
                               encrypted_data + (i * SECTOR_SIZE), SECTOR_SIZE)) {
            fprintf(stderr, "Failed to decrypt sector %zu\n", sector_num);
            return 0;
        }
        plaintext_len = len;
        if (!EVP_DecryptFinal_ex(xts_ctx->ctx, decrypted_data + (i * SECTOR_SIZE) + plaintext_len,
                                 &len)) {
            fprintf(stderr, "Failed to finalize decryption for sector %zu\n", sector_num);
            return 0;
        }
        plaintext_len += len;
    }
    return 1;
}

int encrypt_xts_data_with_ctx(xts_decrypt_ctx_t *xts_ctx, const unsigned char *plaintext_data,
                              unsigned char *encrypted_data, size_t data_len,
                              size_t sector_offset) {
    int len, ciphertext_len;
    unsigned char tweak[16];
    size_t num_sectors = data_len / SECTOR_SIZE;
    for (size_t i = 0; i < num_sectors; i++) {
        // Prepare tweak value (sector number as little-endian in second 8 bytes)
        memset(tweak, 0, 16);
        // Encode the sector number as little-endian into the second 8 bytes
        size_t sector_num = sector_offset + i;
        memcpy(tweak + 8, &sector_num, sizeof(sector_num));

        if (!EVP_EncryptInit_ex(xts_ctx->ctx, NULL, NULL, xts_ctx->keys, tweak)) {
            fprintf(stderr, "Failed to set key and tweak for sector %zu\n", sector_num);
            return 0;
        }
        if (!EVP_EncryptUpdate(xts_ctx->ctx, encrypted_data + (i * SECTOR_SIZE), &len,
                               plaintext_data + (i * SECTOR_SIZE), SECTOR_SIZE)) {
            fprintf(stderr, "Failed to encrypt sector %zu\n", sector_num);
            return 0;
        }
        ciphertext_len = len;
        if (!EVP_EncryptFinal_ex(xts_ctx->ctx, encrypted_data + (i * SECTOR_SIZE) + ciphertext_len,
                                 &len)) {
            fprintf(stderr, "Failed to finalize encryption for sector %zu\n", sector_num);
            return 0;
        }
        ciphertext_len += len;
    }
    return 1;
}

int cleanup(char *error_msg, FILE *base_file, FILE *overlay_file, FILE *output_file,
            struct ubi_metadata *metadata, uint8_t *buffer) {
    if (error_msg != NULL) fprintf(stderr, "%s\n", error_msg);
    if (buffer) free(buffer);
    if (base_file) fclose(base_file);
    if (overlay_file) fclose(overlay_file);
    if (output_file) fclose(output_file);
    if (metadata) free(metadata);
    return (error_msg != NULL);
}

int main(int argc, char *argv[]) {
    char *base_image = NULL;
    char *overlay_image = NULL;
    char *output_image = NULL;
    char *kek_file = NULL;
    char *vhost_backend_conf_file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "-base-image=", 12) == 0) {
            base_image = argv[i] + 12;
        } else if (strncmp(argv[i], "-overlay-image=", 15) == 0) {
            overlay_image = argv[i] + 15;
        } else if (strncmp(argv[i], "-output-image=", 14) == 0) {
            output_image = argv[i] + 14;
        } else if (strncmp(argv[i], "-kek-file=", 10) == 0) {
            kek_file = argv[i] + 10;
        } else if (strncmp(argv[i], "-vhost-backend-conf-file=", 25) == 0) {
            vhost_backend_conf_file = argv[i] + 25;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            return 1;
        }
    }

    if (!base_image || !overlay_image || !output_image || !kek_file || !vhost_backend_conf_file) {
        fprintf(stderr,
                "Usage: %s -base-image=<path> -overlay-image=<path> -output-image=<path> "
                "-kek-file=<path> -vhost-backend-conf-file=<path>\n",
                argv[0]);
        return 1;
    }

    printf("Base image: %s\n", base_image);
    printf("Overlay image: %s\n", overlay_image);
    printf("Output image: %s\n", output_image);
    printf("KEK file: %s\n", kek_file);
    printf("VHost backend conf file: %s\n", vhost_backend_conf_file);

    xts_decrypt_ctx_t xts_ctx = {0};
    if (process_decryption_files(kek_file, vhost_backend_conf_file, &xts_ctx) != 0) {
        fprintf(stderr, "Failed to process decryption files\n");
        return 1;
    }
    printf("Decryption context initialized successfully\n");

    if (flatten_image(base_image, overlay_image, output_image, xts_ctx) != 0) {
        return 1;
    }

    return 0;
}
