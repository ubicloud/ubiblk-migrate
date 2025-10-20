#define _LARGEFILE64_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>

#define UBI_METADATA_SIZE (8 * 1024 * 1024)
#define UBI_MAX_STRIPES (2 * 1024 * 1024)
#define UBI_MAGIC_SIZE 9
#define UBI_MAGIC "BDEV_UBI"

struct ubi_metadata {
    uint8_t magic[UBI_MAGIC_SIZE];
    uint8_t versionMajor[2];
    uint8_t versionMinor[2];
    uint8_t stripe_size_kb;
    uint8_t stripe_headers[UBI_MAX_STRIPES][2];
    uint8_t padding[UBI_METADATA_SIZE - UBI_MAGIC_SIZE - UBI_MAX_STRIPES * 2 - 5];
};

enum stripe_status { STRIPE_NOT_FETCHED = 0, STRIPE_INFLIGHT, STRIPE_FAILED, STRIPE_FETCHED };

int ubi_get_stripe_status_from_metadata(struct ubi_metadata *metadata, int index) {
    return metadata->stripe_headers[index][0];
}

int cleanup(char *error_msg, FILE *base_file, FILE *overlay_file, FILE *output_file,
            struct ubi_metadata *metadata, uint8_t *buffer);

int flatten_image(const char *base_image_path, const char *overlay_image_path,
                  const char *output_path) {
    FILE *base_file = NULL;
    FILE *overlay_file = NULL;
    FILE *output_file = NULL;
    struct ubi_metadata *metadata = NULL;
    uint8_t *buffer = NULL;

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

    // Read metadata from the overlay file (first 8MB)
    metadata = calloc(1, sizeof(struct ubi_metadata));
    if (!metadata)
        return cleanup("Failed to allocate memory for metadata", base_file, overlay_file,
                       output_file, metadata, buffer);
    if (fseek(overlay_file, 0, SEEK_SET) != 0)
        return cleanup("Failed to seek to beginning of overlay file", base_file, overlay_file,
                       output_file, metadata, buffer);
    if (fread(metadata, 1, sizeof(struct ubi_metadata), overlay_file) !=
        sizeof(struct ubi_metadata))
        return cleanup("Failed to read metadata", base_file, overlay_file, output_file, metadata,
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

            if (fwrite(buffer, 1, bytes_read, output_file) != bytes_read)
                return cleanup("Failed to write to output image", base_file, overlay_file,
                               output_file, metadata, buffer);
        }

        stripe_index++;
    }

    printf("Processed %lu stripes\n", stripe_index);
    return cleanup(NULL, base_file, overlay_file, output_file, metadata, buffer);
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

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "-base-image=", 12) == 0) {
            base_image = argv[i] + 12;
        } else if (strncmp(argv[i], "-overlay-image=", 15) == 0) {
            overlay_image = argv[i] + 15;
        } else if (strncmp(argv[i], "-output-image=", 14) == 0) {
            output_image = argv[i] + 14;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            return 1;
        }
    }

    if (!base_image || !overlay_image || !output_image) {
        fprintf(stderr, "Usage: %s -base-image=<path> -overlay-image=<path> -output-image=<path>\n",
                argv[0]);
        return 1;
    }

    printf("Base image: %s\n", base_image);
    printf("Overlay image: %s\n", overlay_image);
    printf("Output image: %s\n", output_image);

    if (flatten_image(base_image, overlay_image, output_image) != 0) {
        return 1;
    }

    return 0;
}
