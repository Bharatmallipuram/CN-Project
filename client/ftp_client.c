// gcc ftp_client.c -o ftp_client -lssl -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8080
#define BUFFER_SIZE 1024

void initialize_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method = SSLv23_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void show_menu()
{
    printf("\nFTP Client Menu:\n");
    printf("1. LIST - List files on server\n");
    printf("2. RETR - Download file from server\n");
    printf("3. STOR - Upload file to server\n");
    printf("4. QUIT - Disconnect\n");
    printf("Enter your choice: ");
}

void handle_commands(SSL *ssl)
{
    char command[BUFFER_SIZE];
    char buffer[BUFFER_SIZE];
    char temp[BUFFER_SIZE - 10];
    int choice;
    int bytes;

    while (1)
    {
        show_menu();
        scanf("%d", &choice);
        getchar();

        if (choice == 1)
        {
            strcpy(command, "LIST");
            SSL_write(ssl, command, strlen(command));

            printf("Files on server:\n");
            while ((bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0)
            {
                buffer[bytes] = '\0';
                if (strncmp(buffer, "END", 3) == 0)
                    break;
                printf("%s", buffer); // Print each line received
            }
        }
        else if (choice == 2)
        {
            printf("Enter filename to download: ");
            fgets(command, sizeof(command), stdin);
            command[strcspn(command, "\n")] = '\0';

            // Ensure the RETR command doesn't overflow buffer
            // snprintf(buffer, BUFFER_SIZE - 5, "RETR %s", command);
            snprintf(buffer, BUFFER_SIZE - 5, "RETR %s", strncpy(temp, command, BUFFER_SIZE - 10));
            SSL_write(ssl, buffer, strlen(buffer));

            FILE *file = fopen(command, "wb");
            if (!file)
            {
                perror("Unable to open file");
                continue;
            }

            while ((bytes = SSL_read(ssl, buffer, sizeof(buffer))) > 0)
            {
                if (strncmp(buffer, "END", 3) == 0)
                    break;
                fwrite(buffer, 1, bytes, file);
            }
            fclose(file);
            printf("File downloaded as '%s'.\n", command);
        }
        else if (choice == 3)
        {
            printf("Enter filename to upload: ");
            fgets(command, sizeof(command), stdin);
            command[strcspn(command, "\n")] = '\0';

            // Ensure the STOR command doesn't overflow buffer
            // snprintf(buffer, BUFFER_SIZE - 5, "STOR %s", command);
            snprintf(buffer, BUFFER_SIZE - 5, "STOR %s", strncpy(temp, command, BUFFER_SIZE - 10));
            SSL_write(ssl, buffer, strlen(buffer));

            FILE *file = fopen(command, "rb");
            if (!file)
            {
                perror("Unable to open file");
                continue;
            }

            while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0)
            {
                SSL_write(ssl, buffer, bytes);
            }
            fclose(file);
            SSL_write(ssl, "END", 3);
            printf("File uploaded successfully.\n");
        }
        else if (choice == 4)
        {
            strcpy(command, "QUIT");
            SSL_write(ssl, command, strlen(command));
            printf("Disconnecting from server...\n");
            break;
        }
        else
        {
            printf("Invalid choice. Please try again.\n");
        }
    }
}

int main()
{
    int sock;
    struct sockaddr_in server_addr;
    SSL_CTX *ctx;
    SSL *ssl;

    initialize_openssl();
    ctx = create_context();

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Unable to connect to server");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    printf("Connected to server with SSL/TLS encryption.\n");

    handle_commands(ssl);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);

    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}
