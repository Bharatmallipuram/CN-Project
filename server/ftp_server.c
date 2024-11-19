// Compile with: gcc ftp_server.c -o ftp_server -lssl -lcrypto

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
    const SSL_METHOD *method = SSLv23_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void handle_client(SSL *ssl)
{
    char buffer[BUFFER_SIZE] = {0};
    int bytes;

    while ((bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0)
    {
        buffer[bytes] = '\0';
        printf("Received command: %s\n", buffer);

        if (strncmp(buffer, "LIST", 4) == 0)
        {
            FILE *list_file = popen("ls", "r");
            if (list_file == NULL)
            {
                perror("Failed to list directory");
                SSL_write(ssl, "ERROR", strlen("ERROR"));
                return;
            }

            while (fgets(buffer, sizeof(buffer), list_file) != NULL)
            {
                SSL_write(ssl, buffer, strlen(buffer));
            }
            pclose(list_file);
            SSL_write(ssl, "END", strlen("END"));
        }
        else if (strncmp(buffer, "RETR ", 5) == 0)
        {
            char filename[BUFFER_SIZE];
            sscanf(buffer + 5, "%s", filename);
            FILE *file = fopen(filename, "rb");
            if (file == NULL)
            {
                perror("File open error");
                SSL_write(ssl, "ERROR", strlen("ERROR"));
                continue;
            }
            printf("Sending %s to client...\n", filename);
            while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0)
            {
                SSL_write(ssl, buffer, bytes);  // Send data in chunks
            }
            fclose(file);
            SSL_write(ssl, "END", 3);  // End of file transfer
        }
        else if (strncmp(buffer, "STOR ", 5) == 0)
        {
            char filename[BUFFER_SIZE];
            sscanf(buffer + 5, "%s", filename);
            FILE *file = fopen(filename, "wb");
            if (file == NULL)
            {
                perror("File open error");
                SSL_write(ssl, "ERROR", strlen("ERROR"));
                continue;
            }
            printf("Receiving %s from client...\n", filename);
            while ((bytes = SSL_read(ssl, buffer, sizeof(buffer))) > 0)
            {
                if (strncmp(buffer, "END", 3) == 0)
                    break;  // End of file transfer
                fwrite(buffer, 1, bytes, file);  // Write to file
            }
            fclose(file);
            printf("File %s stored successfully.\n", filename);
        }
        else if (strncmp(buffer, "QUIT", 4) == 0)
        {
            printf("Client requested to disconnect.\n");
            break;
        }
    }
}

int main()
{
    int server_fd;
    struct sockaddr_in addr;
    SSL_CTX *ctx;

    initialize_openssl();
    ctx = create_context();
    configure_context(ctx);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 1) < 0)
    {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    printf("Server is waiting for a client...\n");
    while (1)
    {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0)
        {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0)
        {
            ERR_print_errors_fp(stderr);
        }
        else
        {
            printf("Client connected with SSL/TLS encryption.\n");
            handle_client(ssl);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
