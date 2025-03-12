#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>
#include <ifaddrs.h>

#define PORT 8443
#define BUFFER_SIZE 1024

// 初始化 OpenSSL 库
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// 清理 OpenSSL 资源
void cleanup_openssl() {
    EVP_cleanup();
    ERR_free_strings();
}

// 创建 SSL 上下文
SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// 配置 SSL 上下文
void configure_context(SSL_CTX *ctx) {
    // 加载证书和私钥
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // 验证私钥是否与证书匹配
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(EXIT_FAILURE);
    }
}

// 获取服务器 IP 地址
char *get_server_ip() {
    struct ifaddrs *ifaddr, *ifa;
    static char ip[INET_ADDRSTRLEN];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return NULL;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *s = (struct sockaddr_in *)ifa->ifa_addr;
            if (inet_ntop(AF_INET, &s->sin_addr, ip, INET_ADDRSTRLEN) != NULL) {
                if (strcmp(ip, "127.0.0.1") != 0) {
                    freeifaddrs(ifaddr);
                    return ip;
                }
            }
        }
    }

    freeifaddrs(ifaddr);
    return NULL;
}

// 获取系统当前时间
char *get_current_time() {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    static char time_str[26];

    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    return time_str;
}

// 处理客户端请求
void handle_client(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    int bytes;

    // 读取客户端请求
    bytes = SSL_read(ssl, buffer, sizeof(buffer));
    if (bytes > 0) {
        buffer[bytes] = '\0';
        //printf("Received request:\n%s\n", buffer);

        // 获取服务器 IP 地址
        char *ip = get_server_ip();
        if (ip == NULL) {
            ip = "Unknown";
        }

        // 获取系统当前时间
        char *current_time = get_current_time();

        // 构造响应
        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response), "HTTP/1.1 200 OK\r\n"
                                               "Content-Type: text/html\r\n"
                                               "Content-Length: %zu\r\n"
                                               "\r\n"
                                               "<html><body><p>Server IP: %s</p><p>Current Time: %s</p></body></html>",
                 strlen("<html><body><p>Server IP: ") + strlen(ip) + strlen("</p><p>Current Time: ") + strlen(current_time) + strlen("</p></body></html>"),
                 ip, current_time);

        // 发送响应
        SSL_write(ssl, response, strlen(response));
    }

    // 关闭 SSL 连接
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    SSL_CTX *ctx;

    // 初始化 OpenSSL
    init_openssl();

    // 创建 SSL 上下文
    ctx = create_context();
    configure_context(ctx);

    // 创建套接字
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        cleanup_openssl();
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // 绑定套接字
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        cleanup_openssl();
        exit(EXIT_FAILURE);
    }

    // 监听连接
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        close(server_fd);
        cleanup_openssl();
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    while (1) {
        // 接受客户端连接
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
            perror("accept");
            continue;
        }

        // 创建 SSL 对象
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_socket);

        //printf("accept new client fd : %d, ssl : 0x%x\r\n", new_socket, ssl);

        // 执行 SSL 握手
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(new_socket);
            SSL_free(ssl);
            continue;
        }

        // 获取客户端 IP 地址和端口号
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(address.sin_addr), client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(address.sin_port);

        printf("Client connected from %s:%d, fd : %d, ssl : 0x%p\n", client_ip, client_port,new_socket, ssl);

        // 处理客户端请求
        handle_client(ssl);
    }

    // 清理资源
    close(server_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}