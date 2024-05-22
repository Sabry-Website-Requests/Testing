#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>

int main() {
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    char buffer[1024];

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        std::cerr << "Error creating socket" << std::endl;
        return -1;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(8082);

    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) {
        std::cerr << "Error binding socket" << std::endl;
        close(serverSocket);
        return -1;
    }

    if (listen(serverSocket, 5) == -1) {
        std::cerr << "Error listening on socket" << std::endl;
        close(serverSocket);
        return -1;
    }

    std::cout << "Server started on port 8082" << std::endl;

    while (true) {
        socklen_t clientAddrLen = sizeof(clientAddr);

        clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &clientAddrLen);
        if (clientSocket == -1) {
            std::cerr << "Error accepting connection" << std::endl;
            close(serverSocket);
            return -1;
        }

        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesReceived == -1) {
            std::cerr << "Error receiving data from client" << std::endl;
            close(clientSocket);
            continue;
        }

        std::cout << "Received from client: " << std::string(buffer, bytesReceived) << std::endl;

        const char *response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello from C++ server";
        send(clientSocket, response, strlen(response), 0);

        close(clientSocket);
    }

    close(serverSocket);

    return 0;
}
