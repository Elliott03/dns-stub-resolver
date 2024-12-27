#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>

#define DNS_PORT 53
#define MAX_BUF_SIZE 1024

struct resource_record {
    char* name;
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    char* rdata;
};

struct query {
    char* name;
    uint16_t type;
    uint16_t class;
};

struct dns_data {
    uint16_t transactionId;
    uint16_t flags;
    uint16_t question_count;
    uint16_t answers_count;
    uint16_t authority_count;
    uint16_t additional_count;
    struct query query;
    struct resource_record* answers;
    struct resource_record* authorities;
    struct resource_record* additionals;
};

uint16_t id = 0;
char* queryBuf;
uint queryBufIndex = 0;
char responseBuf[MAX_BUF_SIZE];
uint responseBufIndex;
struct dns_data dnsResponse;

void packHeader() {
    id++;
    uint16_t networkId = htons(id);
    memcpy(&queryBuf[queryBufIndex], &networkId, 2);
    queryBufIndex += 2;
    
    uint16_t flags = 0;
    memcpy(&queryBuf[queryBufIndex], &flags, 2);
    queryBufIndex += 2;

    uint16_t qdcount = htons(1); 
    memcpy(&queryBuf[queryBufIndex], &qdcount, 2);
    queryBufIndex += 2;

    uint16_t ancount = 0;
    memcpy(&queryBuf[queryBufIndex], &ancount, 2);
    queryBufIndex += 2;

    uint16_t nscount = 0;
    memcpy(&queryBuf[queryBufIndex], &nscount, 2);
    queryBufIndex += 2;

    uint16_t arcount = 0;
    memcpy(&queryBuf[queryBufIndex], &arcount, 2);
    queryBufIndex += 2;
}

char* formatDomain(char* domain) {
    printf("Formatting Question...\n");
    char* domainCopy = malloc(strlen(domain) + 1);
    if (domainCopy == NULL) {
        fprintf(stderr, "Error allocating memory to domainCopy\n");
        free(domainCopy);
        return NULL;
    }
    strcpy(domainCopy, domain);
    char delimiters[] = ".";
    char* formattedDomain = malloc(strlen(domain) + 2); /* +1 for initial counter, +1 for null byte */
    if (formattedDomain == NULL) {
        fprintf(stderr, "Error allocating memory to formattedDomain\n");
        free(domainCopy);
        return NULL;
    }

    char* splitString = strtok(domainCopy, delimiters);
    while (splitString != NULL) {
        uint8_t lengthOfSplitString = strlen(splitString);
        char* formattedSplitString = malloc(strlen(splitString) + 1);
        if (formattedSplitString == NULL) {
            fprintf(stderr, "Error allocating memory to formattedSplitString");
            free(domainCopy);
            free(formattedDomain);
            return NULL;
        }
        formattedSplitString[0] = lengthOfSplitString;
        memcpy(formattedSplitString + 1, splitString, lengthOfSplitString);
        strcat(formattedDomain, formattedSplitString);
        free(formattedSplitString);
        splitString = strtok(NULL, delimiters);
    }

    strcat(formattedDomain, "\0");
    free(domainCopy);
    return formattedDomain;
}
int packQuestion(char* domain) {
    char *formattedDomain = formatDomain(domain);
    if (formattedDomain == NULL) {
        fprintf(stderr, "Error in formatDomain()\n");
        free(formattedDomain);
        return 1;
    }
    strcpy(&queryBuf[queryBufIndex], formattedDomain);
    queryBufIndex += strlen(formattedDomain) + 1;
    
    uint16_t type = htons(1);
    memcpy(&queryBuf[queryBufIndex], &type, 2);
    queryBufIndex += 2;
    
    uint16_t class = htons(1);
    memcpy(&queryBuf[queryBufIndex], &class, 2);
    queryBufIndex += 2;
    
    free(formattedDomain);
    return 0;
}
void unpackHeader() {
    memcpy(&dnsResponse.transactionId, &responseBuf[responseBufIndex], 2);
    dnsResponse.transactionId = ntohs(dnsResponse.transactionId);
    responseBufIndex += 2;

    memcpy(&dnsResponse.flags, &responseBuf[responseBufIndex], 2);
    dnsResponse.flags = ntohs(dnsResponse.flags);
    responseBufIndex += 2;

    memcpy(&dnsResponse.question_count, &responseBuf[responseBufIndex], 2);
    dnsResponse.question_count = ntohs(dnsResponse.question_count);
    responseBufIndex += 2;

    memcpy(&dnsResponse.answers_count, &responseBuf[responseBufIndex], 2);
    dnsResponse.answers_count = ntohs(dnsResponse.answers_count);
    responseBufIndex += 2;

    memcpy(&dnsResponse.authority_count, &responseBuf[responseBufIndex], 2);
    dnsResponse.authority_count = ntohs(dnsResponse.authority_count);
    responseBufIndex += 2;

    memcpy(&dnsResponse.additional_count, &responseBuf[responseBufIndex], 2);
    dnsResponse.additional_count = ntohs(dnsResponse.additional_count);
    responseBufIndex += 2;
}
int unpackQuestion() { // This function assumes we have 1 question
    char* question = malloc(strlen(&responseBuf[responseBufIndex]) + 1);
    strcpy(question, &responseBuf[responseBufIndex]);
    dnsResponse.query.name = malloc(strlen(question) + 1);
    responseBufIndex += strlen(question) + 1;
}
int main(int argc, char** argv) {
    if (argv[1] == NULL) {
        fprintf(stderr, "Invalid domain given.\n");
        return 1;
    }
    char googleResolverIpv4[8] = "8.8.8.8";
    uint sizeOfHeaderInBytes = 12;
    uint sizeOfQuestionInBytes = strlen(argv[1]); /* +1 for initial counter, +1 for null byte, +2 for class, +2 for type */
    queryBuf = malloc(sizeOfHeaderInBytes + sizeOfQuestionInBytes);
    if (queryBuf == NULL) {
        fprintf(stderr, "Error allocating memory to queryBuf.\n");
        return 1;
    }

    if (packQuestion(argv[1]) == 1) {
        fprintf(stderr, "Error in packQuestion()\n");
        free(queryBuf);
        return 1;
    }
    struct sockaddr_in servinfo;
    int sockfd;
    int numBytes;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    servinfo.sin_family = AF_INET;
    servinfo.sin_port = htons(DNS_PORT);
    if (inet_pton(AF_INET, googleResolverIpv4, &servinfo.sin_addr) <= 0) {
        fprintf(stderr, "inet_pton failed\n");
        return 1;
    }
    if (sockfd < 0) {
        fprintf(stderr, "socket creation failed\n");
        return 1;
    }
    if ((numBytes = sendto(sockfd, queryBuf, sizeOfHeaderInBytes + sizeOfQuestionInBytes, 0, (struct sockaddr*)&servinfo, sizeof(servinfo))) == -1) {
        fprintf(stderr, "sendto failed\n");
        return 1;
    }
    printf("client sent %d bytes to %s\n", numBytes, googleResolverIpv4);
    socklen_t addrLen = sizeof(servinfo);
    if ((numBytes = recvfrom(sockfd, responseBuf, MAX_BUF_SIZE, 0, (struct sockaddr*)&servinfo, &addrLen)) == -1) {
        fprintf(stderr, "recvfrom failed\n");
        return 1;
    }
    if (close(sockfd) == -1) {
        fprintf(stderr, "Error closing socket");
        return 1;
    }
    printf("client recieved %d bytes\n", numBytes);
    if (numBytes > MAX_BUF_SIZE) {
        fprintf(stderr, "Error reading response - response too large\n");
        return 1;
    } 
    unpackHeader();
    


    free(queryBuf);
}
