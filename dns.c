#include <complex.h>
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
unsigned char responseBuf[MAX_BUF_SIZE];
uint responseBufIndex;
struct dns_data dnsResponse;

void packHeader() {
    id++;
    uint16_t networkId = htons(id);
    memcpy(&queryBuf[queryBufIndex], &networkId, 2);
    queryBufIndex += 2;
    
    uint16_t flags = htons(0x0100);
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
    char* domainCopy = calloc(strlen(domain) + 1, 1);
    if (domainCopy == NULL) {
        fprintf(stderr, "Error allocating memory to domainCopy\n");
        return NULL;
    }
    strcpy(domainCopy, domain);
    char delimiters[] = ".";
    char* formattedDomain = calloc(strlen(domain) + 2, 1); /* +1 for initial counter, +1 for null byte */
    if (formattedDomain == NULL) {
        fprintf(stderr, "Error allocating memory to formattedDomain\n");
        free(domainCopy);
        return NULL;
    }
    char* splitString = strtok(domainCopy, delimiters);
    while (splitString != NULL) {
        uint8_t lengthOfSplitString = strlen(splitString);
        char* formattedSplitString = calloc(strlen(splitString) + 1, 1);
        if (formattedSplitString == NULL) {
            fprintf(stderr, "Error allocating memory to formattedSplitString");
            free(domainCopy);
            free(formattedDomain);
            return NULL;
        }
        formattedSplitString[0] = lengthOfSplitString;
        memcpy(formattedSplitString + 1, splitString, lengthOfSplitString);
        strcat(formattedDomain, formattedSplitString);
        splitString = strtok(NULL, delimiters);
    }
    formattedDomain[strlen(formattedDomain)] = '\0';
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
    free(formattedDomain);
    
    uint16_t type = htons(1);
    memcpy(&queryBuf[queryBufIndex], &type, 2);
    queryBufIndex += 2;
    
    uint16_t class = htons(1);
    memcpy(&queryBuf[queryBufIndex], &class, 2);
    queryBufIndex += 2;
    
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
    dnsResponse.query.name = malloc(strlen(&responseBuf[responseBufIndex]) + 1);
    if (dnsResponse.query.name == NULL) {
        fprintf(stderr, "Error allocating memory to dnsResponse.query.name\n");
        return 1;
    }
    strcpy(dnsResponse.query.name, &responseBuf[responseBufIndex]);
    responseBufIndex += strlen(dnsResponse.query.name) + 1;
    
    memcpy(&dnsResponse.query.type, &responseBuf[responseBufIndex], 2);
    dnsResponse.query.type = ntohs(dnsResponse.query.type);
    responseBufIndex += 2;

    memcpy(&dnsResponse.query.class, &responseBuf[responseBufIndex], 2);
    dnsResponse.query.class = ntohs(dnsResponse.query.class);
    responseBufIndex += 2;
    return 0;
}

char* decompressDomain(struct resource_record record) {
    if (record.type == 1) {
        char *ipv4Domain = malloc(record.rdlength + 1);
        memcpy(ipv4Domain, &responseBuf[responseBufIndex], record.rdlength);
        responseBufIndex += record.rdlength;
        return ipv4Domain;
    } else if (record.type == 28) {
        char *ipv6Domain = malloc(record.rdlength + 1);
        memcpy(ipv6Domain, &responseBuf[responseBufIndex], record.rdlength);
        responseBufIndex += record.rdlength; 
        return ipv6Domain;
    }
    char* domain = malloc(256);
    if (domain == NULL) {
        perror("Error allocating memory to domain");
        return NULL;
    }
    int pos = 0;
    int jumped = 0;
    int offset;

    while (responseBuf[responseBufIndex] != 0) {
        if (responseBuf[responseBufIndex] >= 192) { // Pointer detected
            if (!jumped) {
                offset = responseBufIndex + 2;
            }
            responseBufIndex = ((responseBuf[responseBufIndex] & 0x3F) << 8) | responseBuf[responseBufIndex + 1];
            jumped = 1;
        } else {
            int len = responseBuf[responseBufIndex];
            responseBufIndex++;
            for (int i = 0; i < len; i++) {
                domain[pos++] = responseBuf[responseBufIndex];
                responseBufIndex++;
            }
            domain[pos++] = '.';
        }
    }

    if (!jumped) {
        responseBufIndex++;
    } else {
        responseBufIndex = offset;
    }

    domain[pos - 1] = '\0'; // Replace last '.' with null terminator
    return domain;
}
int unpackAnswers() {
    dnsResponse.answers = malloc(sizeof(struct resource_record)* dnsResponse.answers_count);
    for (int i = 0; i < dnsResponse.answers_count; i++) {
        dnsResponse.answers[i].name = decompressDomain(dnsResponse.answers[i]);
        if (dnsResponse.answers[i].name == NULL) {
            fprintf(stderr, "Error decompressing answer name.\n");
            return 1;
        }
        memcpy(&dnsResponse.answers[i].type, &responseBuf[responseBufIndex], 2);
        dnsResponse.answers[i].type = ntohs(dnsResponse.answers[i].type);
        responseBufIndex += 2;

        memcpy(&dnsResponse.answers[i].class, &responseBuf[responseBufIndex], 2);
        dnsResponse.answers[i].class = ntohs(dnsResponse.answers[i].class);
        responseBufIndex += 2;

        memcpy(&dnsResponse.answers[i].ttl, &responseBuf[responseBufIndex], 4);
        dnsResponse.answers[i].ttl = ntohl(dnsResponse.answers[i].ttl);
        responseBufIndex += 4;

        memcpy(&dnsResponse.answers[i].rdlength, &responseBuf[responseBufIndex], 2);
        dnsResponse.answers[i].rdlength = ntohs(dnsResponse.answers[i].rdlength);
        responseBufIndex += 2;

        dnsResponse.answers[i].rdata = decompressDomain(dnsResponse.answers[i]);
        if (dnsResponse.answers[i].rdata == NULL) {
            fprintf(stderr, "Error decompressing answer rdata.\n");
            return 1;
        }
    }
    return 0;
}
int unpackAuthorities() {
    dnsResponse.authorities = malloc(sizeof(struct resource_record)* dnsResponse.authority_count);
    for (int i = 0; i < dnsResponse.authority_count; i++) {
        dnsResponse.authorities[i].name = decompressDomain(dnsResponse.authorities[i]);
        if (dnsResponse.authorities[i].name == NULL) {
            fprintf(stderr, "Error decompressing authority name.\n");
            return 1;
        }

        memcpy(&dnsResponse.authorities[i].type, &responseBuf[responseBufIndex], 2);
        dnsResponse.authorities[i].type = ntohs(dnsResponse.authorities[i].type);
        responseBufIndex += 2;
        
        memcpy(&dnsResponse.authorities[i].class, &responseBuf[responseBufIndex], 2);
        dnsResponse.authorities[i].class = ntohs(dnsResponse.authorities[i].class);
        responseBufIndex += 2;
        
        memcpy(&dnsResponse.authorities[i].ttl, &responseBuf[responseBufIndex], 4);
        dnsResponse.authorities[i].ttl = ntohs(dnsResponse.authorities[i].ttl);
        responseBufIndex += 4;
        
        memcpy(&dnsResponse.authorities[i].rdlength, &responseBuf[responseBufIndex], 4);
        dnsResponse.authorities[i].rdlength = ntohs(dnsResponse.authorities[i].rdlength);
        responseBufIndex += 2;
        
        dnsResponse.authorities[i].rdata = decompressDomain(dnsResponse.authorities[i]);
        if (dnsResponse.authorities[i].rdata == NULL) {
            fprintf(stderr, "Error decompressing authority rdata.\n");
            return 1;
        }
    }
    return 0;
}
int unpackAdditionals() {
    dnsResponse.additionals = malloc(sizeof(struct resource_record)* dnsResponse.additional_count);
    for (int i = 0; i < dnsResponse.additional_count; i++) {
        dnsResponse.additionals[i].name = decompressDomain(dnsResponse.additionals[i]);
        if (dnsResponse.additionals[i].name == NULL) {
            fprintf(stderr, "Error decompressing additional name.\n");
            return 1;
        }

        memcpy(&dnsResponse.additionals[i].type, &responseBuf[responseBufIndex], 2);
        dnsResponse.additionals[i].type = ntohs(dnsResponse.additionals[i].type);
        responseBufIndex += 2;
        
        memcpy(&dnsResponse.additionals[i].class, &responseBuf[responseBufIndex], 2);
        dnsResponse.additionals[i].class = ntohs(dnsResponse.additionals[i].class);
        responseBufIndex += 2;
        
        memcpy(&dnsResponse.additionals[i].ttl, &responseBuf[responseBufIndex], 4);
        dnsResponse.additionals[i].ttl = ntohs(dnsResponse.additionals[i].ttl);
        responseBufIndex += 4;
        
        memcpy(&dnsResponse.additionals[i].rdlength, &responseBuf[responseBufIndex], 4);
        dnsResponse.additionals[i].rdlength = ntohs(dnsResponse.additionals[i].rdlength);
        responseBufIndex += 2;
        
        dnsResponse.additionals[i].rdata = decompressDomain(dnsResponse.additionals[i]);
        if (dnsResponse.additionals[i].rdata == NULL) {
            fprintf(stderr, "Error decompressing additional rdata.\n");
            return 1;
        }
    }
    return 0;
}
int hexToAsciiIp(char* hexIp, char* result) {

    char *primaryLabel = malloc(15);
    if (primaryLabel == NULL) {
        fprintf(stderr, "Error allocating memory to primaryLabel.\n");
        return 1;
    }
    for(int i = 0; i < 4; i++) {
        char *tempLabel = malloc(4);
        if (tempLabel == NULL) {
            fprintf(stderr, "Error allocating memory to tempLabel.\n");
            free(primaryLabel);
            return 1;
        }
        unsigned char unsignedIp = (unsigned char) hexIp[i];
        int ipLabel = (int) unsignedIp;
        sprintf(tempLabel, "%d.", ipLabel);
        strcat(primaryLabel, tempLabel);
    }
    primaryLabel[strlen(primaryLabel) - 1] = '\0';
    strcpy(result, primaryLabel);
    return 0;
}
int displayResourceRecord(uint16_t recordCount, struct resource_record record[recordCount]) {
    for (int i = 0; i < recordCount; i++) {
        uint8_t lengthOfLongestTypeString = 6;
        char *typeString = malloc(lengthOfLongestTypeString);
        if (typeString == NULL) {
            fprintf(stderr, "Failed to allocate memory to typeString.\n");
            return 1;
        }
        switch(record[i].type) {
            case 1:
                strcpy(typeString, "A");
                break;
            case 2:
                strcpy(typeString, "NS");
                break;
            case 5:
                strcpy(typeString, "CNAME");
                break;
            case 6:
                strcpy(typeString, "SOA");
                break;
            case 12:
                strcpy(typeString, "PTR");
                break;
            case 15:
                strcpy(typeString, "MX");
                break;
            case 28:
                strcpy(typeString, "AAAA");
                break;
        }
        if (typeString == NULL) {
            fprintf(stderr, "Unrecognized record type\n");
            free(typeString);
            return 1;
        }
        if (record[i].type == 1) {
            char *ipv4AsString = malloc(16);
            if (ipv4AsString == NULL) {
                fprintf(stderr, "Error allocating memory to ipv4AsString");
                free(typeString);
                free(ipv4AsString);
                return 1;
            }
            if (hexToAsciiIp(record[i].rdata, ipv4AsString) == 1) {
                fprintf(stderr, "Error converting hex ip to ascii.\n");
                free(typeString);
                free(ipv4AsString);
                return 1;
            }
            printf("%-30s\t%s\t%d\t%s\n", record[i].name, typeString, record[i].ttl, ipv4AsString);
            free(ipv4AsString);
        } else {
            printf("%-30s\t%s\t%d\t%s\n", record[i].name, typeString, record[i].ttl, record[i].rdata);
        }
        free(typeString);
    }
    return 0;
}
void freeDnsResponse() {
    free(dnsResponse.query.name);
    for (int i = 0; i < dnsResponse.answers_count; i++) {
        free(dnsResponse.answers[i].name);
        free(dnsResponse.answers[i].rdata);
    }
    free(dnsResponse.answers);
    for (int i = 0; i < dnsResponse.authority_count; i++) {
        free(dnsResponse.authorities[i].name);
        free(dnsResponse.authorities[i].rdata);
    }
    free(dnsResponse.authorities);
    for (int i = 0; i < dnsResponse.additional_count; i++) {
        free(dnsResponse.additionals[i].name);
        free(dnsResponse.additionals[i].rdata);
    }
    free(dnsResponse.additionals);
}
int main(int argc, char** argv) {
    if (argv[1] == NULL) {
        fprintf(stderr, "Invalid domain given.\n");
        return 1;
    }
    char googleResolverIpv4[8] = "8.8.8.8";
    uint sizeOfHeaderInBytes = 12;
    uint sizeOfQuestionInBytes = strlen(argv[1]) + 6; /* +1 for initial counter, +1 for null byte, +2 for class, +2 for type */
    queryBuf = malloc(sizeOfHeaderInBytes + sizeOfQuestionInBytes);
    if (queryBuf == NULL) {
        fprintf(stderr, "Error allocating memory to queryBuf.\n");
        return 1;
    }
    packHeader();
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
    free(queryBuf);
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
    // Check if flags are 0x8001, that is a 'standard query response, Format error'. Also check for all other errors
    unpackHeader();
    if (unpackQuestion() != 0) {
        fprintf(stderr, "Error unpacking question.\n");
        return 1;
    }
    if (unpackAnswers() != 0) {
        fprintf(stderr, "Error unpacking answers.\n");
        return 1;
    } else {
        if (dnsResponse.answers_count > 0) {

            printf("%s answers:\n", argv[1]);
            printf("--------------------------------------\n");
            if (displayResourceRecord(dnsResponse.answers_count, dnsResponse.answers) == 1) {
                fprintf(stderr, "Error displaying answer resource record\n");
                return 1;
            }
            printf("\n");
        }
    }

    if (unpackAuthorities() != 0) {
        fprintf(stderr, "Error unpacking authorities.\n");
        return 1;
    } else {
       if (dnsResponse.authority_count > 0) {

            printf("%s authorities:\n", argv[1]);
            printf("--------------------------------------\n");

            if (displayResourceRecord(dnsResponse.authority_count, dnsResponse.authorities) == 1) {
                fprintf(stderr, "Error displaying authorities resource record\n");
                return 1;
            }
            printf("\n");
        }

    }

    if (unpackAdditionals() != 0) {
        fprintf(stderr, "Error unpacking additionals.\n");
        return 1;
    } else {
        if (dnsResponse.additional_count > 0) {

            printf("%s additionals:\n", argv[1]);
            printf("--------------------------------------\n");
            if (displayResourceRecord(dnsResponse.additional_count, dnsResponse.additionals) == 1) {
                fprintf(stderr, "Error displaying additional resource record\n");
                return 1;
            }
            printf("\n");
        }
    }
    freeDnsResponse();
    return 0;
}
