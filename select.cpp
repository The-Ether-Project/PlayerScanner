#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>

#include <iostream>
#include <fstream>

#include <chrono>

#include "json.hpp"
using json = nlohmann::json;

//THE SHIT BELOW THIS IS SHIT
#include <sys/types.h>

#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <condition_variable>
#include <errno.h>
#include <iterator>
#include <sstream>
#include <string.h>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>

#define HANDSHAKE_SIZE 1024
#define STRING_BUF_SIZE 16
#define PROTOCOL_VERSION 210
#define TIMEOUT_SEC 1 // 1000ms

std::ofstream myfile;
std::string start_time;

struct host
{
   std::string ip;
   int port;
};

uint64_t timeSinceEpochMillisec()
{
   using namespace std::chrono;
   return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

template <typename C, typename P>
void erase_remove_if(C &c, P predicate)
{
   c.erase(std::remove_if(c.begin(), c.end(), predicate), c.end());
}

struct InvalidChar
{
   bool operator()(char c) const
   {
      return !isprint(static_cast<unsigned char>(c));
   }
};

int connect_w_to(struct addrinfo *addr, time_t sec)
{
   int res;
   long arg;
   fd_set myset;
   struct timeval tv;
   int valopt;
   socklen_t lon;
   int soc;

   // Create socket
   soc = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
   if (soc < 0)
   {
      fprintf(stderr, "Error creating socket (%d %s)\n", errno, strerror(errno));
      return -1;
   }

   // Set non-blocking
   if ((arg = fcntl(soc, F_GETFL, NULL)) < 0)
   {
      fprintf(stderr, "Error fcntl(..., F_GETFL) (%s)\n", strerror(errno));
      return -1;
   }
   arg |= O_NONBLOCK;
   if (fcntl(soc, F_SETFL, arg) < 0)
   {
      fprintf(stderr, "Error fcntl(..., F_SETFL) (%s)\n", strerror(errno));
      return -1;
   }
   // Trying to connect with timeout
   res = connect(soc, addr->ai_addr, addr->ai_addrlen);
   if (res < 0)
   {
      if (errno == EINPROGRESS)
      {
         do
         {
            tv.tv_sec = sec;
            tv.tv_usec = 0;
            FD_ZERO(&myset);
            FD_SET(soc, &myset);
            res = select(soc + 1, NULL, &myset, NULL, &tv);
            if (res < 0 && errno != EINTR)
            {
               fprintf(stderr, "Error connecting %d - %s\n", errno, strerror(errno));
               return -1;
            }
            else if (res > 0)
            {
               // Socket selected for write
               lon = sizeof(int);
               if (getsockopt(soc, SOL_SOCKET, SO_ERROR, (void *)(&valopt), &lon) < 0)
               {
                  fprintf(stderr, "Error in getsockopt() %d - %s\n", errno, strerror(errno));
                  close(soc);
                  return -1;
               }
               // Check the value returned...
               if (valopt)
               {
                  close(soc);
                  return -1;
               }
               break;
            }
            else
            {
               close(soc);
               return -1;
            }
         } while (1);
      }
      else
      {
         fprintf(stderr, "Error connecting %d - %s\n", errno, strerror(errno));
         return -1;
      }
   }
   // Set to blocking mode again...
   if ((arg = fcntl(soc, F_GETFL, NULL)) < 0)
   {
      fprintf(stderr, "Error fcntl(..., F_GETFL) (%s)\n", strerror(errno));
      return -1;
   }
   arg &= (~O_NONBLOCK);
   if (fcntl(soc, F_SETFL, arg) < 0)
   {
      fprintf(stderr, "Error fcntl(..., F_SETFL) (%s)\n", strerror(errno));
      return -1;
   }

   return soc;
}

int set_timeout(int sfd, time_t sec)
{
   struct timeval timeout;
   timeout.tv_sec = sec;
   timeout.tv_usec = 0;

   int yes = 1;
   setsockopt(
       sfd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(int));

   // Receive
   if (setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
   {
      fprintf(stderr, "setsockopt failed\n");
      return -1;
   }

   // Send
   if (setsockopt(sfd, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
   {
      fprintf(stderr, "setsockopt failed\n");
      return -1;
   }

   return 0;
}

size_t build_handshake(unsigned char *buffer, char *host, unsigned short port)
{
   size_t host_len = strlen(host);
   size_t len = 1 /* packet id */ + 2 /* Protocol version */;
   len += 1 /* str len */ + host_len;
   len += 2; // port
   len += 1; // state

   size_t i = 0;
   buffer[i++] = len;
   buffer[i++] = 0; /* packet id */
   buffer[i++] = PROTOCOL_VERSION;
   buffer[i++] = 1; /* encoded protocol version - varint */
   buffer[i++] = host_len;
   memcpy(buffer + i, host, host_len);
   i += host_len;
   buffer[i++] = (port >> 8) & 0xFF; /* port little-endian */
   buffer[i++] = port & 0xFF;
   buffer[i] = 1; // next state

   return len + 1; /* add length byte */
}

ssize_t read_byte(const int sfd, void *buf)
{
   ssize_t nread;
   nread = recv(sfd, buf, 1, 0);
   if (nread == -1)
   {
      //perror("Read byte");
      return (1);
   }
   return nread;
}

int read_varint(const int sfd)
{
   int numread = 0;
   int result = 0;
   int value;
   char byte;
   do
   {
      if (read_byte(sfd, &byte) == 0)
      {
         //fprintf(stderr, "Failed read varint: eof\n");

         return (-1);
      }
      value = byte & 0x7F;
      result |= value << (7 * numread);

      numread++;

      if (numread > 5)
      {
         //fprintf(stderr, "Error reading varint: varint too big\n");

         return (-1);
      }
   } while ((byte & 0x80) != 0);

   return result;
}

void ping_server(char *hostname, unsigned short port)
{
   int sfd, s, json_len;
   char string[STRING_BUF_SIZE];
   char port_str[6];
   struct addrinfo hints;
   struct addrinfo *result, *rp;
   char byte;
   unsigned char handshake[HANDSHAKE_SIZE];
   char request[] = {0x1, 0x0};
   size_t len;
   ssize_t nread;

   if (strlen(hostname) > 250)
   {
      fprintf(stderr, "Hostname too long\n");
      return;
   }

   if (port == 0)
   {
      fprintf(stderr, "Invalid port\n");
      return;
   }

#ifdef _WIN32
   WORD wVersionRequested;
   WSADATA wsaData;
   int err;

   /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
   wVersionRequested = MAKEWORD(2, 2);

   err = WSAStartup(wVersionRequested, &wsaData);
   if (err != 0)
   {
      /* Tell the user that we could not find a usable */
      /* Winsock DLL.                                  */
      fprintf(stderr, "WSAStartup failed with error: %d\n", err);
      return;
   }
   /* Confirm that the WinSock DLL supports 2.2.*/
   /* Note that if the DLL supports versions greater    */
   /* than 2.2 in addition to 2.2, it will still return */
   /* 2.2 in wVersion since that is the version we      */
   /* requested.                                        */

   if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
   {
      /* Tell the user that we could not find a usable */
      /* WinSock DLL.                                  */
      fprintf(stderr, "Could not find a usable version of Winsock.dll\n");
      WSACleanup();
      return;
   }
#endif

   /* Obtain address(es) matching host/port */
   memset(&hints, 0, sizeof(struct addrinfo));
   hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
   hints.ai_socktype = SOCK_STREAM; /* TCP socket */
   hints.ai_flags = 0;
   hints.ai_protocol = 0; /* Any protocol */

   sprintf(port_str, "%d", port);
   s = getaddrinfo(hostname, port_str, &hints, &result);
   if (s != 0)
   {
      fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
      return;
   }

   /* getaddrinfo() returns a list of address structures.
     Try each address until we successfully connect(2).
     If socket(2) (or connect(2)) fails, we (close the socket
     and) try the next address. */

   for (rp = result; rp != NULL; rp = rp->ai_next)
   {
      sfd = connect_w_to(rp, TIMEOUT_SEC);
      if (sfd != -1)
      {
         break;
      }

      close(sfd);
   }

   if (rp == NULL)
   { /* No address succeeded */
      //fprintf(stderr, "Could not connect\n");

      return;
   }

   if (set_timeout(sfd, TIMEOUT_SEC) == -1)
   {
      close(sfd);
      return;
   }

   freeaddrinfo(result);

   len = build_handshake(handshake, hostname, port);
   if (send(sfd, handshake, len, 0) != len)
   {
      //fprintf(stderr, "Failed to send handshake\n");
      close(sfd);
      return;
   }

   if (send(sfd, request, 2, 0) != 2)
   {
      //fprintf(stderr, "Failed to send request\n");
      close(sfd);
      return;
   }

   read_varint(sfd); /* read packet length */
   if (read_byte(sfd, &byte) == 0)
   { /* read packet id */
      //fprintf(stderr, "Failed to read\n");
      close(sfd);
      return;
   }
   if (byte != 0)
   {
      //fprintf(stderr, "Unknown packet id\n");
      close(sfd);
      return;
   }

   std::string jsonStuff;

   /* read json and print to stdout */
   json_len = read_varint(sfd);
   while (json_len > 0)
   {
      nread = recv(sfd, string, STRING_BUF_SIZE, 0);
      if (nread == -1)
      {
         //perror("json read");
         close(sfd);
         return;
      }

      json_len -= nread;

      std::string readBuffer(string, nread);

      jsonStuff += readBuffer;
   }

   close(sfd);

   erase_remove_if(jsonStuff, InvalidChar());

   if (jsonStuff.length() != 0)
   {
      try
      {
         json j = json::parse(jsonStuff);
         if (sizeof(j["players"]["sample"]) > 0 && j["players"]["sample"] != nullptr)

         {
            sqlite3 *db;
            char *zErrMsg = 0;
            int rc;

            /* Open database */
            rc = sqlite3_open("players.db", &db);

            if (rc)
            {
               fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
            }

            auto sample = j["players"]["sample"];
            for (int i = 0; i < sample.size(); i++)
            {
               std::string id = sample[i]["id"];
               std::string name = sample[i]["name"];

               std::string mainString;
               mainString = "INSERT INTO PLAYERS (TIMESTAMP,IP,PORT,ID,NAME) VALUES (?,?,?,?,?)";

               sqlite3_stmt *statement;
               sqlite3_prepare_v2(db, mainString.c_str(), mainString.length(), &statement, NULL);

               sqlite3_bind_int64(statement, 1, timeSinceEpochMillisec());
               sqlite3_bind_text(statement, 2, hostname, strlen(hostname), SQLITE_TRANSIENT);
               sqlite3_bind_int(statement, 3, port);
               sqlite3_bind_text(statement, 4, id.c_str(), id.size(), SQLITE_TRANSIENT);
               sqlite3_bind_text(statement, 5, name.c_str(), name.size(), SQLITE_TRANSIENT);

               sqlite3_step(statement);
               sqlite3_finalize(statement);
            }
            sqlite3_close(db);
         }
      }
      catch (json::parse_error)
      {
         return;
      }
   }
   return;
}

static int callback(void *data, int argc, char **argv, char **azColName)
{
   int i;

   for (i = 0; i < argc; i++)
   {
      myfile << argv[i] << std::endl;
   }

   return 0;
}

int counter = 0;

static int callback_two(void *data, int argc, char **argv, char **azColName)
{
   ping_server(argv[0], std::stoi(argv[1]));
   return 0;
}

int part_one()
{
   printf("Checking if processor is available...");
   if (system(NULL))
      puts("Ok");
   else
      exit(EXIT_FAILURE);

   sqlite3 *db;
   char *zErrMsg = 0;
   int rc;
   char *sql;
   const char *data = "Callback function called";

   /* Open database */
   rc = sqlite3_open("videlicet.db", &db);

   if (rc)
   {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return (0);
   }
   else
   {
      fprintf(stderr, "Opened database successfully\n");
   }

   myfile.open("masscanInput.txt");

   /* Create SQL statement */
   sql = "SELECT DISTINCT IP from BASIC_PINGS";

   /* Execute SQL statement */
   rc = sqlite3_exec(db, sql, callback, (void *)data, &zErrMsg);

   if (rc != SQLITE_OK)
   {
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
   }
   else
   {
      fprintf(stdout, "Operation done successfully\n");
   }
   myfile.close();
   sqlite3_close(db);

   start_time = std::to_string(timeSinceEpochMillisec());

   system("./masscan -iL masscanInput.txt -p25550-25587 --max-rate 1000 --banners --hello=minecraft --source-ip 192.168.1.234");

   return 0;
}

int part_two()
{
   sqlite3 *db;
   char *zErrMsg = 0;
   int rc;
   std::string sql;

   const char *data = "Callback function called";

   /* Open database */
   rc = sqlite3_open("videlicet.db", &db);

   if (rc)
   {
      fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
      return (0);
   }
   else
   {
      fprintf(stderr, "Opened database successfully\n");
   }

   /* Create SQL statement */
   sql = "SELECT DISTINCT IP, PORT FROM BASIC_PINGS WHERE PLAYERS_ONLINE > 0 AND TIMESTAMP > " + start_time;

   /* Execute SQL statement */
   rc = sqlite3_exec(db, sql.c_str(), callback_two, (void *)data, &zErrMsg);

   if (rc != SQLITE_OK)
   {
      fprintf(stderr, "SQL error: %s\n", zErrMsg);
      sqlite3_free(zErrMsg);
   }
   else
   {
      fprintf(stdout, "Operation done successfully\n");
   }
   sqlite3_close(db);

   return 0;
}

int main(int argc, char *argv[])
{
   part_one();
   printf("Checking for players... Please be patient or fuck off.\n");
   part_two();
   return 0;
}
