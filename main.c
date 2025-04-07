#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

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

    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Erreur : échec de l'initialisation de curl\n");
        return 1;
    }

    // Étape 1 : DECLARE (à implémenter)
    // Étape 2 : FETCH en boucle (à implémenter)
    // Étape 3 : RESULT (à implémenter)

    curl_easy_cleanup(curl);
    curl_global_cleanup();
    return 0;
}