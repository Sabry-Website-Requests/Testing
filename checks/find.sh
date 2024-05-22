#!/bin/bash

search_patterns() {
    local pattern="[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]"
    local keywords="(key|password|token|auth_secret|api_key|auth_token|access_key|client_secret|api_secret|auth_key|client_key|oauth_token|session_key|private_key|public_key|shared_secret)"

    result=$(grep -rIE --color=auto --exclude="find.sh" --exclude=".git" --exclude=".*" \
        -E '(\bvariable\b|\bpassword\b|\btoken\b|\bkey\b|\bauth_secret\b|\bapi_key\b|\bauth_token\b|\baccess_key\b|\bclient_secret\b|\bapi_secret\b|\bauth_key\b|\bclient_key\b|\boauth_token\b|\bsession_key\b|\bprivate_key\b|\bpublic_key\b|\bshared_secret\b)[[:space:]]*([=]{1,3}|:)[[:space:]]*"[^"]+"' "$1")

    if [[ -z "$result" ]]; then
        echo "Check passed."
    else
        echo "$result"
    fi
}

search_directory=".."

search_patterns "$search_directory"
