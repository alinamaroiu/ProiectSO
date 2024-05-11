#!/bin/bash



# Funcția pentru a verifica dacă un cuvânt este o cuvânt cheie asociat fișierelor periculoase

is_keyword() {

    keywords=("corrupted" "dangerous" "risk" "attack" "malware" "malicious")

    for keyword in "${keywords[@]}"; do

        if [[ "$1" == *"$keyword"* ]]; then

            return 0 # Cuvântul este o cuvânt cheie

        fi

    done

    return 1 # Cuvântul nu este o cuvânt cheie

}



#analizarea unui fișier și a determina dacă este suspect sau nu

    file_path="$1"



    chmod +r "$file_path"



    line_count=$(wc -l < "$file_path")

    word_count=$(wc -w < "$file_path")

    char_count=$(wc -m < "$file_path")

    non_ascii_count=$(grep -cP '[^\x00-\x7F]' "$file_path")

    if [ "$line_count" -lt 3 ] && [ "$word_count" -gt 1000 ] && [ "$char_count" -gt 2000 ] && [ "$non_ascii_count" -gt 5 ]; then

        echo "$file_path" # Fișierul este suspect

    fi



    while read -r word; do

        if is_keyword "$word"; then

            echo "$file_path" # Fișierul este suspect

        fi

    done < <(tr -sc '[:alnum:]' '\n' < "$file_path")



    echo "SAFE" # Fișierul este sigur



chmod 000 "$file_path"



exit 0