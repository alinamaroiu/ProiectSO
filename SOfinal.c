#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>

#define MAX_DIRECTORIES 10

// Structura pentru metadatele unei intrări (fișier sau director)
typedef struct {
    char name[256];
    char type; // 'F' pentru fișier, 'D' pentru director
    time_t last_modified;
    off_t size;
    mode_t permissions;
    ino_t inode_number;
} Metadata;

// Funcția pentru a crea snapshot-ul pentru un director și subdirectoarele sale
void createSnapshot(const char *dir_path, FILE *snapshot_file) {
    DIR *dir;
    struct dirent *entry;
    struct stat file_stat;
    Metadata metadata;

    dir = opendir(dir_path);

    if (dir == NULL) {
        fprintf(stderr, "Nu s-a putut deschide directorul %s\n", dir_path);
        return;
    }

    // Scrie numele directorului în snapshot
    fprintf(snapshot_file, "%s\n", dir_path);

    while ((entry = readdir(dir)) != NULL) {
        char entry_path[256];
        strcpy(entry_path, dir_path);
        strcat(entry_path, "/");
        strcat(entry_path, entry->d_name);

        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            stat(entry_path, &file_stat);

            strcpy(metadata.name, entry->d_name);
            metadata.last_modified = file_stat.st_mtime;
            metadata.size = file_stat.st_size;
            metadata.permissions = file_stat.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
            metadata.inode_number = file_stat.st_ino;

            if (S_ISDIR(file_stat.st_mode)) {
                metadata.type = 'D';
                // Apel recursiv pentru subdirector
                createSnapshot(entry_path, snapshot_file);
            } else {
                metadata.type = 'F';
            }

            // Scrie metadatele în snapshot
            fprintf(snapshot_file, "%c\t%s\t%ld\t%ld\t%o\t%lu\n", metadata.type, metadata.name, (long)metadata.last_modified, (long)metadata.size, metadata.permissions, (unsigned long)metadata.inode_number);
        }
    }

    closedir(dir);
}

// Funcția pentru a compara snapshot-urile și a actualiza cel vechi
void compareAndUpdateSnapshots(const char *old_snapshot_path, const char *new_snapshot_path) {
    // Deschide fișierele de snapshot
    FILE *old_snapshot_file = fopen(old_snapshot_path, "r");
    FILE *new_snapshot_file = fopen(new_snapshot_path, "r");

    // Verifică dacă s-au putut deschide fișierele de snapshot
    if (old_snapshot_file == NULL || new_snapshot_file == NULL) {
        if (old_snapshot_file != NULL) {
            fclose(old_snapshot_file);
        }
        if (new_snapshot_file != NULL) {
            fclose(new_snapshot_file);
        }
        //fprintf(stderr, "Nu s-au putut deschide fișierele de snapshot pentru %s și %s\n", old_snapshot_path, new_snapshot_path);
        return;
    }

    // Procesează fișierele de snapshot
    char old_line[512], new_line[512];

    while (fgets(old_line, sizeof(old_line), old_snapshot_file) != NULL && fgets(new_line, sizeof(new_line), new_snapshot_file) != NULL) {
        // Verifică dacă sunt diferențe între snapshot-uri
        if (strcmp(old_line, new_line) != 0) {
            // Actualizează snapshot-ul vechi cu cel nou
            fseek(old_snapshot_file, 0, SEEK_SET); // Repozitionează cursorul la începutul fișierului
            FILE *temp_file = tmpfile(); // Creează un fișier temporar

            // Copiază conținutul neschimbat din snapshot-ul nou în fișierul temporar
            while (fgets(new_line, sizeof(new_line), new_snapshot_file) != NULL) {
                fputs(new_line, temp_file);
            }

            // Înlocuiește conținutul fișierului vechi cu cel temporar
            FILE *old_snapshot_temp = fopen(old_snapshot_path, "w");
            fseek(temp_file, 0, SEEK_SET); // Repozitionează cursorul la începutul fișierului temporar
            while (fgets(new_line, sizeof(new_line), temp_file) != NULL) {
                fputs(new_line, old_snapshot_temp);
            }
            fclose(old_snapshot_temp);

            // Închide fișierul temporar
            fclose(temp_file);
            break; // Ieși din buclă, nu mai este nevoie să continui procesarea
        }
    }

    // Închide fișierele de snapshot
    fclose(old_snapshot_file);
    fclose(new_snapshot_file);
}

// Funcție pentru crearea snapshot-ului în cadrul unui proces copil
void createSnapshotChild(const char *dir_path, const char *snapshot_path) {
    FILE *snapshot_file = fopen(snapshot_path, "w");
    if (snapshot_file == NULL) {
        fprintf(stderr, "Nu s-a putut crea fișierul de snapshot pentru %s\n", dir_path);
        exit(1);
    }

    createSnapshot(dir_path, snapshot_file);

    fclose(snapshot_file);

    printf("Snapshot for Directory %s created successfully.\n", dir_path);
}

char* generateSnapshotFileName(const char *output_directory, const char *directory_name, int index) {
    char *snapshot_file_name = (char *)malloc(512 * sizeof(char));
    if (snapshot_file_name == NULL) {
        fprintf(stderr, "Eroare la alocarea memoriei\n");
        exit(1);
    }

    snprintf(snapshot_file_name, 512, "%s/Snapshot_%s_%d.txt", output_directory, directory_name, index);

    return snapshot_file_name;
}
// Funcție pentru verificarea drepturilor lipsă și izolarea fișierelor periculoase
// Funcție pentru verificarea drepturilor lipsă și izolarea fișierelor periculoase
void checkPermissionsAndIsolate(const char *output_directory, const char *isolated_space_dir, const char *dir_path) {
    DIR *dir = opendir(dir_path);
    if (dir == NULL) {
        fprintf(stderr, "Nu s-a putut deschide directorul %s\n", dir_path);
        return;
    }

    struct dirent *entry;
    int dangerous_files_count = 0; // Contor pentru fișierele periculoase

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char file_path[256];
        //snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, entry->d_name);
        strncpy(file_path, dir_path, sizeof(file_path));
        strncat(file_path, "/", sizeof(file_path) - strlen(file_path) - 1);
        strncat(file_path, entry->d_name, sizeof(file_path) - strlen(file_path) - 1);


        struct stat file_stat;
        if (stat(file_path, &file_stat) == -1) {
            fprintf(stderr, "Eroare la obținerea informațiilor despre fișierul %s\n", file_path);
            continue;
        }

        if ((file_stat.st_mode & S_IRUSR) == 0 && (file_stat.st_mode & S_IWUSR) == 0 && (file_stat.st_mode & S_IXUSR) == 0) {
            pid_t pid = fork();
            if (pid == -1) {
                fprintf(stderr, "Eroare la crearea procesului pentru %s\n", file_path);
                continue;
            } else if (pid == 0) {

                char args[256] = "./verify_for_malicious.sh ";
                strcat(args,file_path);

                FILE* pipe=popen(args,"r");
                if(pipe==NULL){
                    exit(-6);
                }
                char script_output[256];
                fscanf(pipe,"%s",script_output);
                if(strcmp(script_output,"SAFE")!=0){
                    char new_path[256];
                    //snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, entry->d_name);
                    strncpy(new_path, isolated_space_dir, sizeof(new_path));
                    strncat(new_path, "/", sizeof(new_path) - strlen(new_path) - 1);
                    strncat(new_path, entry->d_name, sizeof(new_path) - strlen(new_path) - 1);

                    if (rename(file_path, new_path) != 0) {
                        perror("Nu s-a putut muta ");
                        exit(-9);
                    }
                    exit(1); // Ieși din procesul copil cu codul de ieșire 1 pentru a marca un fișier periculos
                }
                pclose(pipe);
                exit(0);
            }
        }
    }

    closedir(dir);

    // Așteaptă terminarea proceselor copil
    int status;
    pid_t child_pid;
    while ((child_pid = wait(&status)) != -1) {
        if (WIFEXITED(status) && WEXITSTATUS(status) == 1) {
            dangerous_files_count++; // Incrementăm contorul pentru fiecare fișier periculos
        }
    }

    printf("Procesul copil pentru directorul %s a găsit %d fișiere periculoase.\n", dir_path, dangerous_files_count);
}

int main(int argc, char *argv[]) {
    if (argc < 6 || argc > MAX_DIRECTORIES + 5) {
        fprintf(stderr, "Utilizare: %s -o <director_iesire> -s <izolated_space_dir> <dir1> <dir2> ... (maxim %d directoare)\n", argv[0], MAX_DIRECTORIES);
        return 1;
    }

    // Parsarea argumentelor din linia de comandă
    char *output_directory = NULL;
    int directories_count = 0;
    char *directories[MAX_DIRECTORIES];
    char *isolated_space_dir = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 < argc) {
                output_directory = argv[i + 1];
                i++; // Sari peste argumentul pentru directorul de ieșire
            } else {
                fprintf(stderr, "Nu s-a specificat directorul de ieșire\n");
                return 1;
            }
        }
        else if (strcmp(argv[i], "-s") == 0) {
            if (i + 1 < argc) {
                isolated_space_dir = argv[i + 1];
                i++;
            } else {
                fprintf(stderr, "Nu s-a specificat directorul de izolare\n");
                return 1;
            }
        }
        else {
            directories[directories_count++] = argv[i];
        }
    }

    // Verifică dacă s-a specificat directorul de ieșire
    if (output_directory == NULL) {
        fprintf(stderr, "Nu s-a specificat directorul de ieșire\n");
        return 1;
    }

    // Verifică dacă directorul de ieșire există deja
    struct stat st;
    if (stat(output_directory, &st) == 0 && S_ISDIR(st.st_mode)) {
        printf("Directorul de ieșire %s există deja.\n", output_directory);
    } else {
        // Creează directorul de ieșire dacă nu există
        if (mkdir(output_directory, 0777) == -1) {
            fprintf(stderr, "Eroare la crearea directorului de ieșire %s\n", output_directory);
            return 1;
        }
    }

    // Creează snapshot-uri pentru fiecare director specificat
    for (int i = 0; i < directories_count; i++) {
        // Generăm numele fișierului de snapshot pentru directorul curent
        char *snapshot_path = generateSnapshotFileName(output_directory, directories[i], i + 1);

        FILE *snapshot_file = fopen(snapshot_path, "w");
        if (snapshot_file == NULL) {
            fprintf(stderr, "Nu s-a putut crea fișierul de snapshot pentru %s\n", directories[i]);
            continue;
        }

        createSnapshot(directories[i], snapshot_file);
        fclose(snapshot_file);

        // Eliberăm memoria alocată pentru numele fișierului de snapshot
        free(snapshot_path);
    }

    // Compară și actualizează snapshot-urile dacă există snapshot-uri vechi și noi
    for (int i = 0; i < directories_count; i++) {
        char *old_snapshot_path = generateSnapshotFileName(output_directory, directories[i], i + 1);
        char *new_snapshot_path = generateSnapshotFileName(output_directory, directories[i], i + 2);

        compareAndUpdateSnapshots(old_snapshot_path, new_snapshot_path);

        // Eliberăm memoria alocată pentru numele fișierelor de snapshot
        free(old_snapshot_path);
        free(new_snapshot_path);
    }

    printf("Snapshot-urile au fost create și actualizate cu succes în directorul %s\n", output_directory);

    // Creează procesele copil și apelul funcției createSnapshotChild pentru fiecare director
    for (int i = 0; i < directories_count; i++) {
        pid_t pid = fork();

        if (pid == -1) {
            fprintf(stderr, "Eroare la crearea procesului copil pentru %s\n", directories[i]);
            continue;
        } else if (pid == 0) {
            // Suntem în procesul copil
            char *snapshot_path = generateSnapshotFileName(output_directory, directories[i], i + 1);

            createSnapshotChild(directories[i], snapshot_path);
            free(snapshot_path); // Eliberăm memoria alocată pentru numele fișierului de snapshot
            exit(0);
        }
    }

    // Așteaptă terminarea tuturor proceselor copil
    int status;
    pid_t child_pid;
    while ((child_pid = wait(&status)) != -1) {
        printf("Child Process %d terminated with exit code %d.\n", child_pid, WEXITSTATUS(status));
    }

    if (isolated_space_dir == NULL) {
        fprintf(stderr, "Nu s-a specificat directorul de izolare\n");
        return 1;
    }

    for (int i = 0; i < directories_count; i++) {
        checkPermissionsAndIsolate(output_directory, isolated_space_dir, directories[i]);
    }

    return 0;
}