#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#define CREATE_USER 0x1
#define DELETE_USER 0x2
#define LIST_USERS 0x3
#define EDIT_USER 0x4
#define EXIT 0x5
#define MAX_USERS 66

typedef struct
{
    unsigned long long id;
    unsigned long long age;
    char name[8];
} User;

User *users[MAX_USERS] = {0};

void init(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void menu(void)
{
    puts("1. Create User");
    puts("2. Delete User");
    puts("3. List Users");
    puts("4. Edit User");
    puts("5. Exit");
    printf(">> ");
}

void create_user(void)
{
    for (int i = 0; i < MAX_USERS; i++)
    {
        if (users[i] == NULL)
        {
            users[i] = malloc(sizeof(User));
            if (!users[i])
            {
                puts(":(");
                _exit(-1);
            }
            printf("Enter ID: ");
            scanf("%llu", &users[i]->id);
            printf("Enter Age: ");
            scanf("%llu", &users[i]->age);
            printf("Enter Name: ");
            read(0, users[i]->name, sizeof(users[i]->name));
            printf("User created\n");
            return;
        }
    }
    puts("User limit reached");
}

void delete_user(void)
{
    unsigned int index;
    printf("Enter user index to delete: ");
    scanf("%u", &index);
    if (index >= MAX_USERS || users[index] == NULL)
    {
        puts("Invalid index");
        return;
    }
    free(users[index]);
    puts("User deleted");
}

void list_users(void)
{
    for (int i = 0; i < MAX_USERS; i++)
    {
        if (users[i] != NULL)
        {
            printf("Index: %d, ID: %llu, Age: %llu, Name: %s\n", i, users[i]->id, users[i]->age, users[i]->name);
        }
    }
}

void edit_user(void)
{

    unsigned int index;
    printf("Enter user index to edit: ");
    scanf("%u", &index);
    if (index >= MAX_USERS || users[index] == NULL)
    {
        puts("Invalid index");
        return;
    }
    printf("Enter new ID: ");
    scanf("%llu", &users[index]->id);
    printf("Enter new Age: ");
    scanf("%llu", &users[index]->age);
    printf("Enter new Name: ");
    read(0, users[index]->name, sizeof(users[index]->name));
    printf("User updated\n");
}

int main(void)
{
    init();
    unsigned int choice;
    bool edit_used = false;
    while (true)
    {
        menu();
        scanf("%u", &choice);
        switch (choice)
        {
        case CREATE_USER:
            create_user();
            break;
        case DELETE_USER:
            delete_user();
            break;
        case LIST_USERS:
            list_users();
            break;
        case EDIT_USER:
            if (!edit_used)
            {
                edit_used = true;
                edit_user();
            }
            else
            {
                puts("Edit option can only be used once.");
            }
            break;
        case EXIT:
            _exit(0);
            break;
        default:
            puts("Invalid choice");
        }
    }
    return 0;
}
