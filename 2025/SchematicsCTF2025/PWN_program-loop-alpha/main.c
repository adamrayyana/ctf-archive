#include <stdio.h>
#include <stdlib.h>

void banner() {
  printf ("   ____   _____   ____   _________   \n"
          "  /  _ \\ /     \\_/ __ \\ / ___\\__  \\  \n"
          " (  <_> )  Y Y  \\  ___// /_/  > __ \\_\n"
          "  \\____/|__|_|  /\\___  >___  (____  /\n"
          "              \\/     \\/_____/     \\/ \n");
}

void menu() {
  printf ("Program loop Alpha: sequence initiated...\n"
          "1. Allocate\n"
          "2. View\n"
          "3. Edit\n"
          "4. Free\n"
          "<blip> ");
}

void error() {
  printf("<bleep> Critical error.\n");
}

char *memory[8];
int count = 0;

void add() {
  if (count < 8) {
    printf("Allocating memory...\nSize: ");
    char input[8];
    fgets(input, sizeof(input), stdin);
    int size = atoi(input);
    if (size <= 0 || size > 0x500) {
      error();
      return;
    }
    memory[count] = malloc(size);
    count++;
  } else {
    error();
  }
}

void view() {
  if (count > 0) {
    printf("Analyzing memory...\nIndex: ");
    char input[8];
    fgets(input, sizeof(input), stdin);
    int index = atoi(input);
    if (index < 0 || index >= count) {
      error();
      return;
    }
    puts(memory[index]);
  } else {
    error();
  }
}

void edit() {
  if (count > 0) {
    printf("Reconditioning memory...\nIndex: ");
    char input[8];
    fgets(input, sizeof(input), stdin);
    int index = atoi(input);
    if (index < 0 || index >= count) {
      error();
      return;
    }
    printf("Edit: ");
    scanf("%s", memory[index]);
    getchar();
  } else {
    error();
  }
}

void deallocate() {
  if (count > 0) {
    printf("Deallocating memory...\nIndex: ");
    char input[8];
    fgets(input, sizeof(input), stdin);
    int index = atoi(input);
    if (index < 0 || index >= count) {
      error();
      return;
    }
    free(memory[index]);
  } else {
    error();
  }
}

int main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);
  banner();

  char input[8];

  for(;;){
    menu();
    fgets(input, sizeof(input), stdin);

    switch (atoi(input)) {
      case 1:
        add();
        break;
      case 2:
        view();
        break;
      case 3:
        edit();
        break;
      case 4:
        deallocate();
        break;
      default:
        error();
        break;
    }

    printf("\n");
  }
}