#include <algorithm>
#include <cstddef>
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>

struct Bini {
    Bini *next = nullptr;
    char *curr = nullptr;
    Bini() {}
    Bini(char *my) {
        curr = my;
    }
};

class MyKisah {

private:
    Bini *free = nullptr;
    Bini *used = nullptr;
    char *kisah;

public:
    MyKisah() {
        kisah = (char*)mmap(nullptr, 0x120, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        for (int i = 0; i < 0x120; i += 0x20) {
            Bini *tmp = free;
            free = new Bini(kisah + i);
            free->next = tmp;
        }
    }

    int add(char *bini) {
        if (!free) return -1;
        Bini *tmp = used;
        used = free;
        free = free->next;
        used->next = tmp;
        strncpy(used->curr, bini, 0x20);
        return 0;
    }

    int del(unsigned int id) {
        if (!used) return -1;
        if (!id) {
            Bini *tmp = free;
            free = used;
            used = used->next;
            free->next = tmp;
            return 0;
        }
        Bini *cur = used;
        for (int i = 0; i < (int)id - 1; ++i) {
            if (!cur) return -1;
            cur = cur->next;
        }
        if (!cur || !cur->next) return -1;
        Bini *tmp = free;
        free = cur->next;
        cur->next = cur->next->next;
        free->next = tmp;
        return 0;
    }

    void view(int id) {
        Bini *cur = used;
        for (int i = 0; i < id; ++i) {
            if (!cur) {
                std::cout << "no bini\n";
                return;
            }
            cur = cur->next;
        }
        if (!cur) {
            std::cout << "no bini\n";
            return;
        }
        std::cout << cur->curr << '\n';
    }    
    
};

class Karbit {
    protected:
        size_t karbit_level;
    public:
        char karbit[20];
        Karbit() {
            std::cout << "nama: ";
            std::cin.ignore();
            std::cin.getline(karbit, 0x20);
            std::cout << "level karbit (0-100): ";
            std::cin >> karbit_level;
        }
        void info(){
            std::cout << karbit << " adalah "<< std::min(karbit_level, (size_t)100) << "%" << " karbit\n";
        }
        virtual void mybini() = 0;
};

class User: public Karbit {

    private:
        MyKisah my;
    public:
        User(){}
        void mybini() {
            std::cout << "0. edit karbit\n1. add bini\n2. view bini\n3. delete bini\n4. logout\n";
        }

        void edit_karbit(){
            std::cout << "karbit old: " << karbit << '\n';
            std::cout << "karbit new: ";
            std::cin.ignore();
            std::cin.getline(karbit, 0x20);
        }

        void add_bini(){
            char bini[0x20];
            std::cout << "nama bini: ";
            std::cin.ignore();
            std::cin.getline(bini, 0x20);
            if (my.add(bini) == -1) {
                std::cout << "gagal menambah bini\n";
                return;
            }
        }
        
        void view_bini(){
            unsigned int idx;
            std::cout << "index bini: ";
            std::cin >> idx;
            my.view(idx);
        }

        void delete_bini(){
            unsigned int idx;
            std::cout << "index bini: ";
            std::cin >> idx;
            if (my.del(idx) == -1) {
                std::cout << "gagal menghapus bini\n";
                return;
            }
        }
};

std::vector<User> users;
int selected_user = -1;

int main(){
    int c;

    for (;;){
        if (selected_user == -1) {
            std::cout << "1. register" << std::endl;
            std::cout << "2. login" << std::endl;
            std::cout << "3. list karbit" << std::endl;
            std::cout << "4. exit" << std::endl;
            std::cout << "> ";
            std::cin >> c;

            switch (c) {
                case 1:
                    users.push_back(User{});
                    break;
                case 2:
                    {
                        std::string name;
                        std::cout << "nama: ";
                        std::cin >> name;
                        for (int i = 0; i < (int)users.size(); i++){
                            if (users[i].karbit == name) {
                                selected_user = i;
                                break;
                            }
                        }

                        if (selected_user == -1) {
                            std::cout << "karbit tidak ditemukan" << std::endl;
                        }
                    }
                    break;
                case 3:
                    for (auto& user : users) user.info();
                    break;
                case 4:
                    std::cout << "bye!" << std::endl;
                    exit(0);
                default:
                    std::cout << "invalid option" << std::endl;
            }
        } else {
            users[selected_user].mybini();
            std::cout << "> ";
            std::cin >> c;

            switch (c) {
                case 0:
                    users[selected_user].edit_karbit();
                    break;
                case 1:
                    users[selected_user].add_bini();
                    break;
                case 2:
                    users[selected_user].view_bini();
                    break;
                case 3:
                    users[selected_user].delete_bini();
                    break;
                case 4:
                    selected_user = -1;
                    break;
                default:
                    std::cout << "invalid option" << std::endl;
                    break;
            }
        }
    }

    return 0;
}


void init() {
    setbuf(stdin, nullptr);
    setbuf(stdout, nullptr);
    setbuf(stderr, nullptr);
}
