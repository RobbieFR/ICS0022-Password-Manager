#include <stdio.h>

char ascii[] = 
    "               _______\n"
    "              |.-----.|\n"
    "              ||x . x||\n"
    "              ||_.-._||\n"
    "              `--)-(--`\n"
    "            __[=== o]___\n"
    "            |:::::::::::|\\\n"
    "            `-=========-`()\n"
    "      ICS0022 Secure password manager\n";

char login[] =
    "You may log in to access your data.\n"
    "1. Log in                 2. Sign up\n"
    "99. EXIT\n";

char menu[] =
    "========== MAIN MENU ==========\n"
    "1. Add an entry                 2. Remove an entry\n"
    "3. Retrieve an entry            4. Modify an entry\n"
    "99. Log out\n";


int main(){
    printf("%s \n",ascii);
    printf("%s \n",login);
    int choice=1;
    scanf("%d", &choice);
    switch (choice){ 
        case 1 : 
            printf("You are logged in ! \n %s", menu);
            break;
        case 2 : 
            printf("You are signed up ! \n %s", menu);
            break;
        case 3 : 
            return 0;
    }
    return 0;
}