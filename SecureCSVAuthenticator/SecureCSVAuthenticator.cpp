// SecureCSVAuthenticator.cpp : Defines the entry point for the application.

/*
Daniel Wilson
3/5/2024
Secure CSV Authenticator
This program will prompt the user for login information and check it against an encrypted csv 'database'.
*/

#include "SecureCSVAuthenticator.h"

enum userDBStatus {userFoundWithPass = 1,userFoundBadPass = 2,userNotFound = 3,fileError = -1,unexpectedError = -2};

userDBStatus searchAccounts(std::string user, std::string pwd);
bool addNewAccount(const std::string& user, const std::string& pwd);
std::string encryptString(const std::string& iString);
std::string decryptString(std::string iString);
int getKey();

int main() {
    std::string userName;
    std::string password;
    int attempts = 3;
    std::cout << "Log In\n";
    while (attempts != 0) {
        std::cout << "Please Input Username and Password:\n";
        std::cin >> userName;
        std::cin >> password;

        // DEBUG Encryption Test:
        //std::cout << "\n\n ENCRYPTION TEST:\n";
        //std::cout << "Encrypted: " << encryptString(userName,KEY) << " " << encryptString(password, KEY) << "\n";
        //std::cout << "Decrypted: " << decryptString(encryptString(userName,KEY),KEY) << " " << decryptString(encryptString(password, KEY),KEY) << "\n";
        //std::cout << "\n\n";

        std::cout << "Searching User...\n";
        
        if (searchAccounts(userName, password) == userFoundWithPass) {
            // Username and corrosponding Password are found in database
            std::cout << "ACCESS GRANTED!";
            return 0;
        }
        if (searchAccounts(userName, password) == userFoundBadPass) {
            // The Username was found, but with a different Password
            std::cout << "Wrong Password, " << attempts - 1 << " attempts remaining.\n";
            attempts--;
        }
        if (searchAccounts(userName, password) == userNotFound) {
            // The Username does not exist in the database, the User is prompted to create a new account
            char response;
            std::cout << "User Not Found, create an account?\n(Y or N): ";
            std::cin >> response;
            if (response == 'Y' || response == 'y') {
                bool creatingNewAcc = true;
                while (creatingNewAcc) { // Try until a unique username is provided

                    std::string newUsername, newPassword;
                    std::cout << "Enter new username and password: \n";
                    std::cin >> newUsername;
                    std::cin >> newPassword;

                    if (addNewAccount(newUsername, newPassword)) {
                        std::cout << "Account Created! ";
                        creatingNewAcc = false;
                    }
                }
            }
            else {
                break;
            }
            std::cout << "Please Log In.\n";
        }

    }
    return 0;
}


// Function will return:
// 1 if Username and matching Password are found
// 2 if Username found, Password is incorrect
// 3 if Username not found
// -1 if file error
// -2 if unexpected error
userDBStatus searchAccounts(std::string user, std::string pwd) {
    try {
        // Open database file
        std::ifstream in("accounts.csv");
        if (!in) {
            std::cout << "\nError opening file for reading.\n";
            throw fileError;
        }

        // Convert input to lowercase to compare
        std::transform(user.begin(), user.end(), user.begin(), ::tolower);
        std::transform(pwd.begin(), pwd.end(), pwd.begin(), ::tolower);

        std::string cursor;
        while (std::getline(in, cursor)) {
            // decrypt data to compare to username and password

            // DEBUG Search Test:
            //std::cout << "Compairing "<< decryptString(cursor,KEY) << " to "<< user << "\n\n";

            if (decryptString(cursor) == user) {
                // The user exists
                // Check Password
                if (std::getline(in, cursor)) {

                    // DEBUG Search Test:
                    //std::cout << "Compairing "<< decryptString(cursor,KEY) << " to "<< pwd << "\n\n";

                    if (decryptString(cursor) == pwd) {
                        // The password matches
                        return userFoundWithPass; // User found, Correct Password
                    }
                }
                return userFoundBadPass; // User Found, Wrong Password
            }
        }
        in.close();
        return userNotFound; // User was not found
    }
    catch (const std::exception& e) {
        std::cerr << "Exception occurred: " << e.what() << "\n";
        return unexpectedError; // Handle other exceptions (i.e. decryption error)
    }
}

// Function will fail for file error or if username already exists.
bool addNewAccount(const std::string& user, const std::string& pwd) {
    try {
        std::cout << "Creating New Account for " << user << "...\n";
        // Open database file
        std::ofstream out;
        out.open("accounts.csv", std::ios_base::app);
        if (!out) {
            throw std::runtime_error("Error opening file for writing to.");
        }

        // Check if the Username is taken
        if (searchAccounts(user, pwd) == userFoundWithPass || searchAccounts(user, pwd) == userFoundBadPass) {
            throw std::runtime_error("Username Taken! Please Try Again.");
        }

        // Encrypt data before writing to file
        out << encryptString(user) << "\n" << encryptString(pwd) << "\n";
        out.close();
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Exception occurred: " << e.what() << "\n";
        return false;
    }

}

// 'Ceasar Cypher', letters are shifted down in the alphabet
std::string encryptString(const std::string& iString) {
    try {
        std::string result = "";
        for (char c : iString) {
            if (std::isalpha(c)) {
                char shiftedChar = (std::tolower(c) - 'a' + getKey()) % 26 + 'a';
                result += shiftedChar;
            }
            else {
                result += c; // non alphabetic characters are left unchanged
            }
        }
        return result;
    }
    catch (const std::exception& e) {
        std::cerr << "Exception occurred: " << e.what() << "\n";
    }
}

// 'Ceasar Cypher' is reversed, letters are shifted back in the alphabet
std::string decryptString(std::string iString) {
    try {
        std::string result = "";
        for (char c : iString) {
            if (std::isalpha(c)) {
                char shiftedChar = (std::tolower(c) - 'a' - getKey() + 26) % 26 + 'a';
                result += shiftedChar;
            }
            else {
                result += c; // non alphabetic characters left unchanged
            }
        }
        return result;
    }
    catch (const std::exception& e) {
        std::cerr << "Exception occurred: " << e.what() << "\n";
    }
}

int getKey() {
    try {
        std::ifstream in("key.txt");
        if (!in) {
            throw std::runtime_error("Error retrieving key.");
        }
        int key;
        in >> key;
        in.close();
        return key;
    }
    catch (const std::exception& e) {
        std::cerr << "Exception occurred: " << e.what() << "\n";
        return -1;
    }
}
