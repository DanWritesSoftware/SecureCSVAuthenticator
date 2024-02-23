﻿// SecureCSVAuthenticator.cpp : Defines the entry point for the application.

/*
Daniel Wilson
2/22/2024
Secure CSV Authenticator
This program will prompt the user for login information and check it against an encrypted csv 'database'.
*/

#include "SecureCSVAuthenticator.h"


int searchAccounts(std::string user, std::string pwd, int KEY);
bool addNewAccount(const std::string& user, const std::string& pwd, int KEY);
std::string encryptString(const std::string& iString, int shift);
std::string decryptString(std::string iString, int shift);

int main() {
    std::string userName;
    std::string password;
    int KEY = 4;
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

        if (searchAccounts(userName, password, KEY) == 1) {
            // Username and corrosponding Password are found in database
            std::cout << "ACCESS GRANTED!";
            return 0;
        }
        if (searchAccounts(userName, password, KEY) == 2) {
            // The Username was found, but with a different Password
            std::cout << "Wrong Password, " << attempts - 1 << " attempts remaining.\n";
            attempts--;
        }
        if (searchAccounts(userName, password, KEY) == 3) {
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

                    if (addNewAccount(newUsername, newPassword, KEY)) {
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
int searchAccounts(std::string user, std::string pwd, int KEY) {
    // Open database file
    std::ifstream in("accounts.csv");
    if (!in) {
        std::cout << "\nError opening file for reading.\n";
        return -1;
    }
    else {

        // Convert input to lowercase to compare
        std::transform(user.begin(), user.end(), user.begin(), ::tolower);
        std::transform(pwd.begin(), pwd.end(), pwd.begin(), ::tolower);

        std::string cursor;
        while (std::getline(in, cursor)) {
            // decrypt data to compare to username and password

            // DEBUG Search Test:
            //std::cout << "Compairing "<< decryptString(cursor,KEY) << " to "<< user << "\n\n";

            if (decryptString(cursor, KEY) == user) {
                // The user exists
                // Check Password
                if (std::getline(in, cursor)) {

                    // DEBUG Search Test:
                    //std::cout << "Compairing "<< decryptString(cursor,KEY) << " to "<< pwd << "\n\n";

                    if (decryptString(cursor, KEY) == pwd) {
                        // The password matches
                        return 1; // User found, Correct Password
                    }
                }
                return 2; // User Found, Wrong Password
            }
        }
        return 3; // User was not found

        in.close();
    }
}

// Function will fail for file error or if username already exists.
bool addNewAccount(const std::string& user, const std::string& pwd, int KEY) {
    std::cout << "Creating New Account for " << user << "...\n";
    // Open database file
    std::ofstream out;
    out.open("accounts.csv", std::ios_base::app);
    if (!out) {
        std::cout << "\nError opening file for writing to.\n";
        return false;
    }
    // Check if the Username is taken
    if (searchAccounts(user, pwd, KEY) == 1 || searchAccounts(user, pwd, KEY) == 2) {
        std::cout << "Username Taken! Please Try Again.\n";
        return false;
    }

    // Encrypt data before writing to file
    out << encryptString(user, KEY) << "\n" << encryptString(pwd, 4) << "\n";
    out.close();
    return true;
}

// 'Ceasar Cypher', letters are shifted down in the alphabet
std::string encryptString(const std::string& iString, int shift) {
    std::string result = "";
    for (char c : iString) {
        if (std::isalpha(c)) {
            char shiftedChar = (std::tolower(c) - 'a' + shift) % 26 + 'a';
            result += shiftedChar;
        }
        else {
            result += c; // non alphabetic characters are left unchanged
        }
    }
    return result;
}

// 'Ceasar Cypher' is reversed, letters are shifted back in the alphabet
std::string decryptString(std::string iString, int shift) {
    std::string result = "";
    for (char c : iString) {
        if (std::isalpha(c)) {
            char shiftedChar = (std::tolower(c) - 'a' - shift + 26) % 26 + 'a';
            result += shiftedChar;
        }
        else {
            result += c; // non alphabetic characters left unchanged
        }
    }
    return result;
}


