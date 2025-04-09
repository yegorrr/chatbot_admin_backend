#include <drogon/drogon.h>
#include <iostream> // For std::cout
#include <string>   // For std::string
#include <vector>   // For std::vector
#include <stdexcept>// For std::runtime_error
#include <random>   // For salt generation
#include <iterator> // For std::back_inserter
#include <argon2.h> // Argon2 header
//#include "controllers/AuthController.h" 


// Helper function (can be placed before main() in main.cc)
std::string generate_argon2_hash(const std::string& password) {
    // --- Parameters ---
    uint32_t t_cost = 2;      // Time cost (iterations) - adjust as needed
    uint32_t m_cost = (1 << 16); // Memory cost (KB) -> 65536 KB = 64 MB - adjust as needed
    uint32_t parallelism = 1; // Parallelism (threads) - adjust as needed

    // --- Salt ---
    const size_t saltlen = 16; // Recommended salt length
    std::vector<uint8_t> salt(saltlen);
    std::random_device rd;
    // *** Generate random unsigned ints in the range 0-255 ***
    std::uniform_int_distribution<unsigned int> dist(0, 255); // Use unsigned int

    for (size_t i = 0; i < saltlen; ++i) {
        // *** Cast the generated int down to uint8_t ***
        salt[i] = static_cast<uint8_t>(dist(rd));
    }

    // --- Hashing ---
    const size_t hashlen = 32; // Desired hash length in bytes

    // --- Output Encoding ---
    const size_t encodedlen = argon2_encodedlen(t_cost, m_cost, parallelism, saltlen, hashlen, Argon2_id);
    std::vector<char> encoded_hash(encodedlen);

    int result = argon2id_hash_encoded(
        t_cost, m_cost, parallelism,
        password.c_str(), password.length(),
        salt.data(), saltlen,
        hashlen,
        encoded_hash.data(), encodedlen
    );

    if (result != ARGON2_OK) {
        throw std::runtime_error(std::string("Argon2 hashing failed: ") + argon2_error_message(result));
    }
    return std::string(encoded_hash.data());
}

int main() {

    LOG_INFO << "Called AuthController::ensureRegistration()";

    //Set HTTP listener address and port
    drogon::app().addListener("127.0.0.1",8080);
    //Load config file
    std::string config_path = "C:\\src\\chatbot_admin\\chatbot_admin_backend\\config.json";
    LOG_INFO << "Attempting to load config file: " << config_path;
    try {
        drogon::app().loadConfigFile(config_path);
        LOG_INFO << "Config file loaded successfully (or did not throw).";
    }
    catch (const std::exception& e) {
        LOG_ERROR << "!!! Failed to load config file: " << config_path << " - Error: " << e.what();

        return 1; // Exit if config fails to load
    }
    catch (...) {
        LOG_ERROR << "!!! Failed to load config file: " << config_path << " - Unknown error";
        return 1;
    }
    // ... rest of main, including the logging check after loadConfigFile ...

    //Run HTTP framework,the method will block in the internal event loop

    // ************************************************
    // ** TEMPORARY ARGON2 HASH & SQL GEN - START **
    // ************************************************
    try {
        std::string password_to_hash = "my_password"; // Or your desired admin password
        std::string username_to_insert = "admin";     // The username for the DB

        std::cout << "--- Argon2 Test & SQL Generation ---" << std::endl;
        std::cout << "Hashing password for user: \"" << username_to_insert << "\"" << std::endl;

        std::string hashed_password = generate_argon2_hash(password_to_hash); // Call helper function

        std::cout << "Generated Argon2id Hash: " << hashed_password << std::endl;
        std::cout << std::endl; // Blank line

        // --- Generate the SQL INSERT statement ---
        std::cout << "---> Copy and run this SQL command in psql <---" << std::endl;
        std::cout << "INSERT INTO users (username, password_hash) VALUES ('"
            << username_to_insert << "', '" << hashed_password << "');" << std::endl;
        std::cout << "------------------------------------------------" << std::endl;
        std::cout << std::endl; // Blank line


    }
    catch (const std::exception& e) {
        std::cerr << "!! Argon2 Test FAILED: " << e.what() << std::endl;
        // return 1; // Optional: Exit if hashing fails
    }
    // ************************************************
    // ** TEMPORARY ARGON2 HASH & SQL GEN - END   **
    // ************************************************

    
    drogon::app().run();
    return 0;
}
