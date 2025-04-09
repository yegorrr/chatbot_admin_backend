#include "AuthController.h"        // Include the header for this controller
#include <drogon/orm/DbClient.h>
#include <drogon/orm/Criteria.h>   // Provides Criteria and CompareOperator
#include <drogon/orm/Mapper.h>     // Provides Mapper
#include <drogon/HttpAppFramework.h>
#include <drogon/utils/Utilities.h>
#include <jwt-cpp/jwt.h>           // JWT library
#include <argon2.h>                // Argon2 library
#include <chrono>                  // For time calculations
#include <future>                  // For async operations (used internally by ORM)
#include <memory>                  // For std::shared_ptr, std::make_shared
#include <vector>                  // For salt generation
#include <stdexcept>               // For exceptions
#include <random>                  // For salt generation
#include <iterator>                // For std::back_inserter

// Use the namespace confirmed from your generated files
using namespace drogon_model::chatbot_db;

// --- Helper Function Implementations ---

std::string AuthController::getJwtSecret() {
    try {
        // Use getCustomConfig() to access the "custom_config" object from config.json
        const Json::Value& customConfig = app().getCustomConfig();

        // Check if "jwt" and "secret_key" exist inside "custom_config"
        if (customConfig.isMember("jwt") &&
            customConfig["jwt"].isObject() && // Ensure "jwt" is an object
            customConfig["jwt"].isMember("secret_key") &&
            customConfig["jwt"]["secret_key"].isString())
        {
            std::string secret = customConfig["jwt"]["secret_key"].asString();

            // Validate that the secret is not empty
            if (secret.empty()) {
                LOG_FATAL << "JWT secret_key is empty in custom_config section of config.json";
                throw std::runtime_error("JWT configuration error: secret_key is empty");
            }

            // Optional: Add a minimum length warning for security
            if (secret.length() < 32) { // Example: warn if less than 32 chars
                LOG_WARN << "JWT secret_key in custom_config is potentially too short for strong security!";
            }

            return secret; // Return the valid secret
        }
        else {
            // Log clearly if the structure is wrong or keys are missing
            LOG_FATAL << "JWT 'secret_key' missing, not a string, or 'jwt' section missing/not object in 'custom_config' of config.json";
            throw std::runtime_error("JWT configuration error: secret_key missing or invalid");
        }
    }
    catch (const Json::Exception& json_e) { // Catch JsonCpp specific exceptions
        LOG_FATAL << "JSON Error accessing JWT secret_key from custom_config in config.json: " << json_e.what();
        throw std::runtime_error("JWT configuration error: JSON access failed for secret_key");
    }
    catch (const std::exception& e) { // Catch other potential standard exceptions
        // Log the original error message for debugging
        LOG_FATAL << "Error accessing JWT secret_key from custom_config in config.json: " << e.what();
        // Re-throw or throw a specific error
        throw std::runtime_error("JWT configuration error: Failed to access secret_key");
    }
    // Should not be reached due to throws, but prevents compiler warnings
    return "";
}

std::chrono::seconds AuthController::getJwtExpiryDuration() {
    long long expirySeconds = 3600; // Default to 1 hour (3600 seconds)
    try {
        // Use getCustomConfig() to access the "custom_config" object
        const Json::Value& customConfig = app().getCustomConfig();

        // Check if "jwt" and "expires_after" exist inside "custom_config"
        if (customConfig.isMember("jwt") &&
            customConfig["jwt"].isObject() && // Ensure "jwt" is an object
            customConfig["jwt"].isMember("expires_after"))
        {
            const auto& expiryVal = customConfig["jwt"]["expires_after"];

            // Check numeric types supported by JsonCpp for integers
            if (expiryVal.isInt64()) {
                expirySeconds = expiryVal.asInt64();
            }
            else if (expiryVal.isUInt64()) {
                // Be mindful of potential overflow if uint64 is massive, though unlikely for expiry
                expirySeconds = static_cast<long long>(expiryVal.asUInt64());
            }
            else if (expiryVal.isNumeric()) { // Catch other numeric types if possible
                try {
                    // Attempt conversion from string representation if it's numeric but not int/uint64
                    expirySeconds = std::stoll(expiryVal.asString());
                }
                catch (const std::exception& conversion_err) {
                    LOG_WARN << "JWT expires_after in custom_config was numeric but failed conversion ("
                        << conversion_err.what() << "), using default (3600s)";
                    expirySeconds = 3600; // Fallback on conversion error
                }
            }
            else {
                LOG_WARN << "Non-numeric expires_after value type in custom_config's jwt section, using default (3600s)";
                expirySeconds = 3600; // Use default if type is wrong (e.g., string, bool)
            }

            // Validate the range after potential parsing/conversion
            if (expirySeconds <= 0) {
                LOG_WARN << "Invalid expires_after value (<=0) in custom_config's jwt section, using default (3600s)";
                expirySeconds = 3600;
            }
        }
        else {
            // Log if jwt or expires_after is missing from custom_config
            LOG_WARN << "'jwt' section or 'expires_after' key missing in 'custom_config', using default expiry (3600s)";
            // expirySeconds remains the default 3600
        }
    }
    catch (const Json::Exception& json_e) { // Catch JsonCpp errors
        LOG_ERROR << "JSON Error reading JWT expires_after from custom_config: " << json_e.what() << ". Using default (3600s).";
        expirySeconds = 3600; // Reset to default on error
    }
    catch (const std::exception& e) { // Catch other errors
        LOG_ERROR << "Error reading JWT expires_after from custom_config: " << e.what() << ". Using default (3600s).";
        expirySeconds = 3600; // Reset to default on error
    }

    // Return the determined duration
    return std::chrono::seconds(expirySeconds);
}
// Verify password using Argon2 library function
bool AuthController::verifyPassword(const std::string& plainPassword, const std::string& storedHash) {
    if (storedHash.empty() || plainPassword.empty()) {
        return false; // Cannot verify empty strings
    }
    int result = argon2id_verify(
        storedHash.c_str(),
        plainPassword.c_str(),
        plainPassword.length()
    );
    LOG_TRACE << "Argon2 verification result: " << result << " (ARGON2_OK=" << ARGON2_OK << ")";
    return (result == ARGON2_OK); // ARGON2_OK (usually 0) means verification succeeded
}

// Generate JWT using jwt-cpp library
std::string AuthController::generateJwt(int userId, const std::string& username) {
    try {
        auto secret = getJwtSecret();
        auto expiryDuration = getJwtExpiryDuration();
        auto expiryTime = std::chrono::system_clock::now() + expiryDuration;

        // Create token
        auto token = jwt::create()
            .set_issuer("chatbot_admin_backend") // Set your issuer name
            .set_type("JWS")
            .set_issued_at(std::chrono::system_clock::now())
            .set_expires_at(expiryTime)
            .set_payload_claim("uid", jwt::claim(std::to_string(userId))) // User ID
            .set_payload_claim("unm", jwt::claim(username))             // Username
            .sign(jwt::algorithm::hs256{ secret }); // Sign with HS256

        return token;
    }
    catch (const std::exception& e) {
        LOG_ERROR << "Failed to generate JWT: " << e.what();
        throw; // Re-throw to be caught by the login handler
    }
}

// --- Login Endpoint Implementation ---

void AuthController::login(const HttpRequestPtr& req,
    std::function<void(const HttpResponsePtr&)>&& callback)
{
    // Wrap callback in shared_ptr for safe capture in nested lambdas
    auto sharedCallback = std::make_shared<std::function<void(const HttpResponsePtr&)>>(std::move(callback));

    // 1. Parse and Validate Request Body
    auto jsonPtr = req->getJsonObject();
    if (!jsonPtr || !(*jsonPtr).isMember("username") || !(*jsonPtr).isMember("password") ||
        !(*jsonPtr)["username"].isString() || !(*jsonPtr)["password"].isString() ||
        (*jsonPtr)["username"].asString().empty() || (*jsonPtr)["password"].asString().empty())
    {
        LOG_WARN << "Login request failed validation: Missing or invalid fields.";
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k400BadRequest);
        resp->setContentTypeCode(CT_APPLICATION_JSON);
        resp->setBody("{\"error\":\"Missing or invalid username or password\"}");
        (*sharedCallback)(resp); // Call via shared_ptr
        return;
    }

    std::string username = (*jsonPtr)["username"].asString();
    std::string password = (*jsonPtr)["password"].asString();
    LOG_DEBUG << "Login attempt for user: " << username;

    // 2. Find User in Database (Asynchronously)
    auto dbClient = app().getDbClient("pg_client"); // Use default client
    if (!dbClient) {
        LOG_ERROR << "Default database client could not be retrieved! Check config and logs.";
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k500InternalServerError);
        resp->setContentTypeCode(CT_APPLICATION_JSON);
        resp->setBody("{\"error\":\"Database client initialization failed\"}");
        (*sharedCallback)(resp); // Call via shared_ptr
        return;
    }
    LOG_TRACE << "Successfully retrieved default DB client for login.";
    orm::Mapper<Users> userMapper(dbClient); // Use the generated Users model

    // Find one user matching the username criteria
    userMapper.findOne(
        drogon::orm::Criteria(Users::Cols::_username, drogon::orm::CompareOperator::EQ, username), // Use correct operator name

        // --- Success Lambda (User Found) ---
        // Capture shared_ptr by value (copies the shared_ptr, increasing ref count)
        [this, password, dbClient, sharedCallback]
    (Users user) // Receive the Users object
        {
            LOG_DEBUG << "User found: " << user.getValueOfUsername();

            // 3. Verify Password
            if (!verifyPassword(password, user.getValueOfPasswordHash())) {
                LOG_WARN << "Invalid password for user: " << user.getValueOfUsername();
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k401Unauthorized);
                resp->setContentTypeCode(CT_APPLICATION_JSON);
                resp->setBody("{\"error\":\"Invalid username or password\"}");
                (*sharedCallback)(resp); // Call via shared_ptr
                return;
            }

            // --- Password Verified ---
            LOG_INFO << "Password verified for user: " << user.getValueOfUsername();
            int userId = user.getValueOfId();
            std::string currentUsername = user.getValueOfUsername();

            // 4. Generate JWT
            std::string token;
            try {
                token = generateJwt(userId, currentUsername);
                LOG_TRACE << "Generated JWT for user " << currentUsername;
            }
            catch (const std::exception& e) {
                // Error already logged in generateJwt
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k500InternalServerError);
                resp->setContentTypeCode(CT_APPLICATION_JSON);
                resp->setBody("{\"error\":\"Token generation failed\"}");
                (*sharedCallback)(resp); // Call via shared_ptr
                return;
            }

            // 5. Store Session Info in DB (Asynchronously)
            orm::Mapper<ActiveSessions> sessionMapper(dbClient);
            auto newSession = std::make_shared<ActiveSessions>();
            newSession->setUserId(userId);

            // ... (Token signature extraction remains the same) ...
            size_t lastDot = token.rfind('.');
            // ... (check lastDot) ...
            std::string tokenSignature = token.substr(lastDot + 1);
            // *** Log signature BEFORE setting it ***
            LOG_DEBUG << "LOGIN: Storing signature [" << tokenSignature << "] for user " << currentUsername;
            newSession->setTokenSignature(tokenSignature); // Set signature

            // *** Calculate expiry time using std::chrono ***
            auto expiryDuration = getJwtExpiryDuration();
            auto expiryTimePoint = std::chrono::system_clock::now() + expiryDuration;

            // *** Convert time_point to MICROSECONDS since epoch ***
            auto expiryMicroseconds = std::chrono::duration_cast<std::chrono::microseconds>(
                expiryTimePoint.time_since_epoch())
                .count();

            // *** Construct trantor::Date using MICROSECONDS ***
            trantor::Date expiryTrantorDate(expiryMicroseconds); // Pass microseconds

            newSession->setExpiresAt(expiryTrantorDate);

            // *** Logging (keep as is for verification) ***
            LOG_DEBUG << "LOGIN: Storing expires_at (Local from Trantor): " << expiryTrantorDate.toDbStringLocal();
            LOG_DEBUG << "LOGIN: Storing expires_at (epoch seconds): " << expiryTrantorDate.secondsSinceEpoch();
            LOG_DEBUG << "LOGIN: Storing signature [" << tokenSignature << "] for user " << currentUsername; // Log signature after expiry logging

            // Insert the new session record
            sessionMapper.insert(
                *newSession, // Insert the session object

                // --- Success Lambda (Session Inserted) ---
                // Capture shared_ptr by value again
                [token, sharedCallback, currentUsername]
            (const ActiveSessions& /*insertedSession*/)
                {
                    LOG_INFO << "Active session stored successfully for user " << currentUsername;
                    // 6. Respond to Client with the JWT
                    Json::Value responseJson;
                    responseJson["token"] = token;
                    auto resp = HttpResponse::newHttpJsonResponse(responseJson);
                    (*sharedCallback)(resp); // Call via shared_ptr - Final success response
                },
                // --- Failure Lambda (Session Insert Failed) ---
                // Capture shared_ptr by value again
                    [sharedCallback, currentUsername]
                (const drogon::orm::DrogonDbException& e)
                {
                    LOG_ERROR << "Failed to insert active session for user " << currentUsername << ": " << e.base().what();
                    auto resp = HttpResponse::newHttpResponse();
                    resp->setStatusCode(k500InternalServerError);
                    resp->setContentTypeCode(CT_APPLICATION_JSON);
                    resp->setBody("{\"error\":\"Failed to create session\"}");
                    (*sharedCallback)(resp); // Call via shared_ptr
                }
                ); // End sessionMapper.insert
        }, // End userMapper.findOne success lambda

        // --- Failure Lambda (User Not Found or DB Error) ---
        // Capture shared_ptr by value again
            [sharedCallback, username]
        (const drogon::orm::DrogonDbException& e)
        {
            std::string errorMsg = e.base().what();
            // Check if it's specifically a "not found" error
            if (errorMsg.find("no rows") != std::string::npos ||
                errorMsg.find("result is empty") != std::string::npos ||
                errorMsg.find("optimistic lock failed") != std::string::npos) // findOne error for not found
            {
                LOG_WARN << "Login attempt failed: User not found - " << username;
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k401Unauthorized); // Treat as invalid credentials
                resp->setContentTypeCode(CT_APPLICATION_JSON);
                resp->setBody("{\"error\":\"Invalid username or password\"}");
                (*sharedCallback)(resp); // Call via shared_ptr
            }
            else {
                // Other database error
                LOG_ERROR << "Database error during login for user " << username << ": " << errorMsg;
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k500InternalServerError);
                resp->setContentTypeCode(CT_APPLICATION_JSON);
                resp->setBody("{\"error\":\"Database error during login\"}");
                (*sharedCallback)(resp); // Call via shared_ptr
            }
        } // End userMapper.findOne failure lambda
        ); // End userMapper.findOne call
}

// Implement signup later if needed
// void AuthController::signup(...) { ... }