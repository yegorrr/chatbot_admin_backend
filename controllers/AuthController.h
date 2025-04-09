#pragma once
//#include <drogon/orm/Criteria.h>
#include <drogon/HttpController.h>

#include <drogon/orm/Mapper.h>
// Correctly include the generated model headers
#include "models/Users.h"         // Assumes Users.h is directly in models/
#include "models/ActiveSessions.h" // Assumes ActiveSessions.h is directly in models/
#include <string>
#include <chrono> // For std::chrono::seconds

using namespace drogon;
// Use the namespace confirmed from your generated files
using namespace drogon_model::chatbot_db;

class AuthController : public drogon::HttpController<AuthController> {
public:
    METHOD_LIST_BEGIN
        // Define the /login route (POST method)
       
        METHOD_ADD(AuthController::login, "/login", Post);
    // If you add signup later:
    // METHOD_ADD(AuthController::signup, "/signup", Post);
    METHOD_LIST_END

        // --- Endpoint method declarations ---
        void login(const HttpRequestPtr& req,
            std::function<void(const HttpResponsePtr&)>&& callback);

    // void signup(const HttpRequestPtr& req,
    //            std::function<void(const HttpResponsePtr&)>&& callback);

private:
    // --- Helper method declarations ---
    bool verifyPassword(const std::string& plainPassword, const std::string& storedHash);
    std::string generateJwt(int userId, const std::string& username);
    std::string getJwtSecret();
    std::chrono::seconds getJwtExpiryDuration();
};