#include "JwtFilter.h"
#include "models/ActiveSessions.h" // Include model for DB check
#include <drogon/HttpAppFramework.h>
#include <drogon/HttpRequest.h>      // Included for clarity, often via HttpFilter.h
#include <drogon/HttpResponse.h>    // Included for clarity
#include <drogon/orm/Mapper.h>
#include <drogon/orm/Criteria.h>
#include <drogon/orm/DbClient.h>
#include <drogon/utils/Utilities.h> // For LOG_* macros
#include <jwt-cpp/jwt.h>            // Include jwt-cpp library
#include <json/json.h>            // Include for Json::Value
#include <memory>                 // For std::shared_ptr, std::make_shared
#include <chrono>                 // For time checks
#include <stdexcept>              // For std::runtime_error, std::exception
#include <system_error>           // For potential system errors
#include <string>                 // For std::string, std::stoi

// Use the namespace for your models
using namespace drogon_model::chatbot_db; // Adjust if needed

// --- Helper Function Implementations ---

std::string JwtFilter::getJwtSecret() {
    // Uses the CORRECT METHOD: getCustomConfig()
    try {
        const Json::Value& customConfig = app().getCustomConfig();
        if (customConfig.isMember("jwt") &&
            customConfig["jwt"].isObject() &&
            customConfig["jwt"].isMember("secret_key") &&
            customConfig["jwt"]["secret_key"].isString())
        {
            std::string secret = customConfig["jwt"]["secret_key"].asString();
            if (secret.empty()) {
                LOG_FATAL << "JWT secret_key is empty in custom_config";
                throw std::runtime_error("JWT configuration error: secret_key is empty");
            }
            if (secret.length() < 32) { LOG_WARN << "JWT secret_key is potentially too short!"; }
            return secret;
        }
        else {
            LOG_FATAL << "JWT secret_key missing or invalid in custom_config";
            throw std::runtime_error("JWT configuration error: secret_key missing or invalid");
        }
    }
    catch (const std::exception& e) {
        LOG_FATAL << "Error accessing JWT secret_key from custom_config: " << e.what();
        throw std::runtime_error("JWT configuration error: Failed to access secret_key");
    }
    return ""; // Should not be reached
}

std::chrono::seconds JwtFilter::getJwtExpiryDuration() {
    // Uses the CORRECT METHOD: getCustomConfig()
    long long expirySeconds = 3600; // Default
    try {
        const Json::Value& customConfig = app().getCustomConfig();
        if (customConfig.isMember("jwt") &&
            customConfig["jwt"].isObject() &&
            customConfig["jwt"].isMember("expires_after"))
        {
            const auto& expiryVal = customConfig["jwt"]["expires_after"];
            if (expiryVal.isInt64()) { expirySeconds = expiryVal.asInt64(); }
            else if (expiryVal.isUInt64()) { expirySeconds = static_cast<long long>(expiryVal.asUInt64()); }
            else if (expiryVal.isNumeric()) {
                try { expirySeconds = std::stoll(expiryVal.asString()); }
                catch (const std::exception&) {
                    LOG_WARN << "JWT expires_after in custom_config numeric conversion failed, using default (3600s)";
                    expirySeconds = 3600;
                }
            }
            else {
                LOG_WARN << "Non-numeric expires_after type in custom_config's jwt section, using default (3600s)";
                expirySeconds = 3600;
            }
            if (expirySeconds <= 0) {
                LOG_WARN << "Invalid expires_after value (<=0) in custom_config's jwt section, using default (3600s)";
                expirySeconds = 3600;
            }
        }
        else {
            LOG_WARN << "'jwt' section or 'expires_after' key missing in 'custom_config', using default expiry (3600s)";
        }
    }
    catch (const std::exception& e) {
        LOG_ERROR << "Error reading JWT expires_after from custom_config: " << e.what() << ". Using default (3600s).";
        expirySeconds = 3600;
    }
    return std::chrono::seconds(expirySeconds);
}

std::string JwtFilter::getJwtIssuer() {
    // Assuming hardcoded issuer for now
    return "chatbot_admin_backend";
}


// --- Main Filter Logic Implementation ---

void JwtFilter::doFilter(const HttpRequestPtr& req,
    FilterCallback&& fcb,       // Callback for filter failure
    FilterChainCallback&& fccb) // Callback to continue chain
{
    LOG_TRACE << "JwtFilter checking request for path: " << req->path();

    // 1. Extract Token from Header
    const auto& authHeader = req->getHeader("Authorization");
    std::string token;

    // Helper lambda to send 401 response
    auto send401Error = [&](const std::string& errorMsg) {
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(k401Unauthorized);
        resp->setContentTypeCode(CT_APPLICATION_JSON);
        resp->setBody("{\"error\":\"" + errorMsg + "\"}");
        fcb(resp);
    };

    if (authHeader.empty() || authHeader.rfind("Bearer ", 0) != 0) {
        LOG_DEBUG << "JwtFilter: Missing or invalid Authorization header format.";
        send401Error("Missing or invalid Authorization header");
        return;
    }
    token = authHeader.substr(7); // Skip "Bearer "
    if (token.empty()) {
        LOG_DEBUG << "JwtFilter: Empty token after Bearer prefix.";
        send401Error("Empty token provided");
        return;
    }

    // Wrap main logic in try block
    try {
        // Get JWT settings (will throw if config is bad)
        auto secret = getJwtSecret();
        auto issuer = getJwtIssuer();

        // 2. Verify Token Signature and Standard Claims
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{ secret })
            .with_issuer(issuer);

        auto decoded_token = jwt::decode(token); // Decode (throws on bad format)

        verifier.verify(decoded_token); // Verify signature, expiry, issuer (throws on failure)
        LOG_TRACE << "JWT signature and standard claims verified successfully.";

        // 3. Check against Active Sessions in DB
        size_t lastDot = token.rfind('.');
        if (lastDot == std::string::npos || lastDot + 1 >= token.length()) {
            LOG_WARN << "JwtFilter: Invalid JWT format - no signature part found.";
            throw std::runtime_error("Invalid token format (signature)");
        }
        std::string tokenSignature = token.substr(lastDot + 1);

        auto dbClient = app().getDbClient("pg_client"); // Get default DB client
        if (!dbClient) {
            LOG_ERROR << "JwtFilter: Default database client not available during verification!";
            // Throw an error that indicates server configuration issue
            throw std::runtime_error("Server configuration error (DB)");
        }

        orm::Mapper<ActiveSessions> sessionMapper(dbClient);
        // Use shared_ptr for callbacks to manage lifetime across async calls
        // Move the original callbacks into the shared_ptrs
        auto sharedFcb = std::make_shared<FilterCallback>(std::move(fcb));
        auto sharedFccb = std::make_shared<FilterChainCallback>(std::move(fccb));

        //LOG:
        auto now_for_check = trantor::Date::now(); // Capture time used for check
        LOG_DEBUG << "FILTER: Current time for check (UTC): " << now_for_check.toDbStringLocal(); // Log UTC time string
        LOG_DEBUG << "FILTER: Current time for check (epoch): " << now_for_check.secondsSinceEpoch();
        LOG_DEBUG << "FILTER: Querying for signature [" << tokenSignature << "]"; 

        sessionMapper.findOne(
            // Criteria: Match signature AND ensure DB expiry is in the future
            drogon::orm::Criteria(ActiveSessions::Cols::_token_signature, drogon::orm::CompareOperator::EQ, tokenSignature) &&
            drogon::orm::Criteria(ActiveSessions::Cols::_expires_at, drogon::orm::CompareOperator::GT, trantor::Date::now()),

            // --- Success Lambda (DB Find - Session is Active) ---
            [req, sharedFccb, decoded_token, sharedFcb] // Capture sharedFcb too for error path
        (ActiveSessions /*session*/)
            {
                LOG_TRACE << "JwtFilter: Active session found in DB.";
                try {
                    // 4. Extract User Info and Add to Attributes
                    int userId = std::stoi(decoded_token.get_payload_claim("uid").as_string());
                    std::string username = decoded_token.get_payload_claim("unm").as_string();

                    req->getAttributes()->insert("user_id", userId);
                    req->getAttributes()->insert("username", username);
                    LOG_DEBUG << "JwtFilter: Authentication successful for user '" << username << "' (ID: " << userId << ")";

                    // 5. Proceed to Next Handler/Filter
                    (*sharedFccb)(); // Call chain continuation callback

                }
                catch (const std::exception& claim_err) {
                    LOG_ERROR << "JwtFilter: Error extracting claims from verified token: " << claim_err.what();
                    // If claims are bad, token is effectively invalid - send 401 via sharedFcb
                    auto resp = HttpResponse::newHttpResponse();
                    resp->setStatusCode(k401Unauthorized);
                    resp->setContentTypeCode(CT_APPLICATION_JSON);
                    resp->setBody("{\"error\":\"Invalid token claims\"}");
                    (*sharedFcb)(resp); // Call failure callback via shared_ptr
                }
            },
            // --- Failure Lambda (DB Find - Session Not Found/Expired or DB Error) ---
                [sharedFcb] // Capture failure callback
            (const drogon::orm::DrogonDbException& e)
            {
                std::string errorMsg = e.base().what();
                if (errorMsg.find("no rows") != std::string::npos || errorMsg.find("result is empty") != std::string::npos || errorMsg.find("optimistic lock failed") != std::string::npos) {
                    LOG_WARN << "JwtFilter: Token verified, but corresponding active session not found or expired in DB.";
                }
                else {
                    LOG_ERROR << "JwtFilter: Database error checking active session: " << errorMsg;
                }
                // Send 401 response
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k401Unauthorized);
                resp->setContentTypeCode(CT_APPLICATION_JSON);
                resp->setBody("{\"error\":\"Invalid or expired session\"}");
                (*sharedFcb)(resp); // Call failure callback via shared_ptr
            }
            ); // End sessionMapper.findOne

    }
    // Catch exceptions from JWT verification, DB client check, claim extraction errors rethrown above, etc.
    catch (const std::exception& e) {
        LOG_WARN << "JwtFilter: Authentication failed: " << e.what();
        // Send 401 Unauthorized for most authentication/verification failures
        // If the error was specifically "Server configuration error (DB)", maybe send 500?
        HttpStatusCode statusCode = k401Unauthorized;
        std::string errorMessage = "Authentication failed";
        if (std::string(e.what()).find("Server configuration error") != std::string::npos) {
            statusCode = k500InternalServerError;
            errorMessage = "Server configuration error";
        }
        else if (std::string(e.what()).find("Invalid token claims") != std::string::npos) {
            errorMessage = "Invalid token claims"; // Keep 401
        }
        else if (std::string(e.what()).find("Invalid token format") != std::string::npos) {
            errorMessage = "Invalid token format"; // Keep 401
        }
        // Use the original fcb directly here, as sharedFcb wouldn't have been created/moved yet
        // if the exception happened before findOne was called.
        auto resp = HttpResponse::newHttpResponse();
        resp->setStatusCode(statusCode);
        resp->setContentTypeCode(CT_APPLICATION_JSON);
        resp->setBody("{\"error\":\"" + errorMessage + "\"}");
        fcb(resp); // Call original failure callback
        return;
    }
}