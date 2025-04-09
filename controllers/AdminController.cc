#include "AdminController.h"
#include <string>                // For std::string, std::to_string
#include <drogon/HttpRequest.h>  // For HttpRequestPtr and Attributes methods
#include <drogon/HttpResponse.h> // For HttpResponse::newHttpResponse
#include <drogon/utils/Utilities.h> // For logging LOG_WARN if needed
#include <any>                   // For std::bad_any_cast

// Handler for GET /admin
void AdminController::asyncHandleHttpRequest(const HttpRequestPtr& req,
    std::function<void(const HttpResponsePtr&)>&& callback)
{
    // This code only runs if JwtFilter successfully validates the token

    // Get the original request query string
    std::string query = req->getQuery();

    // Optionally: Access user info added by JwtFilter
    // Get the attributes store from the request
    auto attributes = req->getAttributes(); // Get the shared_ptr to Attributes

    // Default values
    int userId = -1;
    std::string username = "unknown";

    // --- Correct way to check for and get attributes ---

    // Check for 'user_id'
    if (attributes->find("user_id")) // find() returns true if key exists
    {
        // Key exists, now get the value safely
        // Use get<T>() which might throw std::bad_any_cast if type is wrong
        try {
            userId = attributes->get<int>("user_id");
        }
        catch (const std::bad_any_cast& e) {
            // Log a warning if the attribute exists but isn't an int
            LOG_WARN << "Attribute 'user_id' found but failed to cast to int: " << e.what();
            // Keep default userId = -1
        }
    }
    else
    {
        LOG_TRACE << "Attribute 'user_id' not found in request attributes.";
    }

    // Check for 'username'
    if (attributes->find("username")) // find() returns true if key exists
    {
        try {
            username = attributes->get<std::string>("username");
        }
        catch (const std::bad_any_cast& e) {
            // Log a warning if the attribute exists but isn't a string
            LOG_WARN << "Attribute 'username' found but failed to cast to string: " << e.what();
            // Keep default username = "unknown"
        }
    }
    else
    {
        LOG_TRACE << "Attribute 'username' not found in request attributes.";
    }

    // --- End attribute checking ---


    // Create a response object
    auto resp = HttpResponse::newHttpResponse();
    resp->setStatusCode(k200OK);
    resp->setContentTypeCode(CT_TEXT_PLAIN); // Respond with plain text

    // Build the response body
    std::string responseBody = "Admin access granted!\n";
    responseBody += "Authenticated User ID: " + std::to_string(userId) + "\n";
    responseBody += "Authenticated Username: " + username + "\n";
    if (!query.empty()) {
        responseBody += "You asked (admin): ?" + query;
    }
    else {
        responseBody += "You asked nothing (admin - no query parameters).";
    }
    resp->setBody(responseBody); // Set the complete body

    // Send the response
    callback(resp);
}