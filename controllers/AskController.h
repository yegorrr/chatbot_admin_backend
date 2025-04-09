#pragma once

#include <drogon/HttpSimpleController.h> // Use SimpleController for basic echo

using namespace drogon;

// Inherit from HttpSimpleController for simpler handler definition
class AskController : public drogon::HttpSimpleController<AskController>
{
public:
    // Using "absolute path" registration for simple controllers
    // Register GET /ask
    PATH_LIST_BEGIN
        PATH_ADD("/ask", Get); // Use PATH_ADD for specific paths
    PATH_LIST_END

        // Handler method for GET /ask
        virtual void asyncHandleHttpRequest(const HttpRequestPtr& req,
            std::function<void(const HttpResponsePtr&)>&& callback) override;
};