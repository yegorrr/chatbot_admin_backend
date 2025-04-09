#pragma once

#include <drogon/HttpSimpleController.h>

using namespace drogon;

// Also inherit from HttpSimpleController
class AdminController : public drogon::HttpSimpleController<AdminController>
{
public:
    // Register GET /admin and apply the JwtFilter
    PATH_LIST_BEGIN
        // Add filter name ("JwtFilter") as an argument after the method
        PATH_ADD("/admin", Get, "JwtFilter");
    PATH_LIST_END

        // Handler method for GET /admin
        virtual void asyncHandleHttpRequest(const HttpRequestPtr& req,
            std::function<void(const HttpResponsePtr&)>&& callback) override;
};