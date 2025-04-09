#pragma once

#include <drogon/HttpFilter.h>
#include <string>
#include <chrono> // Include chrono for return type

using namespace drogon;

class JwtFilter : public HttpFilter<JwtFilter>
{
public:
    JwtFilter() {}
    void doFilter(const HttpRequestPtr& req,
        FilterCallback&& fcb,
        FilterChainCallback&& fccb) override;

private:
    // *** Ensure these declarations exist ***
    std::string getJwtSecret();
    std::chrono::seconds getJwtExpiryDuration(); // Declaration needed
    std::string getJwtIssuer();
};