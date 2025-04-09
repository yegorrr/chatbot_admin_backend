#include "AskController.h"

// Handler for GET /ask
void AskController::asyncHandleHttpRequest(const HttpRequestPtr& req,
    std::function<void(const HttpResponsePtr&)>&& callback)
{
    // Get the original request query string (everything after '?')
    std::string query = req->getQuery();

    // Create a response object
    auto resp = HttpResponse::newHttpResponse();
    resp->setStatusCode(k200OK);
    resp->setContentTypeCode(CT_TEXT_PLAIN); // Respond with plain text

    // Echo back the query string or a default message
    if (!query.empty()) {
        resp->setBody("You asked: ?" + query);
    }
    else {
        resp->setBody("You asked nothing (no query parameters).");
    }

    // Send the response
    callback(resp);
}