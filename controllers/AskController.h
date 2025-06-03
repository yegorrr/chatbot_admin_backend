#pragma once

#include <drogon/HttpSimpleController.h>
#include <string>
#include <vector>
#include <functional>

using namespace drogon;

// Structure to hold filtered query results from LLM
struct FilteredQuery
{
    std::string confirmation;
    std::string semantic_query;
    std::vector<std::string> bm25_keywords;
};

// Structure to hold individual search results
struct SearchResult
{
    std::string filepath;
    std::string text;
    double score;
    std::string origin;
};

class AskController : public drogon::HttpSimpleController<AskController>
{
public:
    // Register GET /ask
    PATH_LIST_BEGIN
        PATH_ADD("/ask", Post);
    PATH_LIST_END

    // Handler for GET /ask
    void asyncHandleHttpRequest(const HttpRequestPtr& req,
                                std::function<void(const HttpResponsePtr&)>&& callback) override;

private:
    void filterQueryWithLLM(const std::string& userQuestion,
                            std::function<void(bool, const FilteredQuery&)>&& callback);
    void generateFinalAnswer(const std::string& userQuestion,
                             const std::string& context,
                             std::function<void(bool, const std::string&)>&& callback);
    void processSearchAndResponse(const std::string& userQuestion,
                                  const std::string& requestId,
                                  const FilteredQuery& filtered,
                                  std::function<void(const HttpResponsePtr&)> callback);
    std::vector<SearchResult> runBM25Search(const std::vector<std::string>& keywords);
    std::vector<SearchResult> runSemanticSearch(const std::string& query);
    std::vector<SearchResult> mergeResults(const std::vector<SearchResult>& bm25Results,
                                           const std::vector<SearchResult>& semanticResults);
    std::string readFile(const std::string& filepath);
    std::string truncateText(const std::string& text, size_t maxWords);
    std::vector<std::string> tokenize(const std::string& text);
    std::string cleanText(const std::string& text);
    std::string buildContextString(const std::vector<SearchResult>& results);
    std::string getFilterPrompt(const std::string& userQuestion);
    std::string getFinalAnswerPrompt(const std::string& userQuestion, const std::string& context);
};