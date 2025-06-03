#include "AskController.h"
#include <drogon/HttpClient.h>
#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>
#include <json/json.h>
#include <drogon/utils/Utilities.h>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <functional>
#include <string>
#include <vector>
#include <unordered_map>
#include <iomanip>
#include <regex>
#include <filesystem>
#include <chrono>

#ifndef TXT_DIR
#define TXT_DIR ""
#endif

#ifndef OPENROUTER_BASE_URL
#define OPENROUTER_BASE_URL "https://openrouter.ai/api/v1"
#endif

#ifndef OPENROUTER_API_KEY
#define OPENROUTER_API_KEY "" 
#endif

#ifndef LLM_MODEL
#define LLM_MODEL "google/gemini-2.5-flash-preview-05-20"
#endif

namespace fs = std::filesystem;

void AskController::asyncHandleHttpRequest(const HttpRequestPtr &req,
                                           std::function<void(const HttpResponsePtr &)> &&callback)
{
    // Check if request is JSON
    {
        auto contentType = req->getHeader("Content-Type");
        if (contentType.find("application/json") == std::string::npos)
        {
            Json::Value error;
            error["error"] = "Request must be in JSON format";
            auto resp = HttpResponse::newHttpJsonResponse(error);
            resp->setStatusCode(k415UnsupportedMediaType);
            callback(resp);
            return;
        }
    }

    // Parse JSON body
    auto jsonPtr = req->getJsonObject();
    if (!jsonPtr || !(*jsonPtr).isMember("question"))
    {
        Json::Value error;
        error["error"] = "Invalid JSON or missing 'question' field";
        auto resp = HttpResponse::newHttpJsonResponse(error);
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    std::string userQuestion = (*jsonPtr)["question"].asString();
    if (userQuestion.empty())
    {
        Json::Value error;
        error["error"] = "'question' field cannot be empty";
        auto resp = HttpResponse::newHttpJsonResponse(error);
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    // Generate request ID
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    std::string requestId = std::to_string(millis);

    LOG_INFO << "[Req " << requestId << "] Processing question: '" 
             << userQuestion.substr(0, 70) << "...'";

    // Step 1: Filter query with LLM
    filterQueryWithLLM(userQuestion, 
        [this, userQuestion, requestId, callback](bool filterSuccess, const FilteredQuery& filtered) {
            
            if (!filterSuccess) {
                LOG_ERROR << "[Req " << requestId << "] LLM filtering failed, using fallback";
                // Use fallback if LLM fails
                FilteredQuery fallback;
                fallback.confirmation = "Error processing AI. Searching: '" + userQuestion.substr(0, 50) + "...'";
                fallback.semantic_query = userQuestion;
                fallback.bm25_keywords = tokenize(userQuestion);
                if (fallback.bm25_keywords.size() > 5) {
                    fallback.bm25_keywords.resize(5);
                }
                
                // Continue with fallback
                processSearchAndResponse(userQuestion, requestId, fallback, callback);
            } else {
                LOG_INFO << "[Req " << requestId << "] LLM filtering successful";
                processSearchAndResponse(userQuestion, requestId, filtered, callback);
            }
        });
}

void AskController::filterQueryWithLLM(const std::string& userQuestion,
                                      std::function<void(bool, const FilteredQuery&)>&& callback)
{
    auto client = HttpClient::newHttpClient("https://openrouter.ai");
    auto req = HttpRequest::newHttpRequest();
    req->setMethod(drogon::Post);
    req->setPath("/api/v1/chat/completions");
    
    // Set headers
    req->addHeader("Authorization", std::string("Bearer ") + OPENROUTER_API_KEY);
    req->addHeader("Content-Type", "application/json");
    req->addHeader("HTTP-Referer", "http://localhost:5002");
    req->addHeader("X-Title", "RAG Chatbot");
    
    // Build request body
    Json::Value requestBody;
    requestBody["model"] = LLM_MODEL;
    requestBody["temperature"] = 0.1;
    requestBody["max_tokens"] = 2000;
    
    Json::Value messages(Json::arrayValue);
    Json::Value message;
    message["role"] = "user";
    message["content"] = getFilterPrompt(userQuestion);
    messages.append(message);
    requestBody["messages"] = messages;
    
    // Use compact JSON format instead of styled
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    std::string jsonString = Json::writeString(builder, requestBody);
    req->setBody(jsonString);
    
    client->sendRequest(req,
        [callback](ReqResult result, const HttpResponsePtr &response) {
            FilteredQuery filtered;
            
            if (result != ReqResult::Ok || !response) {
                LOG_ERROR << "Failed to connect to OpenRouter API";
                callback(false, filtered);
                return;
            }
            
            if (response->getStatusCode() != k200OK) {
                LOG_ERROR << "OpenRouter API error: " << response->getStatusCode();
                LOG_ERROR << "Response body: " << response->getBody();
                callback(false, filtered);
                return;
            }
            
            try {
                // Check if response is JSON by examining content type
                auto contentType = response->getHeader("Content-Type");
                if (contentType.find("application/json") == std::string::npos) {
                    LOG_ERROR << "OpenRouter API returned non-JSON response";
                    LOG_ERROR << "Content-Type: " << contentType;
                    LOG_ERROR << "Response body: " << response->getBody();
                    callback(false, filtered);
                    return;
                }
                
                auto jsonResp = response->getJsonObject();
                if (!jsonResp || !(*jsonResp).isMember("choices") ||
                    (*jsonResp)["choices"].empty()) {
                    LOG_ERROR << "Invalid response format from OpenRouter";
                    LOG_ERROR << "Response body: " << response->getBody();
                    callback(false, filtered);
                    return;
                }
                
                std::string content = (*jsonResp)["choices"][0]["message"]["content"].asString();
                
                // Clean JSON response
                if (content.find("```json") != std::string::npos) {
                    size_t start = content.find("```json") + 7;
                    size_t end = content.rfind("```");
                    if (end != std::string::npos && end > start) {
                        content = content.substr(start, end - start);
                    }
                }
                
                // Parse JSON response
                Json::Reader reader;
                Json::Value parsedJson;
                if (!reader.parse(content, parsedJson)) {
                    LOG_ERROR << "Failed to parse LLM JSON response";
                    callback(false, filtered);
                    return;
                }
                
                // Extract fields
                filtered.confirmation = parsedJson.get("confirmation", "").asString();
                filtered.semantic_query = parsedJson.get("semantic_query", "").asString();
                
                if (parsedJson.isMember("bm25_keywords") && parsedJson["bm25_keywords"].isArray()) {
                    for (const auto& keyword : parsedJson["bm25_keywords"]) {
                        if (keyword.isString()) {
                            filtered.bm25_keywords.push_back(keyword.asString());
                        }
                    }
                }
                
                callback(true, filtered);
                
            } catch (const std::exception& e) {
                LOG_ERROR << "Exception parsing LLM response: " << e.what();
                callback(false, filtered);
            }
        }, 60.0); // 60 second timeout
}

void AskController::generateFinalAnswer(const std::string& userQuestion,
                                       const std::string& context,
                                       std::function<void(bool, const std::string&)>&& callback)
{
    if (context.empty()) {
        callback(true, "Unfortunately, no information was found in the course materials for your query. "
                       "Please try rephrasing your question.");
        return;
    }
    
    auto client = HttpClient::newHttpClient("https://openrouter.ai");
    auto req = HttpRequest::newHttpRequest();
    req->setMethod(drogon::Post);
    req->setPath("/api/v1/chat/completions");
    
    // Set headers
    req->addHeader("Authorization", std::string("Bearer ") + OPENROUTER_API_KEY);
    req->addHeader("Content-Type", "application/json");
    req->addHeader("HTTP-Referer", "http://localhost:5002");
    req->addHeader("X-Title", "RAG Chatbot");
    
    // Build request body
    Json::Value requestBody;
    requestBody["model"] = LLM_MODEL;
    requestBody["temperature"] = 0.7;
    requestBody["max_tokens"] = 1500;
    
    Json::Value messages(Json::arrayValue);
    Json::Value message;
    message["role"] = "user";
    message["content"] = getFinalAnswerPrompt(userQuestion, context);
    messages.append(message);
    requestBody["messages"] = messages;
    
    // Use compact JSON format instead of styled
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    std::string jsonString = Json::writeString(builder, requestBody);
    req->setBody(jsonString);
    
    client->sendRequest(req,
        [callback](ReqResult result, const HttpResponsePtr &response) {
            if (result != ReqResult::Ok || !response) {
                LOG_ERROR << "Failed to connect to OpenRouter API for final answer";
                callback(false, "Network error: Failed to generate answer.");
                return;
            }
            
            if (response->getStatusCode() != k200OK) {
                LOG_ERROR << "OpenRouter API error for final answer: " << response->getStatusCode();
                LOG_ERROR << "Response body: " << response->getBody();
                callback(false, "API error: Failed to generate answer.");
                return;
            }
            
            try {
                // Check if response is JSON by examining content type
                auto contentType = response->getHeader("Content-Type");
                if (contentType.find("application/json") == std::string::npos) {
                    LOG_ERROR << "OpenRouter API returned non-JSON response for final answer";
                    LOG_ERROR << "Content-Type: " << contentType;
                    LOG_ERROR << "Response body: " << response->getBody();
                    callback(false, "API error: Invalid response format.");
                    return;
                }
                
                auto jsonResp = response->getJsonObject();
                if (!jsonResp || !(*jsonResp).isMember("choices") ||
                    (*jsonResp)["choices"].empty()) {
                    LOG_ERROR << "Invalid response format from OpenRouter for final answer";
                    LOG_ERROR << "Response body: " << response->getBody();
                    callback(false, "Invalid response format from AI.");
                    return;
                }
                
                std::string answer = (*jsonResp)["choices"][0]["message"]["content"].asString();
                callback(true, answer);
                
            } catch (const std::exception& e) {
                LOG_ERROR << "Exception getting final answer: " << e.what();
                callback(false, "Error processing AI response.");
            }
        }, 60.0);
}

// Process search and generate response (helper method)
void AskController::processSearchAndResponse(const std::string& userQuestion,
                                           const std::string& requestId,
                                           const FilteredQuery& filtered,
                                           std::function<void(const HttpResponsePtr &)> callback)
{
    // Step 2: Run searches
    LOG_INFO << "[Req " << requestId << "] Running BM25 Search...";
    auto bm25Results = runBM25Search(filtered.bm25_keywords);
    LOG_INFO << "[Req " << requestId << "] BM25 Search done (" 
             << bm25Results.size() << " results).";
    
    LOG_INFO << "[Req " << requestId << "] Running Semantic Search...";
    auto semanticResults = runSemanticSearch(filtered.semantic_query);
    LOG_INFO << "[Req " << requestId << "] Semantic Search done (" 
             << semanticResults.size() << " results).";
    
    // Step 3: Merge results
    LOG_INFO << "[Req " << requestId << "] Merging Results...";
    auto mergedResults = mergeResults(bm25Results, semanticResults);
    LOG_INFO << "[Req " << requestId << "] Merging done (" 
             << mergedResults.size() << " unique chunks).";
    
    // Step 4: Build context from files
    std::string contextStr = buildContextString(mergedResults);
    
    // Step 5: Generate final answer
    LOG_INFO << "[Req " << requestId << "] Generating Final Answer...";
    generateFinalAnswer(userQuestion, contextStr,
        [requestId, filtered, callback](bool success, const std::string& finalAnswer) {
            LOG_INFO << "[Req " << requestId << "] Final Answer generation done.";
            
            // Build response
            Json::Value response;
            response["request_id"] = requestId;
            response["confirmation"] = filtered.confirmation;
            response["status"] = success ? "done" : "error";
            
            Json::Value result;
            result["final_answer"] = finalAnswer;
            
            // Add source chunks info (simplified)
            Json::Value sourceChunks(Json::arrayValue);
            response["result"] = result;
            
            auto resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(success ? k200OK : k500InternalServerError);
            callback(resp);
        });
}

// Dummy search implementations
std::vector<SearchResult> AskController::runBM25Search(const std::vector<std::string>& keywords)
{
    // TODO: Implement actual BM25 search
    // For now, return dummy results
    std::vector<SearchResult> results;
    
    if (!keywords.empty()) {
        SearchResult dummy1;
        dummy1.filepath = (fs::path(TXT_DIR) / "lesson01" / "introduction.txt").string();
        dummy1.text = "This is a dummy text chunk from BM25 search about " + keywords[0];
        dummy1.score = 0.85;
        dummy1.origin = "bm25";
        results.push_back(dummy1);
        
        SearchResult dummy2;
        dummy2.filepath = (fs::path(TXT_DIR) / "lesson02" / "basics.txt").string();
        dummy2.text = "Another dummy result containing keyword: " + keywords[0];
        dummy2.score = 0.72;
        dummy2.origin = "bm25";
        results.push_back(dummy2);
    }
    
    return results;
}

std::vector<SearchResult> AskController::runSemanticSearch(const std::string& query)
{
    // TODO: Implement actual semantic search
    // For now, return dummy results
    std::vector<SearchResult> results;
    
    if (!query.empty()) {
        SearchResult dummy1;
        dummy1.filepath = (fs::path(TXT_DIR) / "lesson01" / "concepts.txt").string();
        dummy1.text = "Semantically similar content to: " + query.substr(0, 50) + "...";
        dummy1.score = 0.92;
        dummy1.origin = "semantic";
        results.push_back(dummy1);
    }
    
    return results;
}

std::vector<SearchResult> AskController::mergeResults(const std::vector<SearchResult>& bm25Results,
                                                     const std::vector<SearchResult>& semanticResults)
{
    std::vector<SearchResult> merged;
    std::unordered_map<std::string, bool> seen;
    
    // Add semantic results first (higher priority)
    for (const auto& result : semanticResults) {
        if (seen.find(result.filepath) == seen.end()) {
            merged.push_back(result);
            seen[result.filepath] = true;
        }
    }
    
    // Add BM25 results
    for (const auto& result : bm25Results) {
        if (seen.find(result.filepath) == seen.end()) {
            merged.push_back(result);
            seen[result.filepath] = true;
        }
    }
    
    return merged;
}

// Utility implementations
std::string AskController::readFile(const std::string& filepath)
{
    try {
        std::ifstream file(filepath);
        if (!file.is_open()) {
            LOG_ERROR << "Failed to open file: " << filepath;
            return "";
        }
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    } catch (const std::exception& e) {
        LOG_ERROR << "Error reading file " << filepath << ": " << e.what();
        return "";
    }
}

std::string AskController::truncateText(const std::string& text, size_t maxWords)
{
    std::istringstream stream(text);
    std::string word;
    std::vector<std::string> words;
    
    while (stream >> word && words.size() < maxWords) {
        words.push_back(word);
    }
    
    std::string result;
    for (const auto& w : words) {
        if (!result.empty()) result += " ";
        result += w;
    }
    
    return result;
}

std::vector<std::string> AskController::tokenize(const std::string& text)
{
    std::vector<std::string> tokens;
    std::regex word_regex(R"(\b\w+\b)");
    std::string lowerText = text;
    std::transform(lowerText.begin(), lowerText.end(), lowerText.begin(), ::tolower);
    
    std::sregex_iterator iter(lowerText.begin(), lowerText.end(), word_regex);
    std::sregex_iterator end;
    
    while (iter != end) {
        tokens.push_back(iter->str());
        ++iter;
    }
    
    return tokens;
}

std::string AskController::cleanText(const std::string& text)
{
    std::string cleaned = text;
    // Remove multiple spaces
    std::regex multi_space("\\s+");
    cleaned = std::regex_replace(cleaned, multi_space, " ");
    
    // Trim
    size_t start = cleaned.find_first_not_of(" \t\n\r");
    size_t end = cleaned.find_last_not_of(" \t\n\r");
    
    if (start != std::string::npos && end != std::string::npos) {
        cleaned = cleaned.substr(start, end - start + 1);
    } else {
        cleaned = "";
    }
    
    return cleaned;
}

std::string AskController::buildContextString(const std::vector<SearchResult>& results)
{
    if (results.empty()) {
        return "";
    }
    
    std::vector<std::string> chunks;
    
    for (const auto& result : results) {
        // Read actual file content
        std::string content = readFile(result.filepath);
        if (content.empty()) {
            // Fall back to the text from search result
            content = result.text;
        }
        
        std::string filename = fs::path(result.filepath).filename().string();
        std::stringstream chunkStr;
        chunkStr << "**[" << filename << "] (Score: " << std::fixed 
                 << std::setprecision(4) << result.score 
                 << " Origin: " << result.origin << "):**\n";
        chunkStr << truncateText(content, 750);
        
        chunks.push_back(chunkStr.str());
    }
    
    // Join chunks with separator
    std::string context;
    for (size_t i = 0; i < chunks.size(); ++i) {
        if (i > 0) {
            context += "\n\n---\n\n";
        }
        context += chunks[i];
    }
    
    return context;
}

// Prompt templates
std::string AskController::getFilterPrompt(const std::string& userQuestion)
{
    // Ensure userQuestion is properly escaped if it could contain JSON special characters,
    // though JsonCpp usually handles this when creating the Json::Value.
    // Here, it's being directly concatenated into a string, which is fine for prompts.
    std::string prompt = R"(You are an AI tasked with processing a user's question and returning a structured JSON output.
The user's question is in Russian.

YOUR ONLY RESPONSE MUST BE A SINGLE VALID JSON OBJECT.
Do NOT include any explanatory text, markdown, or anything else outside of the JSON object.
The JSON object must have the following exact structure and keys:
{
    "confirmation": "A brief confirmation message in RUSSIAN. This message acknowledges the user's query and states what you will search for. Example: '?????, ??? ?????????? ? ??????? ???????.'",
    "semantic_query": "An optimized query in RUSSIAN suitable for semantic vector search. This should capture the core intent of the user's original question. Example: '??????? ???????'",
    "bm25_keywords": ["An", "array", "of", "3", "to", "5", "relevant", "keywords", "in", "RUSSIAN", "extracted", "from", "the", "user's", "question.", "Example:", "?????", "???????", "???????"]
}

User's question in Russian: )" + userQuestion + R"(

REMEMBER: Output ONLY the JSON object.
)";
    return prompt;
}

std::string AskController::getFinalAnswerPrompt(const std::string& userQuestion, 
                                                const std::string& context)
{
    std::string prompt = R"(You are an AI assistant helping students with course materials.

Based on the following context from course materials, answer the user's question.
Be helpful, accurate, and cite the specific sources when possible.

Context from course materials:
)" + context + R"(

User question: )" + userQuestion + R"(

Please provide a comprehensive answer based on the context above.)";
    
    return prompt;
}