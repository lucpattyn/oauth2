#include <iostream>
#include "oauth2.hpp"
#include "httplib.h"

int main(){
	
	// Generating a random key of length 32 using the mt19937 random number engine 
	//and the uniform_int_distribution distribution. 
	//The key is generated from a character set of 62 characters (26 lowercase, 26 uppercase, and 10 digits).
	auto key = OAuth2::generate_key_HS256(32);
	OAuth2::private_key = key;
	OAuth2::public_key = key;
	
	auto client_verifier = [](std::string client_id, std::string redirect_url) {
		if(client_id != "quarks_app"){
			return false;
		}
		if(redirect_url != "callback"){
			return false;
		}
		
		return true;
	};	
	OAuth2::client_verifier = client_verifier;
	
	auto client_authenticator = [](std::string client_id, std::string client_secret) {
		if(client_id != "quarks_app"){
			return false;
		}
		if(client_secret != "quarks_secret"){
			return false;
		}
		
		return true;
	};
	OAuth2::client_authenticator = client_authenticator;
	
	
	auto user_authenticator = [](std::string username, std::string password) {
		if(username != "admin"){
			return false;
		}
		if(password != "letmein"){
			return false;
		}
	    // Add implementation to authenticate user credentials
	    return true;
	};
	OAuth2::user_authenticator = user_authenticator;
	
	// https://github.com/yhirose/cpp-httplib
	// HTTP
	httplib::Server svr;
	
	// HTTPS
	//httplib::SSLServer svr;
	
	svr.Get("/ping", [](const httplib::Request &, httplib::Response &res) {
	  res.set_content("ping received ..", "text/plain");
	});
	
	svr.Get("/", [](const httplib::Request &, httplib::Response &res) {
	  	res.set_redirect("index.html", 308);
	});	
	
	svr.Get("/auth", [](const httplib::Request& req, httplib::Response& res) {
	    /*if (req.has_header("Content-Length")) {
	      auto val = req.get_header_value("Content-Length");
	    }*/
    	std::map<std::string, std::string> request;
		if (req.has_param("client_id")) {
			request["client_id"] = req.get_param_value("client_id");
    	}
    	if (req.has_param("redirect_url")) {
			request["redirect_url"] = req.get_param_value("redirect_url");;
    	}
    	
    	std::string client_id = request.at("client_id");
    	std::string redirect_url = request.at("redirect_url");
	
		json result = OAuth2::auth(client_id, redirect_url);
		if(result.contains("error")){
			res.set_content(result.dump(), "application/json");
		} else{
			res.set_redirect(result["url"], result["status"]);	
		}
		
  	});
	
  	svr.Post("/signin", [](const httplib::Request& req, httplib::Response& res) {
  		std::map<std::string, std::string> request;
		if (req.has_param("username")) {
			request["username"] = req.get_param_value("username");
    	}
    	if (req.has_param("password")) {
			request["password"] = req.get_param_value("password");;
		}
		if (req.has_param("client_id")) {
			request["client_id"] = req.get_param_value("client_id");
    	}
    	if (req.has_param("redirect_url")) {
			request["redirect_url"] = req.get_param_value("redirect_url");;
    	}
    	
    	json result = OAuth2::signin(request["username"], request["password"], 
									request["client_id"], request["redirect_url"]);
    	if(result.contains("error")){
			res.set_content(result.dump(), "application/json");
		} else{
			res.set_redirect(result["url"], result["status"]);
		}
		
  	});
  	
  	svr.Get("/callback", [](const httplib::Request& req, httplib::Response& res) {
  		if (req.has_param("code")){
  				std::string url = std::string("callback.html?code=") + req.get_param_value("code");
				res.set_redirect(url, 308);
		}
  	});
  	
  	svr.Post("/token",
  		[&](const httplib::Request &req, httplib::Response &res, const httplib::ContentReader &content_reader) {
      		std::string body;
      		content_reader([&](const char *data, size_t data_length) {
      			json result = OAuth2::exchange_for_token(data);    	
    			res.set_content(result.dump(), "application/json");	
        		
				return true;
      		});
  	});
  	
  	svr.Get("/verifytoken", [](const httplib::Request& req, httplib::Response& res) {
  		if (req.has_param("accesstoken")){
  			if(OAuth2::verify_access_token(req.get_param_value("accesstoken"))){
  				res.set_content("ok", "text/plain");
			}else{
				res.set_content("error", "text/plain");
			}
		}
  	});
	//bool ret = svr.set_mount_point("/public", "./www");
	svr.set_base_dir("./public");
	
	int port = 8081;
	std::cout << "oAuth2 server running .. at port " << port << std::endl;	
	svr.listen("0.0.0.0", port);
	
	return 0;
}

// build with :    g++ -I ./include  main.cpp -lssl -lcrypto -pthread -o oauth2
