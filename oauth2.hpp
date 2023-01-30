#include <iostream>
#include <string>
#include <map>

#include "nlohmann/json.hpp"
#include "jwt-cpp/jwt.h"

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/rand.h>

// src: https://medium.com/@ratrosy/building-a-basic-authorization-server-using-authorization-code-flow-c06866859fb1
// converted by : ChatGPT (approx. 80% of it)

using json = nlohmann::json;

namespace OAuth2{

	std::map<std::string, json> authorization_codes;
	
	typedef std::function<bool(std::string, std::string)> authenticator;
	//////////////////// interfacing with business logic ///////////////////////
	// override the callbacks/lamdas client_verifier, client_authenticator,
	// user_authenticator to implement custom verification and authentication 
	////////////////////////////////////////////////////////////////////////////
	authenticator client_verifier = [](std::string client_id, std::string redirect_url) {
		return true;
	};

	authenticator client_authenticator = [](std::string client_id, std::string client_secret) {
		return true;
	};

	authenticator user_authenticator = [](std::string username, std::string password) {
    	// Add implementation to authenticate user credentials
    	return true;
	};
	/////////////////////////////done interfacing///////////////////////////////////
	
	bool verify_client_info(std::string client_id, std::string redirect_url) {
	    // Add implementation to verify client information
		return client_verifier(client_id, redirect_url);
	}
	
	bool authenticate_client(std::string client_id, std::string client_secret){
		 // Add implementation to authenticate client
		return client_authenticator(client_id, client_secret);
	}
	
	bool authenticate_user_credentials(std::string username, std::string password) {
	    // Add implementation to authenticate user credentials
	    return user_authenticator(username, password);
	}
	
	std::string process_redirect_url(std::string redirect_url, std::string authorization_code) {
	    // Add implementation to process redirect URL
	    return redirect_url + "?code=" + authorization_code;
	}
	
	/* Note: This code uses the json library for parsing and generating JSON data, it is a built-in C++ library in C++11 and later.
	You may also need to define request, verify_client_info, and render_template for this code to work.*/
	json auth(std::string client_id, std::string redirect_url) {
	    // Describe the access request of the client and ask user for approval
	    
	    if (client_id.empty() || redirect_url.empty()) {
	        json error = {
	            {"error", "invalid_request"}
	        };
	        return error;
	    }
	
	    if (!verify_client_info(client_id, redirect_url)) {
	        json error = {
	            {"error", "invalid_client"}
	        };
	        return error;
	    }
	
	    // return render_template('AC_grant_access.html', client_id = client_id, redirect_url = redirect_url);
	    // in C++, you will have to render the template manually or use a library for that.
	    json success = {
	    	{"status", 303}, {"url", "signin.html"}
	  	};
	  	
		return success;
	}
	
	/////////// //////////////encryption related methods //////////////////////////
	
	std::string Base64UrlEncode(const std::string& value) {
		BIO *bmem, *b64;
		BUF_MEM *bptr;
		
		b64 = BIO_new(BIO_f_base64());
		BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
		bmem = BIO_new(BIO_s_mem());
		b64 = BIO_push(b64, bmem);
		BIO_write(b64, value.c_str(), value.length());
		BIO_flush(b64);
		BIO_get_mem_ptr(b64, &bptr);
		
		std::string result(bptr->data, bptr->length);
		BIO_free_all(b64);
		
		std::string::iterator it = std::remove(result.begin(), result.end(), '=');
		result.erase(it, result.end());
		std::replace(result.begin(), result.end(), '+', '-');
		std::replace(result.begin(), result.end(), '/', '_');
	
	  	return result;
	}
	
	// https://www.codespeedy.com/c-program-to-encrypt-and-decrypt-a-string/
	// https://github.com/philipperemy/easy-encryption
	
	int gen_key(){
		/*char p[33];
	
	    // this string will do as nicely as the character array
	    char a[] = "abcdefghijklmnopqrstuvwxyz";
	
	    // no += here. I assign the random character directly to the target buffer
	    for (int i=0;i<33;i++)
	        p[i] = a[rand()%26];
	
	    // alternately, you can calculate a random English character with:
	    // p[i] = rand()%26 + 'a';
	    // which removes the need for the a[] buffer at all
	
	    // don't forget to null-terminate
	    p[33] = '\0'; */
	    
	    //return p;
	    return rand()&26;
	}
	
	std::string gen_fernet_key(){
		char p[33];
	
	    // this string will do as nicely as the character array
	    char a[] = "abcdefghijklmnopqrstuvwxyz";
	
	    // no += here. I assign the random character directly to the target buffer
	    for (int i=0;i<33;i++)
	        p[i] = a[rand()%26];
	
	    // alternately, you can calculate a random English character with:
	    // p[i] = rand()%26 + 'a';
	    // which removes the need for the a[] buffer at all
	
	    // don't forget to null-terminate
	    p[33] = '\0'; 
	    
	    return p;
	    
	}
	
	void handleErrors(){
		std::cout << "fernet invokation failed" << std::endl;
	}
	
	size_t fernet_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	  unsigned char *iv, unsigned char *ciphertext)
	{
		EVP_CIPHER_CTX *ctx;
		
		int len;
		
		int ciphertext_len;
		
		/* Create and initialise the context */
		if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
		
		/* Initialise the encryption operation. */
		if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
			handleErrors();
		
		/* Provide the message to be encrypted, and obtain the encrypted output.
		* EVP_EncryptUpdate can be called multiple times if necessary
		*/
		if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
			handleErrors();
		ciphertext_len = len;
		
		/* Finalise the encryption. Further ciphertext bytes may be written at
		* this stage.
		*/
		if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
			ciphertext_len += len;
		
		/* Clean up */
		EVP_CIPHER_CTX_free(ctx);
		
		return ciphertext_len;
	}
	
	
	size_t fernet_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	  unsigned char *iv, unsigned char *plaintext)
	{
	  EVP_CIPHER_CTX *ctx;
	
	  int len;
	
	  int plaintext_len;
	
	  /* Create and initialise the context */
	  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
	
	  /* Initialise the decryption operation. */
	  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
	    handleErrors();
	
	  /* Provide the message to be decrypted, and obtain the plaintext output.
	   * EVP_DecryptUpdate can be called multiple times if necessary
	   */
	  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
	    handleErrors();
	  plaintext_len = len;
	
	  /* Finalise the decryption. Further plaintext bytes may be written at
	   * this stage.
	   */
	  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
	  plaintext_len += len;
	
	  /* Clean up */
	  EVP_CIPHER_CTX_free(ctx);
	
	  return plaintext_len;
	}
	
	int fernet_sample_usage(int argc, char const *argv[]) {
		unsigned char* plaintext = (unsigned char*) "hello fernet!";
		/* Set up the key and iv. Do I need to say to not hard code these in a
		* real-world scenario? :-)
		*/
		
		/* A 256 bit key */
		unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
		
		/* A 128 bit IV */
		unsigned char *iv = (unsigned char *)"01234567890123456";
		
		/* Buffer for ciphertext. Ensure the buffer is long enough for the
		* ciphertext which may be longer than the plaintext, dependant on the
		* algorithm and mode
		*/
		unsigned char ciphertext[128];
		
		/* Buffer for the decrypted text */
		unsigned char decryptedtext[128];
		
		int decryptedtext_len, ciphertext_len;
		
		/* Encrypt the plaintext */
		ciphertext_len = fernet_encrypt (plaintext, strlen ((char *)plaintext), key, iv,
		                        ciphertext);
		
		/* Do something useful with the ciphertext here */
		printf("Ciphertext is:\n");
		BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
		
		/* Decrypt the ciphertext */
		decryptedtext_len = fernet_decrypt(ciphertext, ciphertext_len, key, iv,
		decryptedtext);
		
		/* Add a NULL terminator. We are expecting printable text */
		decryptedtext[decryptedtext_len] = '\0';
		
		return 0;
	}
	
	std::string encrypt_text(std::string text, std::string fernet_key){
		unsigned char* plaintext = (unsigned char*)text.c_str();
		
		/* A 256 bit key */
		unsigned char *key = (unsigned char *) fernet_key.c_str();
		
		/* A 128 bit IV */
		unsigned char *iv = (unsigned char *)"01234567890123456";
		
		/* Buffer for ciphertext. Ensure the buffer is long enough for the
		* ciphertext which may be longer than the plaintext, dependant on the
		* algorithm and mode
		*/
		unsigned char ciphertext[128];
		size_t ciphertext_len;
		
		/* Encrypt the plaintext */
		ciphertext_len = fernet_encrypt (plaintext, strlen ((char *)plaintext), key, iv,
		                        ciphertext);
								
		std::string str;
		str.assign((const char*)ciphertext, ciphertext_len);
		
		return str;
	}
	
	/*
	std::string simple_encrypt(std::string text, int key)
	{
		char temp;
	  	int i;
	  
	  	for(i = 0; i < text.size(); ++i){
	    	temp = text[i];
		    //If the message to be encypted is in lower case
		    if(temp >= 'a' && temp <= 'z'){
		      temp = temp + key;
		      
		      if(temp > 'z'){
		        temp = temp - 'z' + 'a' - 1;
		      }
		      
		      text[i] = temp;
		    }
		    //If the message to be encypted is in upper case
		    else if(temp >= 'A' && temp <= 'Z'){
		      temp = temp + key;
		      
		      if(temp > 'Z'){
		        temp = temp - 'Z' + 'A' - 1;
		      }
		      
		      text[i] = temp;
		    }
		}
	  
		return text;
		
	}
	
	std::string simple_decrypt(std::string text, int key)
	{
		char temp;
	  	int i;
	  
	  	for(i = 0; i < text.size(); ++i){
	    	temp = text[i];
	    	//If the message to be decypted is in lower case.
	    	if(temp >= 'a' && temp <= 'z'){
	      		temp = temp - key;
	      
		      	if(temp < 'a'){
		        	temp = temp + 'z' - 'a' + 1;
		      	}
		      
		      	text[i] = temp;
	    	}	
	    	//If the message to be decypted is in upper case.
	    	else if(temp >= 'A' && temp <= 'Z'){
	      		temp = temp - key;
	      
	      		if(temp < 'A'){
	        		temp = temp + 'Z' - 'A' + 1;
	      		}
	      
	      		text[i] = temp;
	    	}
	  }
	  
	  return text;
	   
	}*/
	
	/////////////////end of encryption related methods//////////////////////////////
	
	
	
	/* Note: This code uses the json library for parsing and generating JSON data, it is a built-in C++ library in C++11 and later. 
	You may also need to define Fernet, f, authorization_codes, time, Base64UrlEncode, and CODE_LIFE_SPAN for this code to work.
	*/
	/*To generate your own fernet you'll want to generate 32 cryptographically secure random bytes and then urlsafe base64 encode them. Of course, 
	since generate_key already does this you should probably just call that unless you need to generate the key outside of your Python process.
	base64.urlsafe_b64encode(os.urandom(32))*/
	
	time_t CODE_LIFE_SPAN = 10 * 60; // 10 mins
	std::string generate_authorization_code(std::string client_id, std::string redirect_url) {
	    //f = Fernet(KEY)
	      // ensure the target has enough memory for the key and a null terminator
	    
		//int KEY = gen_key();
		std::string KEY = gen_fernet_key();
	
	    json payload = {
	        {"client_id", client_id},
	        {"redirect_url", redirect_url}
	    };
	    //std::string authorization_code = f.encrypt(payload.dump());
	    //std::string authorization_code = encryptfunc(payload.dump(), KEY); 
		std::string authorization_code = encrypt_text(payload.dump(), KEY);   
	    authorization_code = Base64UrlEncode(authorization_code);
	    int expiration_date = time(0) + CODE_LIFE_SPAN;
	    
	    //std::cout << "auth code: " << authorization_code;
	    authorization_codes[authorization_code] = {
	        {"client_id", client_id},
	        {"redirect_url", redirect_url},
	        {"exp", expiration_date}
	    };
	    
	    return authorization_code;
	}
	
	json signin(std::string username, std::string password, std::string client_id, std::string redirect_url) {
	    if (username.empty() || password.empty() || client_id.empty() || redirect_url.empty()) {
	        return {{"error","invalid_request"}};
	    }
	
	    if (!verify_client_info(client_id, redirect_url)) {
	        return {{"error","invalid_client"}};
	    }
	
	    if (!authenticate_user_credentials(username, password)) {
	        return {{"error","invalid_user"}};
	    }
	
	    std::string authorization_code = generate_authorization_code(client_id, redirect_url);
	    
	    std::string url = process_redirect_url(redirect_url, authorization_code);
	    json success = {
	    	{"status", 303}, {"url", url}
	  	};
	  	
	    return success;
	    
	}
	
	/*Note: This code uses the time library for working with time. it is a built-in C++ library. 
	You may also need to define authorization_codes for this code to work.
	*/
	bool verify_authorization_code(std::string authorization_code, std::string client_id, std::string redirect_url) {
	    //f = Fernet(KEY)
	    std::map<std::string, json>::iterator it = authorization_codes.find(authorization_code);
	    if (it == authorization_codes.end()) {
	        return false;
	    }
	
		json record = it->second;
	    std::string client_id_in_record = record.at("client_id");
	    std::string redirect_url_in_record = record.at("redirect_url");
	    int exp = record.at("exp");
	
		//std::cout << client_id_in_record << " " << " " << redirect_url_in_record << exp << std::endl
	    if (client_id != client_id_in_record || redirect_url != redirect_url_in_record) {
	        return false;
	    }
	
	    if (exp < time(0)) {
	        return false;
	    }
	
	    authorization_codes.erase(authorization_code);
	
	    return true;
	}
	
	
	/*Note: This code uses the jwt-cpp library for working with JSON Web Tokens (JWT), you may need to install it. 
	And you may also need to define private_key and ISSUER for this code to work.
	*/
	std::string ISSUER = "auth0";
	time_t LIFE_SPAN = 365 * 24 *60 * 60;
	static std::string private_key = "s3c43t";
	//
	//https://github.com/Thalhammer/jwt-cpp/blob/master/example/rsa-create.cpp
	std::string generate_access_token() {
	    json payload = {
	        {"iss", ISSUER},
	        {"exp", time(0) + LIFE_SPAN}
	    };
	
		std::string access_token = jwt::create()
	        //.sign(jwt::algorithm::rs256{private_key});
	        .set_issuer("auth0")
	    	.set_type("JWS")
	    	.set_issued_at(std::chrono::system_clock::now())
			.set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{LIFE_SPAN})
	    	.set_payload_claim("sample", jwt::claim(std::string("test")))
			.sign(jwt::algorithm::hs256{private_key});
	    return access_token;
	}
	
	/*Note : This code uses the jwt-cpp library for working with JSON Web Tokens (JWT), you may need to install it. 
	And you may also need to define public_key and ISSUER for this code to work.
	*/
	static std::string public_key = "s3c43t";
	//
	bool verify_access_token(std::string access_token) {
	    try {
	    	//jwt::decode(access_token, jwt::verify().allow_algorithm(jwt::algorithm::rs256{public_key}).issuer(ISSUER));
	        auto decoded_token = jwt::decode(access_token);
			auto verifier = jwt::verify()
	    		.allow_algorithm(jwt::algorithm::hs256{ public_key })
	    		.with_issuer(ISSUER);
	
			verifier.verify(decoded_token);
	        
	        //jwt::decode(access_token, jwt::verify().allow_algorithm(jwt::algorithm::hs256{public_key}).with_issuer(ISSUER));
	    } catch (std::exception& e) {
	        return false;
	    }
	    
	    return true;
	}
	
	
	/*
	Note: This code uses the json library for parsing and generating JSON data, 
	it is a built-in C++ library in C++11 and later. You may also need to define request, 
	authenticate_client, verify_authorization_code and generate_access_token for this code to work.
	*/
	int JWT_LIFE_SPAN = 1800; //1800 seconds
	json exchange_for_token(std::string authorization_code, std::string client_id, 
							std::string client_secret, std::string redirect_url) {
	    // Issues access token
	    
		//std::cout<<authorization_code<<client_id<<client_secret<<redirect_url<<std::endl;
		if (authorization_code.empty() || client_id.empty() || client_secret.empty() || redirect_url.empty()) {
	        json error = {
	            {"error", "invalid_request"}
	        };
	        return error;
	    }
	
	    if (!authenticate_client(client_id, client_secret)) {
	        json error = {
	            {"error", "invalid_client"}
	        };
	        return error;
	    }
	
	    if (!verify_authorization_code(authorization_code, client_id, redirect_url)) {
	    	//std::cout << "could not verify authorization code!" << std::endl;
	        json error = {
	            {"error", "access_denied"}
	        };
	        return error;
	    }
	
	    std::string access_token = generate_access_token();
	
	    json response = {
	        {"access_token", access_token},
	        {"token_type", "JWT"},
	        {"expires_in", JWT_LIFE_SPAN}
	    };
	
	    return response;
	}
	
	json exchange_for_token(std::string data){
		json request = json::parse(data);
		
		return exchange_for_token(request["authorization_code"], request["client_id"], 
									request["client_secret"], request["redirect_url"]);
									
	}
	
	std::string generate_key_HS256(size_t length) {
		static const char charset[] =
      		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

  		std::string key;
  		key.reserve(length);
  		for (int i = 0; i < length; i++) {
    		unsigned char random_char = 0;
    		RAND_bytes(&random_char, 1);
    		key += charset[random_char % (sizeof(charset) - 1)];
  		}
  		
		return key;	
	}	
	
}
