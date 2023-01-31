# oauth2
An oauth2 web-service built with C++ using ChatGPT

This serivce was built based on the contents provided in this link 
https://medium.com/@ratrosy/building-a-basic-authorization-server-using-authorization-code-flow-c06866859fb1

ChatGPT was used to convert the python codes into C++, which nearly did 80% of the work.
The rest was a few tweaks and a few more questions to ChatGPT which shows its utility as a converter tool!

## How to Build 

Build with the following command:

```
 g++ -I ./include  main.cpp -lssl -lcrypto -pthread -o oauth2
```
Then simply run with ./oauth2

Needless to say cmake and g++ should be pre-installed to compile.

The solution was built with g++ 9.3.0 and uses very few sets of libraries like 
lib openssl, lib crypto and the usual thread library 

Following installation instructions should be enought to get those libraries installed
and get it working on ubuntu (20.04):

```
-$ sudo apt-get update -y
-$ sudo apt-get install build-essential
```
Although the official documentation says checkinstall and zlib1g-dev also should be present 

## Necessary Includes

The main include file is basically oauth2.hpp which was generated mostly using ChatGPT prompt.
Need Httplib - a header only C++ lib to run the webserver.
Json parsing, Json Web Token libraries are also required which is placed in the include directory.

## Sample Usage

main.cpp shows how to include and call the apis in the the header.

You initially generate a key for hasing algorithm and set the private and public key based on which
the final access-token would be generated. 
Since we are using HS256 algorithm so both private and public key is the same.

Then set the required variables OAuth2::client_verifier, OAuth2::client_authenticator
and OAuth2::user_authenticator to plug in own business logics for verification and authentication.

## testing

run the service with ./oauth2 and the in the browser hit "http://localhost:8081"
 
This is a very basic OAUTH2 implementation which shows how to use it for a web-based application.
With a few tweaks and a few queries to ChatGPT, you should be able to design the solution for SPAs and mobile apps.

## Acknowledgements

Ahna Mohiuddin (https://www.linkedin.com/in/ahna-mohiuddin-6ba34119b/) for R&D and digging up the all important python example

Md. Aman Ullah (https://github.com/MdAman02) for explaining the whole process of OAUTH2 which helped to get the job done

## History

### Initial Commit - 30th Jan, 2023
### Readme file updated - 31st Jan, 2023



