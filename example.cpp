
#include <iostream>
#include <auth.h>

int main() {
    std::string secret = "MRSG4NJVNZSDKZDS"; 
    //the secret is a base32 hash, original text: ddn55nd5dr

    std::cout<<auth::generateToken(secret)<<std::endl;

    return 0;
}
