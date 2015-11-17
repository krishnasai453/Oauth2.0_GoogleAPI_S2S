-Author : Krishna Sai	
-Email : krishnasai453@gmail.com

### Oauth 2.0 for accessing any Google API for making an authorized API call. Access token is generated every 60 minutes (Access token expires in 60 minutes)

######################################

### Getting RSA Private Key

> Go to google developers forum and create new service account credential

> After creating new credential download .p12 file of your key

> .p12 file is not readable by file system. So we will convert .p12 file to .pem file format

> Following commands convert .p12 file to .pem file

	openssl pkcs12 -in yourkey.p12 -out yourkey.pem -nodes
	openssl rsa -in yourkey.pem -out RSA_Privatekey.pem


### To run the program follow the steps

> clone the repository

git clone git clone https://github.com/krishnasai453/Oauth2.0_GoogleAPI_S2S.git

> In the file googleoauth2_s2s.erl change the filename to your private key file name in jwt_create() function

jwt_create() ->
{ok,PemBin} = file:read_file("path/RSA_Privatekey.pem"),

> Change the scope in macro definitions of googleoauth2_s2s.erl file to the google api you want to access.
	** Default is google pubsub cloud api


> In the terminal make 

make

> After making type following command

erl -pa ebin/ deps/*/ebin/ -s googleoauth2_s2s

> you will enter erlang shell. Type following command in erlang shell

googleoauth2_s2s:jwt_create().

Thats it you will get the access token every 60 minutes



