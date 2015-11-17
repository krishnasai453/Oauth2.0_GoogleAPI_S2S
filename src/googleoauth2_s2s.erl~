
-module(googleoauth2_s2s).
-author('Krishna Sai').
-export([start/0,jwt_create/0]).
-include_lib("public_key/include/public_key.hrl").

%%===========================================================================
%% Defining Macros
%% @doc
%% make sure to give correct values in the fields. 
%% ISS = service email id , Scope =  The Goolge API you want to access
%% AUD = Host Url
%%end

-define(ISS, <<"793939172578-5sdthqrvfbcq98laicfko0ktinjbksqe@developer.gserviceaccount.com">>).
-define(SCOPE, <<"https://www.googleapis.com/auth/pubsub">>).
-define(AUD, <<"https://www.googleapis.com/oauth2/v3/token">>).

%%=============================================================================
%% function: Start/0
%%  @doc
%%  Starting various applications (not used in this program, for future use)
%%  end
%%

start()->
    ok = application:start(crypto),
    ok = application:start(asn1),
    ok = application:start(public_key),
    ok = application:start(ssl),
    ok = application:start(jsx),
    ok = application:start(inets).


%%=============================================================================
%% function: jwt_header/0
%%	@doc
%%	Generating JWT header
%%	end
%%

jwt_header()->

    [{alg,<<"RS256">>},{typ,<<"JWT">>}] .


%%=============================================================================
%% function: jwt_claimset/0
%%  @doc
%%  Generating JWT Claim set
%%  end
%%

jwt_claimset()->
    IatTime = calendar:datetime_to_gregorian_seconds(calendar:universal_time())-719528*24*3600,
    ExpTime = IatTime + 3600,
   
    [
      {iss,?ISS},
      {scope,?SCOPE},
      {aud,?AUD},
      {exp,ExpTime},
      {iat,IatTime}
    ].


%%=============================================================================
%% function: jwt_create/0
%%  @doc
%%  Generating JSON Web Token (JWT) for sending to google for getting access token to access google API as Response 
%%  end
%%


jwt_create() ->
    {ok,PemBin} = file:read_file("RSA_Privatekey.pem"),
    PemEntry = public_key:pem_decode(PemBin),
    [A|_B] = PemEntry,
    RSAPrivateKey = public_key:pem_entry_decode(A),
    JwtHeaderJson = encode_json(jwt_header()),
    JwtClaimsetJson = encode_json(jwt_claimset()),
    io:format("JwtHeaderJson::, ~p, ~n", [JwtHeaderJson]),
    io:format("JwtClaimsetJson::, ~p, ~n", [JwtClaimsetJson]),
    JWS = jws_compute(JwtHeaderJson, JwtClaimsetJson, RSAPrivateKey),
    JWT=binary:replace(
    binary:replace(<<JwtHeaderJson/binary, ".", JwtClaimsetJson/binary, ".", JWS/binary>>,
                     <<"+">>, <<"-">>, [global]),
                      <<"/">>, <<"_">>, [global]),
    io:format("JWT:: ~p ~n",[JWT]),
    Response = request_token(JWT),
    io:format("AccessToken:: ~p ~n", [Response]),
    timer:apply_after(3600000, googleoauth2_s2s, jwt_create, []).
    

%%=============================================================================
%% function: jws_compute/0
%%  @doc
%%  Computing JSON Web Signature
%%  end
%%

jws_compute(Header, ClaimSet,#'RSAPrivateKey'{publicExponent=Exponent
                                                          ,modulus=Modulus
                                                          ,privateExponent=PrivateExponent
                                                          }) ->
    base64:encode(crypto:sign(rsa, sha256, <<Header/binary, ".", ClaimSet/binary>>, [Exponent, Modulus, 
                                                                                      PrivateExponent])).


%%=============================================================================
%% function: encode_json/0
%%  @doc
%%  Encoiding JWT into JSON base64 format
%%  end
%%

encode_json(JWToken) ->
    base64:encode(jsx:encode(JWToken)).


%%=============================================================================
%% function: request_token/0
%%  @doc
%%  Erlang http:request that posts required parameters to get access token as response
%%  end
%%

request_token(JWT)->

    Method = post,
    URL = "https://www.googleapis.com/oauth2/v3/token",
    Grant = <<"urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer">>,
    Body = <<"grant_type=",Grant/binary,"&assertion=",JWT/binary>>,
    io:format("Body:: ~p~n~n",[Body]),
    
    ContentType = "application/x-www-form-urlencoded",
    case httpc:request(Method, {URL, [], ContentType, Body}, [], []) of
        {ok, {{"HTTP/1.1",200, _State}, _Head, ResponseBody}} ->
        io:format("JSON_Access_Token:: ~p~n~n",[ResponseBody]),
        Response1 = list_to_binary(ResponseBody),
        io:format("AccessTokenJSON:: ~p ~n", [Response1]),
        jsx:decode(Response1);

        {ok, {{"HTTP/1.1",ResponseCode, _State}, _Head, ResponseBody}} ->
        io:format("Response code : ~p~n Body :~p~n~n",[ResponseCode, ResponseBody]),
        ErrorResponceBody = list_to_binary(ResponseBody),
        jsx:decode(ErrorResponceBody);

        {error,Reason} ->
        io:format("~nerror error : ~p~n",[Reason]),
        {error,Reason}
        
    end.
