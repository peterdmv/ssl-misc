-module(ttl).

-compile(export_all).

-define(PORT, 11029).
-define(SERVER_CERT, "certs/server.pem").
-define(SERVER_KEY, "certs/server.key").
-define(CA_CERT, "certs/ca.pem").

-record(client_hello, {
	  client_version,
	  random,
	  session_id,          % opaque SessionID<0..32>
	  cookie,              % opaque<2..2^16-1>
	  cipher_suites,       % cipher_suites<2..2^16-1>
	  compression_methods, % compression_methods<1..2^8-1>,
	  %% Extensions
	  extensions
	 }).

client() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2']}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts, 10000),
    Sock.

client_loop() ->
    faulty_client(),
    %% timer:sleep(100),
    client_loop().

faulty_client() ->
    {ok, Sock} = gen_tcp:connect("localhost", ?PORT, [], 10000),
    Random = crypto:strong_rand_bytes(32),
    CH = client_hello(Random),
    CHBin = encode_client_hello(CH, Random),
    gen_tcp:send(Sock, CHBin),
    gen_tcp:close(Sock).
    %% gen_tcp

server() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2']}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    Pid = spawn_link(?MODULE, accept_loop, [LSock]),
    ssl:controlling_process(LSock, Pid),
    Pid.

accept_loop(Sock) ->
    {ok, CSock} = ssl:transport_accept(Sock),
    {R, _} = ssl:handshake(CSock),
    erlang:display(R),
    accept_loop(Sock).


encode_client_hello(CH, Random) ->
    HSBin = tls_handshake:encode_handshake(CH, {3,3}),
    CS = connection_states(Random),
    {Encoded, _} = tls_record:encode_handshake(HSBin, {3,3}, CS),
    Encoded.

client_hello(Random) ->
    CipherSuites = [<<0,255>>, <<"À,">>, <<"À0">>, <<"À$">>, <<"À(">>,
		    <<"À.">>, <<"À2">>, <<"À&">>, <<"À*">>, <<0,159>>,
		    <<0,163>>, <<0,107>>, <<0,106>>, <<"À+">>, <<"À/">>,
		    <<"À#">>, <<"À'">>, <<"À-">>, <<"À1">>, <<"À%">>,
		    <<"À)">>, <<0,158>>, <<0,162>>, <<0,103>>, <<0,64>>,
		    <<"À\n">>, <<192,20>>, <<0,57>>, <<0,56>>, <<192,5>>,
		    <<192,15>>, <<"À\t">>, <<192,19>>, <<0,51>>, <<0,50>>,
		    <<192,4>>, <<192,14>>],
    Extensions = #{alpn => undefined,
		   ec_point_formats =>
		       {ec_point_formats,
			[0]},
		   elliptic_curves =>
		       {elliptic_curves,
			[{1,3,132,0,39},
			 {1,3,132,0,38},
			 {1,3,132,0,35},
			 {1,3,36,3,3,2,
			  8,1,1,13},
			 {1,3,132,0,36},
			 {1,3,132,0,37},
			 {1,3,36,3,3,2,
			  8,1,1,11},
			 {1,3,132,0,34},
			 {1,3,132,0,16},
			 {1,3,132,0,17},
			 {1,3,36,3,3,2,
			  8,1,1,7},
			 {1,3,132,0,10},
			 {1,2,840,
			  10045,3,1,7},
			 {1,3,132,0,3},
			 {1,3,132,0,26},
			 {1,3,132,0,27},
			 {1,3,132,0,32},
			 {1,3,132,0,33},
			 {1,3,132,0,24},
			 {1,3,132,0,25},
			 {1,3,132,0,31},
			 {1,2,840,
			  10045,3,1,1},
			 {1,3,132,0,1},
			 {1,3,132,0,2},
			 {1,3,132,0,15},
			 {1,3,132,0,9},
			 {1,3,132,0,8},
			 {1,3,132,0,
			  30}]},
		   next_protocol_negotiation =>
		       undefined,
		   renegotiation_info =>
		       {renegotiation_info,
			undefined},
		   signature_algs =>
		       {hash_sign_algos,
			[{sha512,ecdsa},
			 {sha512,rsa},
			 {sha384,ecdsa},
			 {sha384,rsa},
			 {sha256,ecdsa},
			 {sha256,rsa},
			 {sha224,ecdsa},
			 {sha224,rsa},
			 {sha,ecdsa},
			 {sha,rsa},
			 {sha,dsa}]},
		   sni =>
		       {sni,
			"localhost"},
		   srp =>
		       undefined},

    #client_hello{client_version = {3,3},
		  random = Random,
		  session_id = crypto:strong_rand_bytes(32),
		  cipher_suites = CipherSuites,
		  compression_methods = [0],
		  extensions = Extensions
		 }.

connection_states(Random) ->
    CS = #{current_read =>
	       #{beast_mitigation => one_n_minus_one,cipher_state => undefined,
		 client_verify_data => undefined,compression_state => undefined,
		 mac_secret => undefined,secure_renegotiation => undefined,
		 security_parameters =>
		     {security_parameters,<<0,0>>,
		      1,0,0,0,0,0,0,0,0,0,0,undefined,undefined,
		      undefined,undefined,undefined,undefined},
		 sequence_number => 0,server_verify_data => undefined},
	   current_write =>
	       #{beast_mitigation => one_n_minus_one,cipher_state => undefined,
		 client_verify_data => undefined,compression_state => undefined,
		 mac_secret => undefined,secure_renegotiation => undefined,
		 security_parameters =>
		     {security_parameters,<<0,0>>,
		      1,0,0,0,0,0,0,0,0,0,0,undefined,undefined,
		      undefined,undefined,undefined,undefined},
		 sequence_number => 0,server_verify_data => undefined},
	   pending_read =>
	       #{beast_mitigation => one_n_minus_one,cipher_state => undefined,
		 client_verify_data => undefined,compression_state => undefined,
		 mac_secret => undefined,secure_renegotiation => undefined,
		 security_parameters =>
		     {security_parameters,undefined,1,undefined,undefined,undefined,
		      undefined,undefined,undefined,undefined,
		      undefined,undefined,undefined,undefined,
		      undefined,undefined,
		      Random,
		      undefined,undefined},
		 server_verify_data => undefined},
	   pending_write =>
	       #{beast_mitigation => one_n_minus_one,cipher_state => undefined,
		 client_verify_data => undefined,compression_state => undefined,
		 mac_secret => undefined,secure_renegotiation => undefined,
		 security_parameters =>
		     {security_parameters,undefined,1,undefined,undefined,undefined,
		      undefined,undefined,undefined,undefined,
		      undefined,undefined,undefined,undefined,
		      undefined,undefined,
		      Random,
		      undefined,undefined},
		 server_verify_data => undefined}}.
