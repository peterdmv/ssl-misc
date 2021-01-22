-module(tt).
-compile(export_all).
-export([client/0, client_cert/0, server/0,
	 client2/0, server2/0,
	 client3/0, server_verify_strict/0,
	 server_verify_strict2/0,
	 server_verify_strict_hrr/0,
	 server_verify_strict_hrr_no_ccs/0,
	 client_hrr/0,
	 server_sni/0, client_sni/0,
	 server_alpn/0, client_alpn/0]).

-define(PORT, 11029).
-define(SERVER_CERT, "certs/server.pem").
-define(SERVER_KEY, "certs/server.key").
-define(SERVER_EC_CERT, "certs/server-ec.pem").
-define(SERVER_EC_KEY, "certs/server-ec.key").
-define(SERVER_EC2_CERT, "certs/server-ec2.pem").

-define(CA_CERT, "certs/ca.pem").
-define(CA_EC_CERT, "certs/ca2.pem").
%% -define(CA_CERT_LONG, "certs-long/cacerts.pem").
%% -define(SERVER_CERT_LONG, "certs-long/server.pem").
%% -define(SERVER_KEY_LONG, "certs-long/server.key").

-define(TSERVER_CA_CERT, "bad-certs/rsa_server_cacerts.pem").
-define(TCLIENT_CA_CERT, "bad-certs/rsa_client_cacerts.pem").
-define(TSERVER_CERT, "bad-certs/rsa_server_cert.pem").
-define(TSERVER_KEY, "bad-certs/rsa_server_key.pem").
-define(TCLIENT_CERT, "bad-certs/rsa_client_cert.pem").
-define(TCLIENT_KEY, "bad-certs/rsa_client_key.pem").

tserver() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?TSERVER_CERT},
	     {keyfile, ?TSERVER_KEY},
	     {cacertfile, ?TSERVER_CA_CERT},
	     {reuseaddr, true},
	     %% {depth, 5},
	     %% {ciphers, ["DHE-RSA-AES256-SHA","DHE-RSA-AES128-SHA"]},
	     %% {versions, ['tlsv1.2']},
	     %% {signature_algs, [ecdsa_secp521r1_sha512,
	     %% 		       ecdsa_secp384r1_sha384,
	     %% 		       ecdsa_secp256r1_sha256,
	     %% 		       rsa_pss_pss_sha384,
	     %% 		       rsa_pss_pss_sha256,
	     %% 		       rsa_pss_rsae_sha384,
	     %% 		       rsa_pss_rsae_sha256,
	     %% 		       rsa_pkcs1_sha512,
	     %% 		       rsa_pkcs1_sha384,
	     %% 		       rsa_pkcs1_sha256,
	     %% 		       ecdsa_sha1,
	     %% 		       rsa_pkcs1_sha1,
	     %% 		       {sha512,ecdsa},
	     %% 		       {sha512,rsa},
	     %% 		       {sha384,ecdsa},
	     %% 		       {sha384,rsa},
	     %% 		       {sha256,ecdsa},
	     %% 		       {sha256,rsa},
	     %% 		       {sha224,ecdsa},
	     %% 		       {sha224,rsa},
	     %% 		       {sha,ecdsa},
	     %% 		       {sha,rsa},
	     %% 		       {sha,dsa}]},
 	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

tclient() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{certfile, ?TCLIENT_CERT},
	     {keyfile, ?TCLIENT_KEY},
	     {verify, verify_none},
	     {cacertfile, ?TCLIENT_CA_CERT},
	     {ciphers,[#{cipher => aes_256_gcm,key_exchange => dhe_dss,
			 mac => aead,prf => sha384},
		       #{cipher => aes_128_gcm,key_exchange => dhe_dss,
			 mac => aead,prf => sha256}]},
	     %% {client_preferred_next_protocols,
	     %%  {client,[<<"spdy/2">>],<<"http/1.1">>}},
	     %% {depth, 5},
	     %% {ciphers, ["DHE-RSA-AES256-SHA","DHE-RSA-AES128-SHA"]},
	     %% {versions, ['tlsv1.2']},
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

demo_client(Opts) ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {keep_secrets, true}
	    ] ++ Opts,
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


demo_client_hrr() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {supported_groups,[secp256r1, x25519]},
	     {middlebox_comp_mode, true},
	     {log_level, debug},
	     {keep_secrets, true}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


demo_server() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {cacertfile, ?CA_CERT},
	     {reuseaddr, true},
             {verify, verify_peer},
             {fail_if_no_peer_cert, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {middlebox_comp_mode, true},
	     {log_level, debug},
	     {keep_secrets, true}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

demo_server_hrr() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {cacertfile, ?CA_CERT},
	     {cookie, true},
	     {reuseaddr, true},
             {verify, verify_peer},
             {fail_if_no_peer_cert, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {supported_groups, [x448, x25519]},
	     {middlebox_comp_mode, true},
	     {log_level, debug},
	     {keep_secrets, true}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.



server() ->
    %% FunAndState =  {fun(_,{bad_cert, unknown_ca}, UserState) ->
    %% 			    {valid, UserState};
    %% 		       (_,{bad_cert, _} = Reason, _) ->
    %% 			    {fail, Reason};
    %% 		       (_,{extension, _}, UserState) ->
    %% 			    {unknown, UserState};
    %% 		       (_, valid, UserState) ->
    %% 			    {valid, UserState};
    %% 		       (_, valid_peer, UserState) ->
    %% 			    {valid, UserState}
    %% 		    end, []},
    FunAndState = fun tt:verify_fail_always/3,
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {cacertfile, ?CA_CERT},
	     {reuseaddr, true},
	     {versions, ['tlsv1.3']},
	     {verify, verify_peer},
	     %% {anti_replay, '10k'},
	     %% {session_tickets, stateful},
	     %% {reuse_session, fun(_,_,_,_) -> false end},
	     %% {reuse_sessions, true},
	     %%{padding_check, false},
	     %% {secure_renegotiate, false},
	     %% {anti_replay, teast},
	     %%{verify_fun, FunAndState},
	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

server_packet_4() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {cacertfile, ?CA_CERT},
	     {reuseaddr, true},
	     {versions, ['tlsv1.3']},
	     {verify, verify_peer},
	     {packet,4},
	     {active,false},
	     %% {anti_replay, '10k'},
	     %% {session_tickets, stateful},
	     %% {reuse_session, fun(_,_,_,_) -> false end},
	     %% {reuse_sessions, true},
	     %%{padding_check, false},
	     %% {secure_renegotiate, false},
	     %% {anti_replay, teast},
	     %%{verify_fun, FunAndState},
	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.


server_key_limit() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {key_update_at, 1},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     %% {anti_replay, '10k'},
	     %% {session_tickets, stateful},
	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

server_cipher() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {ciphers, ["TLS_AES_256_GCM_SHA384"]},
	     {reuseaddr, true},
	     {versions, ['tlsv1.1','tlsv1.3']}
	    ,{log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

server_only_13() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.3']}
	    ,{log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.


server_psk() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {session_tickets, stateful}
	    %% ,{log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.


server_psk2() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {session_tickets, stateful}
	    %% ,{log_level, debug}
	    ],
    LOpts2 = [%%{certfile, ?SERVER_CERT},
	      %%{keyfile, ?SERVER_KEY},
	      %%{reuseaddr, true},
	      %%{versions, ['tlsv1.2','tlsv1.3']},
	      {session_tickets, stateless}
	    %% ,{log_level, debug}
	    ],

    %% {ok, LSock} = ssl:listen(Port, LOpts),
    %% {ok, CSock} = ssl:transport_accept(LSock),
    %% {ok, _S} = ssl:handshake(CSock),

    %% {ok, CSock2} = ssl:transport_accept(LSock),
    %% {ok, S2} = ssl:handshake(CSock2),

    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, _S} = ssl:handshake(CSock),

    ssl:close(LSock),
    timer:sleep(1000),
    {ok, LSock2} = ssl:listen(11030, LOpts2),

    {ok, CSock2} = ssl:transport_accept(LSock2),
    {ok, S2} = ssl:handshake(CSock2),


    S2.


server_psk_loop() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {session_tickets, stateless}
	    ,{log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    accept_loop(LSock).


server_psk_bloom_loop() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {session_tickets, stateless},
	     {anti_replay, '10k'}
	    %% ,{log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    accept_loop(LSock).


server_psk_hrr_loop() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {supported_groups, [x448, x25519]},
	     {session_tickets, enabled}
	    ,{log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    accept_loop(LSock).

server_early_data_loop() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {session_tickets, stateless},
	     {early_data, enabled}
	    ,{log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    accept_loop(LSock).

accept_loop(Sock) ->
    {ok, CSock} = ssl:transport_accept(Sock),
    {ok, _} = ssl:handshake(CSock),
    accept_loop(Sock).

server_early_data_loop2() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {session_tickets, stateless},
	     {early_data, enabled}
	   %% ,{log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    accept_loop2(LSock).

server_early_data_loop3() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {cacertfile, ?CA_CERT},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {verify,verify_peer},
	     {fail_if_no_peer_cert,true},
	     {session_tickets, stateless},
	     {early_data, enabled}
	   %% ,{log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    accept_loop2(LSock).

server_early_data_loop_10k() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    application:set_env(ssl, server_session_ticket_max_early_data, 10000),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {session_tickets, stateless},
	     {early_data, disabled}
	   %% ,{log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    accept_loop2(LSock).

server_early_data_loop_10k_enabled() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    application:set_env(ssl, server_session_ticket_max_early_data, 10000),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {session_tickets, stateless},
	     {early_data, enabled}
	   %% ,{log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    accept_loop2(LSock).

accept_loop2(Sock) ->
    {ok, CSock} = ssl:transport_accept(Sock),
    {ok, _} = ssl:handshake(CSock),
    {ok, CSock2} = ssl:transport_accept(Sock),
    {ok, S} = ssl:handshake(CSock2),
    S.




server_nv() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {verify,verify_peer},
	     {fail_if_no_peer_cert,true}

%% ,
%% 	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

server_bad() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {fallback, true}
%% ,
%% 	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

server_hs_paused() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {handshake, hello}
%% ,
%% 	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S, Ext} = ssl:handshake(CSock),
    {S, Ext}.

server_hs_paused_12() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2']},
	     {handshake, hello}
%% ,
%% 	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S, Ext} = ssl:handshake(CSock),
    {S, Ext}.


server_honor_cipher_order() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {ciphers, [#{key_exchange => any,
			  cipher => aes_128_gcm,
			  mac => aead,
			  prf => sha256},
			#{key_exchange => any,
			  cipher => aes_256_gcm,
			  mac => aead,
			  prf => sha384}]}

%% ,
%% 	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

verify_pass_always(_Certificate, _Event, State) ->
    %% Create an ETS table, to record the fact that the verify function ran.
    %% Spawn a new process, to avoid the ETS table disappearing.
    %% Parent = self(),
    %% spawn(
    %%   fun() ->
    %% 	      ets:new(verify_fun_ran, [public, named_table]),
    %% 	      ets:insert(verify_fun_ran, {verify_pass_always_ran, true}),
    %% 	      Parent ! go_ahead,
    %% 	      timer:sleep(infinity)
    %%   end),
    %% receive go_ahead -> ok end,
    {valid, State}.

verify_fail_always(_Certificate, _Event, _State) ->
    %% Create an ETS table, to record the fact that the verify function ran.
    %% Spawn a new process, to avoid the ETS table disappearing.
    %% Parent = self(),
    %% spawn(
    %%   fun() ->
    %% 	      ets:new(verify_fun_ran, [public, named_table]),
    %% 	      ets:insert(verify_fun_ran, {verify_fail_always_ran, true}),
    %% 	      Parent ! go_ahead,
    %% 	      timer:sleep(infinity)
    %%   end),
    %% receive go_ahead -> ok end,
    {fail, bad_certificate}.

client() ->
    %% FunAndState =  {fun(_,{bad_cert, unknown_ca}, UserState) ->
    %% 			    {valid, UserState};
    %% 		       (_,{bad_cert, _} = Reason, _) ->
    %% 			    {fail, Reason};
    %% 		       (_,{extension, _}, UserState) ->
    %% 			    {unknown, UserState};
    %% 		       (_, valid, UserState) ->
    %% 			    {valid, UserState};
    %% 		       (_, valid_peer, UserState) ->
    %% 			    {valid, UserState}
    %% 		    end, []},
    FunAndState = {fun tt:verify_fail_always/3, {}},

    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {versions, ['tlsv1.3']},
	     %% {session_tickets, stateless},
	     %%{client_preferred_next_protocols, {client, [<<"http/1.1">>]}},
	     %% {reuse_session, <<1,2,3,4>>},
	     %% {reuse_sessions, true},
	     %% {srp_identity, {"user", "password"}},
	     %%{verify_fun, FunAndState},
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts, 10000),
    Sock.

client_packet_4() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {versions, ['tlsv1.3']},
	     {packet,4},
	     {active,false},
	     %% {session_tickets, stateless},
	     %%{client_preferred_next_protocols, {client, [<<"http/1.1">>]}},
	     %% {reuse_session, <<1,2,3,4>>},
	     %% {reuse_sessions, true},
	     %% {srp_identity, {"user", "password"}},
	     %%{verify_fun, FunAndState},
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts, 10000),
    Sock.


client_no_ca() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, 4},
	     {cacertfile, ?CA_CERT},
	     %% {versions, ['tlsv1.2']},
	     %% {session_tickets, stateless},
	     %%{client_preferred_next_protocols, {client, [<<"http/1.1">>]}},
	     %% {reuse_session, <<1,2,3,4>>},
	     %% {reuse_sessions, true},
	     %% {srp_identity, {"user", "password"}},

	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts, 10000),
    Sock.


client_only_13() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.3']},
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

client_session_tickets() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {log_level, debug},
	     %% {server_name_indication, "localhost"},
	     {session_tickets, enabled}
	    %% ,{use_ticket, <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

client_session_tickets_auto() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [%%{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {log_level, debug},
	     %% {server_name_indication, "localhost"},
	     {session_tickets, auto},
	     {keep_secrets, true}
	    %% ,{use_ticket, <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

client_session_tickets_auto_early_data(Data) ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [%%{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {log_level, debug},
	     %% {server_name_indication, "localhost"},
	     {session_tickets, auto},
	     {early_data, Data}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

client_session_tickets_manual_early_data(Tickets, Data) ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [%%{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {log_level, debug},
	     %% {server_name_indication, "localhost"},
	     {session_tickets, manual},
	     {use_ticket, Tickets},
	     {early_data, Data}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

client_session_tickets_manual_early_data_auth(Tickets, Data) ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [%%{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {log_level, debug},
	     %% {server_name_indication, "localhost"},
	     {session_tickets, manual},
	     {use_ticket, Tickets},
	     {early_data, Data}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

client_session_tickets_manual_early_data_size(Size) ->
    Data = binary:copy(<<"f">>, Size),
    {Sock, [Ticket|_]} = client_session_tickets_manual(),
    ssl:close(Sock),
    client_session_tickets_manual_early_data([Ticket], Data).

client_session_tickets_manual_early_data_size_bad(Size) ->
    Data = binary:copy(<<"f">>, Size),
    {Sock, Tickets0} = client_session_tickets_manual(),
    ssl:close(Sock),
    Tickets = update_session_ticket_extension(Tickets0, 17000),
    client_session_tickets_manual_early_data(Tickets, Data).

client_session_tickets_manual_early_data_size_auth(Size) ->
    Data = binary:copy(<<"f">>, Size),
    {Sock, [Ticket|_]} = client_session_tickets_manual_auth(),
    ssl:close(Sock),
    client_session_tickets_manual_early_data_auth([Ticket], Data).

client_session_tickets_manual_early_data_size_auth_bad(Size) ->
    Data = binary:copy(<<"f">>, Size),
    {Sock, [Ticket|_]} = client_session_tickets_manual_auth(),
    ssl:close(Sock),
    client_session_tickets_manual_early_data([Ticket], Data).

client_session_tickets_manual_early_data_size2(Size) ->
    Data = binary:copy(<<"f">>, Size),
    {Sock, Tickets} = client_session_tickets_manual(),
    ssl:close(Sock),
    client_session_tickets_manual_early_data(Tickets, Data).

client_session_tickets_auto(Port) ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    %%Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {log_level, debug},
	     %% {server_name_indication, "localhost"},
	     {session_tickets, auto}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


client_session_tickets2() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {log_level, debug},
	     %% {server_name_indication, "localhost"},
	     {session_tickets, enabled}
	    %% ,{use_ticket, <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>}
	    ,{use_ticket, [<<131,116,0,0,0,5,100,0,4,104,107,100,102,100,0,6,115,104,97,
                  51,56,52,100,0,3,112,115,107,109,0,0,0,48,199,36,206,173,
                  156,139,254,111,11,232,124,158,36,103,42,246,64,255,82,143,
                  189,222,48,227,186,228,23,210,196,50,156,74,18,112,52,34,
                  224,159,218,76,231,5,217,99,81,241,9,92,100,0,3,115,110,
                  105,107,0,9,108,111,99,97,108,104,111,115,116,100,0,6,116,
                  105,99,107,101,116,104,6,100,0,18,110,101,119,95,115,101,
                  115,115,105,111,110,95,116,105,99,107,101,116,98,0,0,28,32,
                  110,4,0,51,234,250,190,109,0,0,0,8,0,0,0,0,0,0,0,2,109,0,0,
                  0,113,248,232,241,165,29,37,94,116,100,84,140,250,73,165,
                  61,76,4,250,164,131,16,212,187,194,141,125,59,82,194,151,
                  42,218,85,221,165,112,28,114,169,30,133,121,107,83,168,223,
                  231,81,160,82,29,6,153,245,216,9,25,53,157,164,73,249,101,
                  206,166,131,123,54,82,233,160,238,247,210,48,87,110,101,63,
                  20,54,77,144,187,49,49,116,211,71,179,80,225,91,244,33,181,
                  165,98,44,32,109,158,118,221,33,106,139,3,165,220,189,209,
                  174,116,0,0,0,0,100,0,9,116,105,109,101,115,116,97,109,112,
                  98,93,201,82,190>>]}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

client_session_tickets2(Port) ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    %%Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {log_level, debug},
	     %% {server_name_indication, "localhost"},
	     {session_tickets, manual}
	    %% ,{use_ticket, <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>}
	    ,{use_ticket, [<<131,116,0,0,0,5,100,0,4,104,107,100,102,100,0,6,115,104,97,
                  51,56,52,100,0,3,112,115,107,109,0,0,0,48,199,36,206,173,
                  156,139,254,111,11,232,124,158,36,103,42,246,64,255,82,143,
                  189,222,48,227,186,228,23,210,196,50,156,74,18,112,52,34,
                  224,159,218,76,231,5,217,99,81,241,9,92,100,0,3,115,110,
                  105,107,0,9,108,111,99,97,108,104,111,115,116,100,0,6,116,
                  105,99,107,101,116,104,6,100,0,18,110,101,119,95,115,101,
                  115,115,105,111,110,95,116,105,99,107,101,116,98,0,0,28,32,
                  110,4,0,51,234,250,190,109,0,0,0,8,0,0,0,0,0,0,0,2,109,0,0,
                  0,113,248,232,241,165,29,37,94,116,100,84,140,250,73,165,
                  61,76,4,250,164,131,16,212,187,194,141,125,59,82,194,151,
                  42,218,85,221,165,112,28,114,169,30,133,121,107,83,168,223,
                  231,81,160,82,29,6,153,245,216,9,25,53,157,164,73,249,101,
                  206,166,131,123,54,82,233,160,238,247,210,48,87,110,101,63,
                  20,54,77,144,187,49,49,116,211,71,179,80,225,91,244,33,181,
                  165,98,44,32,109,158,118,221,33,106,139,3,165,220,189,209,
                  174,116,0,0,0,0,100,0,9,116,105,109,101,115,116,97,109,112,
                  98,93,201,82,190>>]}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

client_session_tickets3() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    TicketId = ets:last(tls13_session_ticket_db),
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {log_level, debug},
	     %% {server_name_indication, "localhost"},
	     {session_tickets, enabled}
	    ,{use_ticket, [TicketId]}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

client_session_tickets4() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    TicketId0 = ets:last(tls13_session_ticket_db),
    TicketId1 = ets:first(tls13_session_ticket_db),
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {log_level, debug},
	     %% {server_name_indication, "localhost"},
	     {session_tickets, enabled}
	    ,{use_ticket, [TicketId0,TicketId1]}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

client_session_tickets_first() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    TicketId1 = ets:first(tls13_session_ticket_db),
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {log_level, debug},
	     %% {server_name_indication, "localhost"},
	     {session_tickets, manual}
	    ,{use_ticket, [TicketId1]}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

client_session_tickets_manual_simple() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {log_level, debug},
	     {session_tickets, manual}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

client_session_tickets_manual() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {log_level, debug},
	     %% {server_name_indication, "localhost"},
	     {session_tickets, manual}
	    %% ,{use_ticket, [TicketId1]}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    %% Sock.
    {Sock, receive_tickets(2)}.

client_session_tickets_manual_auth() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {log_level, debug},
	     %% {server_name_indication, "localhost"},
	     {session_tickets, manual}
	    %% ,{use_ticket, [TicketId1]}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    %% Sock.
    {Sock, receive_tickets(2)}.


client_session_tickets_manual2(Tickets) ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {log_level, debug},
	     %% {server_name_indication, "localhost"},
	     {session_tickets, manual}
	    ,{use_ticket, Tickets}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


receive_tickets(N) ->
    receive_tickets(N, []).
%%
receive_tickets(0, Acc) ->
    Acc;
receive_tickets(N, Acc) ->
    receive
        {ssl, session_ticket, Ticket} ->
            receive_tickets(N - 1, [Ticket|Acc])
    end.

client_session_tickets3hrr_openssl() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    TicketId = ets:last(tls13_session_ticket_db),
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {log_level, debug},
	     {supported_groups,[secp256r1, x25519]},
	     %% {server_name_indication, "localhost"},
	     {session_tickets, enabled}
	    ,{use_ticket, TicketId}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


client_session_tickets3hrr() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    TicketId = ets:last(tls13_session_ticket_db),
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {log_level, debug},
	     {supported_groups,[secp256r1, x25519]},
	     %% {server_name_indication, "localhost"},
	     {session_tickets, enabled}
	    ,{use_ticket, TicketId}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.



client_nv() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

client_cb_info() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {log_level, debug},
	     {cb_info,{gen_tcp, tcp, tcp_closed, tcp_error}},
	     {log_alert, true}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

client_dtls_cb_info() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {protocol, dtls},
	     %% {log_level, debug},
	     {cb_info,{gen_udp, udp, udp_closed, udp_error}}
	     %% {log_alert, true}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

server_dtls() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {protocol, dtls},
	     {cookie, true},
	     {cb_info,{gen_udp, udp, udp_closed, udp_error}}
	    ,{log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

client_dtls_params(Addr, Port) ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    COpts = [%%{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {protocol, dtls}
	     %% {log_level, debug}
	     %% {log_alert, true}
	    ],
    {ok, Sock} = ssl:connect(Addr, Port, COpts),
    Sock.


server_dtls_params(Port, Params) ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {protocol, dtls},
	     {log_level, debug}
	    ] ++ Params,
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.


client_reuse_sessions() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {reuse_sessions, false},
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.
client_hs_paused() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {handshake, hello},
	     {log_level, debug}
	    ],
    {ok, Sock, Ext} = ssl:connect("localhost", Port, COpts),
    {Sock, Ext}.


client_honor_cipher_order() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {ciphers, [#{key_exchange => any,
			  cipher => aes_256_gcm,
			  mac => aead,
			  prf => sha384},
			#{key_exchange => any,
			  cipher => aes_128_gcm,
			  mac => aead,
			  prf => sha256}]},
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


client_sg() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {log_level, debug},
	     {supported_groups, [x448]}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


client_12() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2']},
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


server_12() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2']},
	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

server_11() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.1']},
	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

server_10() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1']},
	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

client_12_ubuntu() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("ubuntu-vm", Port, COpts),
    Sock.


server_12_hello() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {handshake, hello},
	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S, Exts} = ssl:handshake(CSock),
    {S, Exts}.

client_12_hello() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {handshake, hello},
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


client_13_scheme() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {signature_algs_cert, [ecdsa_secp384r1_sha384,
				    rsa_pss_rsae_sha256,
				    rsa_pkcs1_sha256,
				    {sha256,rsa},{sha256,dsa}]}
,
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.



server_ec() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_EC_CERT},
	     {keyfile, ?SERVER_EC_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2','tlsv1.3']}
%% ,
%% 	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

client_ec() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']}
,
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


server_ec2() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_EC2_CERT},
	     {keyfile, ?SERVER_EC_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2','tlsv1.3']}
%% ,
%% 	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

client_ec2() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_EC_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']}
,
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


server_ec3() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_EC2_CERT},
	     {keyfile, ?SERVER_EC_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2','tlsv1.3']}
%% ,
%% 	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

client_ec3() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_EC_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {signature_algs_cert, [ecdsa_secp384r1_sha384, ecdsa_secp521r1_sha512]}
,
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

client_cert() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {versions, ['tlsv1.2', 'tlsv1.3']}
 ,
 	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


server2() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {supported_groups, [x448, secp256r1, secp384r1]},
	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

client2() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {supported_groups,[secp384r1, secp256r1, x25519]},
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

server_verify_strict() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {cacertfile, ?CA_CERT},
	     {reuseaddr, true},
             {verify, verify_peer},
             {fail_if_no_peer_cert, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     %%{supported_groups, [x448, secp256r1, secp384r1]},
	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

client3() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {supported_groups,[secp384r1, secp256r1, x25519]}
%% ,
%% 	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

%% Triggers alert
server_verify_strict2() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {cacertfile, ?CA_CERT},
	     {reuseaddr, true},
             {verify, verify_peer},
             {fail_if_no_peer_cert, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {supported_groups, [x448, secp256r1, secp384r1]},
	     {signature_algs, [rsa_pkcs1_sha256, rsa_pkcs1_sha384, rsa_pss_rsae_sha256]},
	     %% Skip rsa_pkcs1_sha256!
	     {signature_algs_cert, [rsa_pkcs1_sha384, rsa_pkcs1_sha512]},
	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.


server_verify_strict_hrr() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {cacertfile, ?CA_CERT},
	     {reuseaddr, true},
             {verify, verify_peer},
             {fail_if_no_peer_cert, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {supported_groups, [x448, x25519]},
	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

server_verify_strict_hrr_no_ccs() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {cacertfile, ?CA_CERT},
	     {reuseaddr, true},
             {verify, verify_peer},
             {fail_if_no_peer_cert, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {supported_groups, [x448, x25519]},
	     {middlebox_comp_mode, false},
	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

server_hrr() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {cacertfile, ?CA_CERT},
	     {reuseaddr, true},
	     %%{verify, verify_peer},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {supported_groups, [x448, x25519]},
	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

client_hrr() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {supported_groups,[secp256r1, x25519]}
,
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

client_hrr_no_ccs() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {middlebox_comp_mode, false},
	     {supported_groups,[secp256r1, x25519]}
,
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


server_sni() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {log_level, debug},
	     {sni_hosts,
	      [{"a.server",
		[{certfile, ?SERVER_CERT},
	     	 {keyfile, ?SERVER_KEY}]},
	       {"b.server",
	     	[{certfile, ?SERVER_CERT},
	     	 {keyfile, ?SERVER_KEY}]}]}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

server_12_sni() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {log_level, debug},
	     {sni_hosts,
	      [{"a.server",
	     	[{certfile, ?SERVER_CERT},
	     	 {keyfile, ?SERVER_KEY}]},
	       {"b.server",
	     	[{certfile, ?SERVER_CERT},
	     	 {keyfile, ?SERVER_KEY}]}]}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.


client_sni() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {server_name_indication, "a.server"}
,
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

client_sni_no_verify() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [%%{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {server_name_indication, "a.server" }
,
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

client_12_sni_no_verify() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [%%{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2']},
	     {server_name_indication, "a.server"},
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


server_alpn() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {alpn_preferred_protocols, [<<5,6>>, <<1>>]},
	     {supported_groups, [x448, x25519]},
	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

client_alpn() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {server_name_indication, "localhost"},
	     %% {alpn_advertised_protocols, [<<1,2,3,4>>,<<5,6>>]},
	     {alpn_advertised_protocols, []},
	     {supported_groups,[secp256r1, x25519]}
           , {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


server_sig_alg_cert1() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {cacertfile, ?CA_CERT},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {verify,verify_peer},
	     {signature_algs, [rsa_pkcs1_sha256, rsa_pkcs1_sha384, rsa_pss_rsae_sha256]},
	     %% Skip rsa_pkcs1_sha256!
	     {signature_algs_cert, [ rsa_pkcs1_sha256, rsa_pkcs1_sha384, rsa_pkcs1_sha512]},
	     {fail_if_no_peer_cert, true},
	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.


server_12_sig_alg_cert1() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {cacertfile, ?CA_CERT},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2']},
	     {verify,verify_peer},
	     {signature_algs, [{sha256,rsa},{sha256,dsa}]},
	     %% Skip rsa_pkcs1_sha256!
	     {signature_algs_cert, [{sha256,rsa},{sha256,dsa}]},
	     {fail_if_no_peer_cert, true},
	     {log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.


client_sig_alt_cert1() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {cacertfile, ?CA_CERT},
	     {reuseaddr, true},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {signature_algs, [rsa_pkcs1_sha256, rsa_pkcs1_sha384, rsa_pss_rsae_sha256]},
	     %% Skip rsa_pkcs1_sha256!
	     {signature_algs_cert, [rsa_pkcs1_sha256, rsa_pkcs1_sha384, rsa_pkcs1_sha512]},
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


client_all_ver() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.3','tlsv1.2','tlsv1.1', 'tlsv1']},
	     {server_name_indication, "localhost"},
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


client_all_ver2() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2','tlsv1.1', 'tlsv1']},
	     {server_name_indication, "localhost"},
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

-define(DO_MAYBE, {Ref,Maybe} = maybe(), try).
-define(DONE,
	catch
	    {Ref, #alert{} = Alert} ->
		Alert;
	    {Ref, {#alert{} = Alert, State}} ->
		{Alert, State};
	    {Ref, {State, StateName}} ->
		{State, StateName};
	    {Ref, {State, StateName, ServerHello}} ->
		{State, StateName, ServerHello}
	end).
-record(alert, {}).

maybe() ->
    Ref = erlang:make_ref(),
    Ok = fun(ok) -> ok;
            ({ok,R}) -> R;
            ({error,Reason}) ->
                 throw({Ref,Reason})
         end,
    {Ref,Ok}.


test() ->
    ?DO_MAYBE
	Maybe(ok)
    ?DONE.

test2() ->
    ssl:start(),
    {ok, S1} = ssl:listen(0, [{protocol, dtls}]),
    {ok, {_, Port}} = ssl:sockname(S1),
    [{Port, busy}] = ets:lookup(dtls_listener_sup_port, Port),
    {error, already_listening} =
        ssl:listen(Port, [{protocol, dtls}, {ip, {127,0,0,3}}]),
    [{Port, busy}] = ets:lookup(dtls_listener_sup_port, Port),
    ssl:close(S1),
    [] = ets:lookup(dtls_listener_sup_port, Port),
    {ok, S2} =
        ssl:listen(Port, [{protocol, dtls}, {ip, {127,0,0,3}}]),
    [{Port, 1}] = ets:lookup(dtls_listener_sup_port, Port),
    erlang:display({testcase, ets:lookup(dtls_listener_sup, {all, Port})}),

    ssl:listen(Port, [{protocol, dtls}]).

test3() ->
    ssl:start(),
    
    Test = self(),
    Pid = spawn(fun() ->
			{ok, S1} = ssl:listen(0, [{protocol, dtls}]),
			{ok, {_, Port0}} = ssl:sockname(S1),
			Test ! {self(), Port0}
		end),
    Port =
	receive
	    {Pid, Port1} ->
		Port1
	end,
    [{Port, busy}] = ets:lookup(dtls_listener_sup_port, Port),
    ssl:listen(Port, [{protocol, dtls}]).

early_data_auto() ->
    %% First handshake 1-RTT - get session tickets
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = 11029,
    Data = <<"HEAD / HTTP/1.1\r\nHost: \r\nConnection: close\r\n">>,
    COpts0 = [{cacertfile, ?CA_CERT},
	      {versions, ['tlsv1.2', 'tlsv1.3']},
	      {session_tickets, auto}],
    {ok, Sock0} = ssl:connect("localhost", Port, COpts0),

    %%{ssl, session_ticket, received} ??

    %% Wait for session tickets
    timer:sleep(500),
    %% Close socket if server cannot handle multiple connections e.g. openssl s_server
    ssl:close(Sock0),

    %% Second handshake 0-RTT
    COpts1 = [{cacertfile, ?CA_CERT},
	      {versions, ['tlsv1.2', 'tlsv1.3']},
	      {session_tickets, auto},
	      {early_data, Data}],
    {ok, Sock} = ssl:connect("localhost", Port, COpts1),
    Sock.

early_data_manual() ->
    %% First handshake 1-RTT - get session tickets
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = 11029,
    Data = <<"HEAD / HTTP/1.1\r\nHost: \r\nConnection: close\r\n">>,
    COpts0 = [{cacertfile, ?CA_CERT},
	      {versions, ['tlsv1.2', 'tlsv1.3']},
	      {session_tickets, manual}],
    {ok, Sock0} = ssl:connect("localhost", Port, COpts0),

    %% Wait for session tickets
    Ticket =
	receive
	    {ssl, session_ticket, Ticket0} ->
		Ticket0
	end,

    %% Close socket if server cannot handle multiple connections
    %% e.g. openssl s_server
    ssl:close(Sock0),

    %% Second handshake 0-RTT
    COpts1 = [{cacertfile, ?CA_CERT},
	      {versions, ['tlsv1.2', 'tlsv1.3']},
	      {session_tickets, manual},
	      {use_ticket, [Ticket]},
	      {keep_secrets, true},
	      {early_data, Data}],
    {ok, Sock} = ssl:connect("localhost", Port, COpts1),
    Sock.

%% RFC 8446 B.3.4. Ticket Establishment
-record(new_session_ticket, {
          ticket_lifetime,  %unit32
          ticket_age_add,   %unit32
          ticket_nonce,     %opaque ticket_nonce<0..255>;
          ticket,           %opaque ticket<1..2^16-1>
          extensions        %extensions<0..2^16-2>
         }).

%% #empty{} (client_hello, encrypted_extensions)
-record(early_data_indication, {}).
-record(early_data_indication_nst, {
          indication % uint32 max_early_data_size (new_session_ticket)
         }).

update_session_ticket_extension([Ticket|_], MaxEarlyDataSize) ->
    #{ticket := #new_session_ticket{
                   extensions = #{early_data :=
                                      #early_data_indication_nst{
                                         indication = Size}}}} = Ticket,
    #{ticket := #new_session_ticket{
                   extensions = #{early_data := Extensions0}} = NST0} = Ticket,
    Extensions = #{early_data => #early_data_indication_nst{
                                    indication = MaxEarlyDataSize}},
    NST = NST0#new_session_ticket{extensions = Extensions},
    [Ticket#{ticket => NST}].

