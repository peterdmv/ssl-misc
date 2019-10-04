-module(tls13_simple).
-compile(export_all).
-export([client/0, client_cert/0, server/0,
	 client2/0, server2/0,
	 client3/0, server_verify_strict/0,
	 server_verify_strict2/0,
	 server_verify_strict_hrr/0, client_hrr/0,
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

%% server_12() ->
%%     application:load(ssl),
%%     {ok, _} = application:ensure_all_started(ssl),
%%     Port = ?PORT,
%%     LOpts = [{certfile, ?SERVER_CERT_LONG},
%% 	     {keyfile, ?SERVER_KEY_LONG},
%% 	     {depth, 5},
%% 	     {versions, ['tlsv1.2']}
%% %% ,
%% %% 	     {log_level, debug}
%% 	    ],
%%     {ok, LSock} = ssl:listen(Port, LOpts),
%%     {ok, CSock} = ssl:transport_accept(LSock),
%%     {ok, S} = ssl:handshake(CSock),
%%     S.

%% client_12() ->
%%     application:load(ssl),
%%     {ok, _} = application:ensure_all_started(ssl),
%%     Port = ?PORT,
%%     COpts = [{verify, verify_peer},
%% 	     {cacertfile, ?CA_CERT_LONG},
%% 	     {depth, 5},
%% 	     {versions, ['tlsv1.2']}
%% ,
%% 	     {log_level, debug}
%% 	    ],
%%     {ok, Sock} = ssl:connect("localhost", Port, COpts),
%%     Sock.

server() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {versions, ['tlsv1.2','tlsv1.3']}
	    ,{log_level, debug}
	    ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

server_nv() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY}
,
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
	     {versions, ['tlsv1.2','tlsv1.3']},
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

client() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
	     {cacertfile, ?CA_CERT},
	     {versions, ['tlsv1.2', 'tlsv1.3']},
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
	     {session_tickets, true}
	    %% ,{use_ticket, <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>}
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
	     {session_tickets, true}
	    %% ,{use_ticket, <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>}
	    ,{use_ticket, <<187,86,251,97,101,197,211,219,234,200,96,43,51,119,194,159,237,150,135,89,64,50,78,251,26,157,224,21,17,106,240,32>>}
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
	     {session_tickets, true}
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
	     {session_tickets, true}
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
	     {protocol, dtls},
	     {cb_info,{gen_udp, udp, udp_closed, udp_error}}
	    ,{log_level, debug}
	    ],
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
	     %% {versions, ['tlsv1.2']},
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
             {verify, verify_peer},
             {fail_if_no_peer_cert, true},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {supported_groups, [x448, secp256r1, secp384r1]},
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


server_sni() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, ?SERVER_CERT},
	     {keyfile, ?SERVER_KEY},
	     {versions, ['tlsv1.2','tlsv1.3']},
	     {log_level, debug}
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
	     {server_name_indication, "localhost"}
,
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
	     {versions, ['tlsv1.2', 'tlsv1.3']},
	     {signature_algs, [rsa_pkcs1_sha256, rsa_pkcs1_sha384, rsa_pss_rsae_sha256]},
	     %% Skip rsa_pkcs1_sha256!
	     {signature_algs_cert, [rsa_pkcs1_sha256, rsa_pkcs1_sha384, rsa_pkcs1_sha512]},
	     {log_level, debug}
	    ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.
