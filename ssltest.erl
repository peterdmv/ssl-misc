-module(ssltest).

-compile(export_all).

-define(PORT, 11029).


-include("lib/ssl/src/ssl_connection.hrl").
-include("lib/ssl/src/tls_handshake_1_3.hrl").


server3() ->
       application:load(ssl),
    logger:set_application_level(ssl, debug),
    ssl:start(),
    {ok, ListenSocket} = ssl:listen(?PORT, [{versions, ['tlsv1.3', 'tlsv1.2', 'tlsv1.1', tlsv1]},
                                           {certfile, "test/cert.pem"},
                                           {keyfile, "test/key.pem"},
                                           {cacertfile, "test/cacert.pem"},
                                           {reuseaddr, true}
                                          ,{log_level, debug}
]),
    io:format("Ready to accept connection...~n"),
    try
        {ok, TLSTransportSocket} = ssl:transport_accept(ListenSocket),
        io:format("Proceeding with handshake...~n~n"),
        {ok, Socket} = ssl:handshake(TLSTransportSocket),
        io:format("~nSending message!~n~n"),
        ssl:send(Socket, "It works!")
    catch
        _:_ ->
            ok
    end,
    timer:sleep(10000).

server3b() ->
       application:load(ssl),
    logger:set_application_level(ssl, debug),
    ssl:start(),
    {ok, ListenSocket} = ssl:listen(?PORT, [{versions, ['tlsv1.3', 'tlsv1.2', 'tlsv1.1', tlsv1]},
                                           {certfile, "server.pem"},
                                           {keyfile, "server.key"},
                                           {cacertfile, "ca.pem"},
                                           {reuseaddr, true},
                                           {log_level, debug}]),
    io:format("Ready to accept connection...~n"),
    try
        {ok, TLSTransportSocket} = ssl:transport_accept(ListenSocket),
        io:format("Proceeding with handshake...~n~n"),
        {ok, Socket} = ssl:handshake(TLSTransportSocket),
        io:format("~nSending message!~n~n"),
        ssl:send(Socket, "It works!")
    catch
        _:_ ->
            ok
    end,
    timer:sleep(10000).



server_custom() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, "server.pem"},
             {keyfile, "server.key"},
             {versions, ['tlsv1.2','tlsv1.3']},
             {log_level, debug}
            %% ,{ciphers,[{ecdhe_rsa,aes_256_cbc,sha}]}
            %% , {supported_groups, [x448, secp256r1, secp384r1]} % should work! No HRR!
            , {supported_groups, [x448, x25519]}
],
    %% LOpts = [{certfile, "server.pem"}, {keyfile, "server.key"},{log_level, debug}],

    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.


dtls_client() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
             {cacertfile, "ca.pem"},
             {versions, ['dtlsv1.2']},
             {protocol, dtls},
             {log_level, debug}
            ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

dtls_client_renegotiate() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
             {cacertfile, "ca.pem"},
             {versions, ['dtlsv1.2']},
             {protocol, dtls},
             {log_level, debug},
             {renegotiate_at, 10},
             {reuse_sessions,false}
            ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


dtls_server() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, "server.pem"},
             {keyfile, "server.key"},
             {versions, ['dtlsv1.2']},
             {protocol, dtls},
             {log_level, debug}
            ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, _} = ssl:handshake(CSock).


server2() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, "server.pem"},
             {keyfile, "server.key"},
             {versions, ['tlsv1.2']},
             {log_level, debug}
            ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, _} = ssl:handshake(CSock).

server2verify() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, "server.pem"},
             {keyfile, "server.key"},
             {versions, ['tlsv1.2']},
             {cacertfile, "ca.pem"},
             {verify, verify_peer},
             {fail_if_no_peer_cert, true},
             {log_level, debug}
            ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, _} = ssl:handshake(CSock).

client2() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
             {cacertfile, "ca.pem"},
             {versions, ['tlsv1.2']},
             {log_level, debug}
            ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.



server() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, "server.pem"}, {keyfile, "server.key"},{versions, ['tlsv1.2','tlsv1.3']},{log_level, debug}
            %% ,{ciphers,[{ecdhe_rsa,aes_256_cbc,sha}]}
],
    %% LOpts = [{certfile, "server.pem"}, {keyfile, "server.key"},{log_level, debug}],

    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

server_verify() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, "server.pem"},
             {keyfile, "server.key"},
             {versions, ['tlsv1.2','tlsv1.3']},
             {cacertfile, "ca.pem"},
             {verify, verify_peer},
             {fail_if_no_peer_cert, false},
             {log_level, debug}
            %% ,{ciphers,[{ecdhe_rsa,aes_256_cbc,sha}]}
],
    %% LOpts = [{certfile, "server.pem"}, {keyfile, "server.key"},{log_level, debug}],

    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

server_verify_strict() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, "server.pem"},
             {keyfile, "server.key"},
             {versions, ['tlsv1.2','tlsv1.3']},
             {cacertfile, "ca.pem"},
             {verify, verify_peer},
             {fail_if_no_peer_cert, true},
             {log_level, debug}
            %% ,{ciphers,[{ecdhe_rsa,aes_256_cbc,sha}]}
],
    %% LOpts = [{certfile, "server.pem"}, {keyfile, "server.key"},{log_level, debug}],

    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.

client() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer}, {cacertfile, "ca.pem"},{versions, ['tlsv1.3', 'tlsv1.2']},{log_level, debug}
            %% ,{ciphers,[{ecdhe_rsa,aes_256_cbc,sha}]}
            %% ,{signature_algs, [{sha,rsa}]}
            %% ,{signature_algs_cert, [rsa_pkcs1_sha256,ecdsa_sha1]}
            %% ,{signature_algs_cert, [ecdsa_sha1]}
],
    %% COpts = [{verify, verify_peer}, {cacertfile, "ca.pem"},{versions, ['tlsv1.3']},{log_level, debug}],

    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


client_sg() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer}, {cacertfile, "ca.pem"},{versions, ['tlsv1.3', 'tlsv1.2']},
	     {log_level, debug},
	     {supported_groups, [x448]}

],
    %% COpts = [{verify, verify_peer}, {cacertfile, "ca.pem"},{versions, ['tlsv1.3']},{log_level, debug}],

    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

server_hs() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, "server.pem"}, {keyfile, "server.key"},{versions, ['tlsv1.3']},{log_alert, false},{handshake,hello}],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    S=ssl:handshake(CSock),
    S.

ec_client() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
             {cacertfile, "ecc-ca.pem"},
             {versions, ['tlsv1.2']},
             {log_level, debug}
             %% {ciphers,[{ecdhe_rsa,aes_256_cbc,sha}]}
            ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

ec_server() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, "ecc-server.pem"},
             {keyfile, "ecc-server.key"},
             {versions, ['tlsv1.2']},
             {log_level, debug},
             {ciphers,[{ecdhe_rsa,aes_256_cbc,sha}]}
            ],

    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    ok = ssl:handshake(CSock),
    CSock.

ec2_client() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
             {cacertfile, "ecc-ca.pem"},
             {versions, ['tlsv1.2']},
             {log_level, debug},
             {eccs ,[secp256r1,secp521r1,secp384r1]},
              {ciphers,[{ecdhe_rsa,aes_256_cbc,sha}]}
            ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


ec2_client_cipher_order() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
             {cacertfile, "ecc-ca.pem"},
             {versions, ['tlsv1.2']},
             {log_level, debug},
             {eccs ,[secp256r1,secp521r1,secp384r1]},
             {ciphers,[{ecdhe_rsa,aes_256_cbc,sha}, {ecdhe_ecdsa,aes_256_cbc,sha}]}
            ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

ec2_server() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, "ecc2-server.pem"},
             {keyfile, "ecc2-server.key"},
             {versions, ['tlsv1.2']},
             {log_level, debug}
             %% {ciphers,[{ecdhe_rsa,aes_256_cbc,sha}]}
            ],

    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    ok = ssl:handshake(CSock),
    CSock.

ec3_server() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, "ecc3-server.pem"},
             {keyfile, "ecc3-server.key"},
             {versions, ['tlsv1.2']},
             {log_level, debug}
             %% {ciphers,[{ecdhe_rsa,aes_256_cbc,sha}]}
            ],

    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    ok = ssl:handshake(CSock),
    CSock.





debug() ->
    dbg:tracer(),
    dbg:p(all,c).

hex(B) ->
    {A, _} = logger_ssl_formatter:convert_to_hex(tls_record, B),
    Comp = "0090 - 00 01 00 02 00 03 00 0f  00 10 00 11 00 0b 00 02    ................\n",
    logger:info(Comp ++ A).

hex2(L0) ->
    Ref = "0090 - 00 01 00 02 00 03 00 0f  00 10 00 11 00 0b 00 02    ................\n",
    L = lists:map(fun input/1, L0),
    logger:info(lists:foldl(fun hex_log/2, Ref, L)).

hex_log(Input, Acc) ->
    {A, _} = logger_ssl_formatter:convert_to_hex(tls_record, Input),
    Acc ++ A.

input(N) ->
    [<< <<X>> || X <- lists:seq(1,N) >>].


sort(L) ->
    Fun = fun ({A,_},{C,_}) when A > C -> true;
              ({A,B},{C,D}) when A =:= C, B > D -> true;
              (_,_) -> false
          end,
    lists:sort(Fun,L).



serverb() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, "server.pem"},
             {keyfile, "server.key"},
             {cacertfile, "ca.pem"},
             {log_level, debug},
             {verify, verify_peer},
             {verify_fun, fun ssltest:verify_fail_always/0}],

    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    ok = ssl:handshake(CSock),
    CSock.

clientb() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
             {certfile, "server.pem"},
             {keyfile, "server.key"},
             {cacertfile, "ca.pem"},
             {log_level, debug},
             {verify, verify_peer},
             {verify_fun, fun ssltest:verify_fail_always/0}],

    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


verify_fail_always(_Certificate, _Event, _State) ->
    {fail, bad_certificate}.

verify_pass_always(_Certificate, _Event, State) ->
    {valid, State}.



server_dh() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, "server.pem"}, {keyfile, "server.key"},{versions, ['tlsv1.2','tlsv1.1']},{log_level, debug}
            %% ,{ciphers,[{dhe_rsa,aes_256_gcm,aead,sha384}]}
            ,{ciphers,[{ecdhe_rsa,aes_256_cbc,sha}]}
],
    %% LOpts = [{certfile, "server.pem"}, {keyfile, "server.key"},{log_level, debug}],

    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    ok = ssl:handshake(CSock),
    CSock.

client_dh() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer}, {cacertfile, "ca.pem"},{versions, ['tlsv1.1', 'tlsv1.2']},{log_level, debug}
            ,{ciphers,[{dhe_rsa,aes_256_gcm,aead,sha384}]}
            %% ,{signature_algs, [{sha,rsa}]}
            %% ,{signature_algs_cert, [rsa_pkcs1_sha256,ecdsa_sha1]}
            %% ,{signature_algs_cert, [ecdsa_sha1]}
],
    %% COpts = [{verify, verify_peer}, {cacertfile, "ca.pem"},{versions, ['tlsv1.3']},{log_level, debug}],

    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.


convert(List0) ->
    List = lists:filter(fun(C) -> not lists:member(C, [$ ,10,13,$%]) end, List0),
    convert(List, <<$">>, 0).
%%
convert([], Acc, _) ->
    io:format("~s~n", [binary_to_list(<<Acc/binary>>)]);
convert([H], Acc, N) when (N rem 32) < 32 ->
    convert([], <<Acc/binary,H,$">>, N + 1);
convert([H|T], Acc, N) when (N rem 32) =:= 31 ->
    convert(T, <<Acc/binary,H,$",10,$">>, N + 1);
convert([H], Acc, N) when (N rem 8) < 8 ->
    convert([], <<Acc/binary,H,$">>, N + 1);
convert([H|T], Acc, N) when (N rem 8) =:= 7 ->
    convert(T, <<Acc/binary,H,$",$ ,$">>, N + 1);
convert([H|T], Acc, N) ->
    convert(T, <<Acc/binary,H>>, N + 1).


hexstr2int(S) ->
    B = hexstr2bin2(S),
    Bits = size(B) * 8,
    <<Integer:Bits/integer>> = B,
    Integer.

hexstr2bin2(S) when is_binary(S) ->
    hexstr2bin2(S, <<>>);
hexstr2bin2(S) ->
    hexstr2bin2(list_to_binary(S), <<>>).
%%
hexstr2bin2(<<>>, Acc) ->
    Acc;
hexstr2bin2(<<C,T/binary>>, Acc) when C =:= 32;   %% SPACE
                                     C =:= 10;   %% LF
                                     C =:= 13 -> %% CR
    hexstr2bin2(T, Acc);
hexstr2bin2(<<X,Y,T/binary>>, Acc) ->
    I = hex2int(X) * 16 + hex2int(Y),
    hexstr2bin2(T, <<Acc/binary,I>>).

hex2int(C) when $0 =< C, C =< $9 ->
    C - $0;
hex2int(C) when $A =< C, C =< $F ->
    C - $A + 10;
hex2int(C) when $a =< C, C =< $f ->
    C - $a + 10.



client_hello() ->
    hexstr2bin2(" 01 00 00 c0 03 03 cb 34 ec b1 e7 81 63 ba
          1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83 02
          4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00
          09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12
          00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00
          00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d
          8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af
          2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02
          03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02
          02 02 00 2d 00 02 01 01 00 1c 00 02 40 01").

server_hello() ->
     hexstr2bin2("02 00 00 56 03 03 a6 af 06 a4 12 18 60
          dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e
          d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88
          76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1
          dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04").

encrypted_extensions() ->
    hexstr2bin2("08 00 00 24 00 22 00 0a 00 14 00
          12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 1c
          00 02 40 01 00 00 00 00").

certificate() ->
    hexstr2bin2("0b 00 01 b9 00 00 01 b5 00 01 b0 30 82
          01 ac 30 82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a 86 48
          86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04 03 13 03
          72 73 61 30 1e 17 0d 31 36 30 37 33 30 30 31 32 33 35 39 5a 17
          0d 32 36 30 37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a 06
          03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7
          0d 01 01 01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f
          82 79 30 3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26
          d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c
          1a f1 9e aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52
          4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74
          80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93
          ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03
          01 00 01 a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30 00 30 0b 06
          03 55 1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7 0d 01
          01 0b 05 00 03 81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a
          72 67 17 06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea
          e8 f8 a5 8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a 03 01
          51 56 72 60 96 fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be
          c1 fc 63 a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b
          1c 3b 84 e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8
          96 12 29 ac 91 87 b4 2b 4d e1 00 00").

certificate_verify() ->
    hexstr2bin2("0f 00 00 84 08 04 00 80 5a 74 7c
          5d 88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a
          b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07
          86 53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b
          be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44
          5c 9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a
          3d a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3").

messages() ->
    [certificate(),encrypted_extensions(),server_hello(),client_hello()].

state() ->
    #state{handshake_env =
               #handshake_env{
                  tls_handshake_history = {messages(), certificate()}}}.


%% The digital signature is then computed over the concatenation of:
%%   -  A string that consists of octet 32 (0x20) repeated 64 times
%%   -  The context string
%%   -  A single 0 byte which serves as the separator
%%   -  The content to be signed
%%
%% For example, if the transcript hash was 32 bytes of 01 (this length
%% would make sense for SHA-256), the content covered by the digital
%% signature for a server CertificateVerify would be:
%%
%%    2020202020202020202020202020202020202020202020202020202020202020
%%    2020202020202020202020202020202020202020202020202020202020202020
%%    544c5320312e332c207365727665722043657274696669636174655665726966
%%    79
%%    00
%%    0101010101010101010101010101010101010101010101010101010101010101
digitally_sign(THash, Context, HashAlgo, PrivateKey =  #'RSAPrivateKey'{}) ->
    Content = build_content(Context, THash),

    %% The length of the Salt MUST be equal to the length of the output
    %% of the digest algorithm.
    %% PadLen = ssl_cipher:hash_size(HashAlgo),

    public_key:sign(Content, HashAlgo, PrivateKey,
                    [{rsa_padding, rsa_pkcs1_pss_padding},
                     {rsa_pss_saltlen, -1}]).


build_content(Context, THash) ->
    Prefix = binary:copy(<<32>>, 64),
    <<Prefix/binary,Context/binary,?BYTE(0),THash/binary>>.


ccv() ->
    SignatureScheme = rsa_pss_rsae_sha256,
    %% CertificateVerifyHS =
    %%     tls_handshake_1_3:certificate_verify(PrivateKey, SignatureScheme,
    %%                                          State0, server),


    {HashAlgo, _, _} =
        ssl_cipher:scheme_to_components(rsa_pss_rsae_sha256),

    Context = lists:reverse(messages()),
    %% io:format("### Context = ~p~n", [Context]),
    THash = tls_v1:transcript_hash(Context, HashAlgo),

    Signature = digitally_sign(THash, <<"TLS 1.3, server CertificateVerify">>,
                               HashAlgo, private_key()),

    CVRec = #certificate_verify_1_3{
               algorithm = SignatureScheme,
               signature = Signature
              },
    iolist_to_binary(tls_handshake:encode_handshake(CVRec, {3,4})).



private_key() ->

     Modulus =
        hexstr2int(
          "b4 bb 49 8f 82 79 30 3d 98 08 36 39 9b 36 c6 98 8c
           0c 68 de 55 e1 bd b8 26 d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab
           bc 9a 95 13 7a ce 6c 1a f1 9e aa 6a f9 8c 7c ed 43 12 09 98 e1 87
           a8 0e e0 cc b0 52 4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f
           da 43 08 46 74 80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0
           3e 2b d1 93 ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e
           3f"),

    PublicExponent =
        hexstr2int("01 00 01"),

    PrivateExponent =
        hexstr2int(
          "04 de a7 05 d4 3a 6e a7 20 9d d8 07 21 11 a8 3c 81
           e3 22 a5 92 78 b3 34 80 64 1e af 7c 0a 69 85 b8 e3 1c 44 f6 de 62
           e1 b4 c2 30 9f 61 26 e7 7b 7c 41 e9 23 31 4b bf a3 88 13 05 dc 12
           17 f1 6c 81 9c e5 38 e9 22 f3 69 82 8d 0e 57 19 5d 8c 84 88 46 02
           07 b2 fa a7 26 bc f7 08 bb d7 db 7f 67 9f 89 34 92 fc 2a 62 2e 08
           97 0a ac 44 1c e4 e0 c3 08 8d f2 5a e6 79 23 3d f8 a3 bd a2 ff 99
           41"),

    Prime1 =
        hexstr2int(
          "e4 35 fb 7c c8 37 37 75 6d ac ea 96 ab 7f 59 a2 cc 10 69 db
           7d eb 19 0e 17 e3 3a 53 2b 27 3f 30 a3 27 aa 0a aa bc 58 cd 67 46
           6a f9 84 5f ad c6 75 fe 09 4a f9 2c 4b d1 f2 c1 bc 33 dd 2e 05 15"),

    Prime2 =
        hexstr2int(
          "ca bd 3b c0 e0 43 86 64 c8 d4 cc 9f 99 97 7a 94 d9 bb fe ad
           8e 43 87 0a ba e3 f7 eb 8b 4e 0e ee 8a f1 d9 b4 71 9b a6 19 6c f2
           cb ba ee eb f8 b3 49 0a fe 9e 9f fa 74 a8 8a a5 1f c6 45 62 93 03"),

    Exponent1 =
        hexstr2int(
          "3f 57 34 5c 27 fe 1b 68 7e 6e 76 16 27 b7 8b 1b 82 64 33
           dd 76 0f a0 be a6 a6 ac f3 94 90 aa 1b 47 cd a4 86 9d 68 f5 84 dd
           5b 50 29 bd 32 09 3b 82 58 66 1f e7 15 02 5e 5d 70 a4 5a 08 d3 d3
           19"),

    Exponent2 =
        hexstr2int(
          "18 3d a0 13 63 bd 2f 28 85 ca cb dc 99 64 bf 47 64 f1 51
           76 36 f8 64 01 28 6f 71 89 3c 52 cc fe 40 a6 c2 3d 0d 08 6b 47 c6
           fb 10 d8 fd 10 41 e0 4d ef 7e 9a 40 ce 95 7c 41 77 94 e1 04 12 d1
           39"),

    Coefficient =
        hexstr2int(
          "83 9c a9 a0 85 e4 28 6b 2c 90 e4 66 99 7a 2c 68 1f 21
           33 9a a3 47 78 14 e4 de c1 18 33 05 0e d5 0d d1 3c c0 38 04 8a 43
           c5 9b 2a cc 41 68 89 c0 37 66 5f e5 af a6 05 96 9f 8c 01 df a5 ca
           96 9d"),

    #'RSAPrivateKey'{
       version = 'two-prime',
       modulus = Modulus,
       publicExponent = PublicExponent,
       privateExponent = PrivateExponent,
       prime1 = Prime1,
       prime2 = Prime2,
       exponent1 = Exponent1,
       exponent2 = Exponent2,
       coefficient = Coefficient,
       otherPrimeInfos = 'asn1_NOVALUE'}.


rsapss() ->

    {ok, File} = file:open("test.bin", [read, binary]),
    {ok, Message} = file:read(File, 32),
    io:format("### Message: ~p~n", [Message]),

    {ok, PemBin} = file:read_file("server.key"),

    [RSAEntry] = public_key:pem_decode(PemBin),

    PrivateKey = public_key:pem_entry_decode(RSAEntry),
    HashAlgo = sha256,

    %% public_key:pkix_decode_cert(Cert, otp).
    %% io:format("~p~n", [RSAEntry]).



    Sign = public_key:sign(Message, HashAlgo, PrivateKey,
                    [{rsa_padding, rsa_pkcs1_pss_padding},
                     {rsa_pss_saltlen, -1},
                     {rsa_mgf1_md, HashAlgo}]),

    {ok, SigFile} = file:open("sig2.bin", [write, binary]),
    file:write(SigFile, Sign),
    file:close(SigFile),

    ok.

ecdsa() ->
    {ok, File} = file:open("test.bin", [read, binary]),
    {ok, Message} = file:read(File, 32),
    io:format("### Message: ~p~n", [Message]),

    {ok, PemBin} = file:read_file("server-ec.key"),

    [_Param, ECEntry] = public_key:pem_decode(PemBin),

    PrivateKey = public_key:pem_entry_decode(ECEntry),
    HashAlgo = sha256,

    %% public_key:pkix_decode_cert(Cert, otp).
    %% io:format("~p~n", [RSAEntry]).



    Sign = public_key:sign(Message, HashAlgo, PrivateKey, []),

    {ok, SigFile} = file:open("ecsig2.bin", [write, binary]),
    file:write(SigFile, Sign),
    file:close(SigFile),
    ok.

oldrsa() ->

    {ok, File} = file:open("test.bin", [read, binary]),
    {ok, Message} = file:read(File, 32),
    io:format("### Message: ~p~n", [Message]),

    {ok, PemBin} = file:read_file("server.key"),

    [RSAEntry] = public_key:pem_decode(PemBin),

    PrivateKey = public_key:pem_entry_decode(RSAEntry),
    HashAlgo = sha256,

    %% public_key:pkix_decode_cert(Cert, otp).
    %% io:format("~p~n", [RSAEntry]).


    Message1 = binary:copy(<<1>>, 32),
    Sign = public_key:sign(Message1, HashAlgo, PrivateKey, [{rsa_padding, rsa_pkcs1_padding}]),

    {ok, SigFile} = file:open("rsasig2.bin", [write, binary]),
    file:write(SigFile, Sign),
    file:close(SigFile),

    ok.


validate_key_share(_ ,[]) ->
    ok;
validate_key_share([], _) ->
    {error, illegal_parameter};
validate_key_share([G|ClientGroups], [{_, G, _}|ClientShares]) ->
    validate_key_share(ClientGroups, ClientShares);
validate_key_share([_|ClientGroups], [_|_] = ClientShares) ->
    validate_key_share(ClientGroups, ClientShares).


test_key_share() ->
    SG0 = [x25519,secp256r1,x448,secp521r1,secp384r1],
    KS0 = [{key_share_entry,x25519,
                    <<255,97,115,123,234,96,209,19,138,155,185,132,162,207,
                      33,55,142,80,253,188,200,46,227,148,15,84,132,9,15,
                      126,155,63>>}],
    ok = validate_key_share(SG0, KS0),

    SG1 = [secp256r1,x448,secp521r1,secp384r1],
    KS1 = [{key_share_entry,x25519,
                    <<255,97,115,123,234,96,209,19,138,155,185,132,162,207,
                      33,55,142,80,253,188,200,46,227,148,15,84,132,9,15,
                      126,155,63>>}],
    {error, illegal_parameter} = validate_key_share(SG1, KS1),

    SG2 = [secp256r1,x25519,x448,secp521r1,secp384r1],
    KS2 = [{key_share_entry,x25519,
                    <<255,97,115,123,234,96,209,19,138,155,185,132,162,207,
                      33,55,142,80,253,188,200,46,227,148,15,84,132,9,15,
                      126,155,63>>}],
    ok = validate_key_share(SG2, KS2),

    SG3 = [secp256r1,x25519,x448,secp521r1,secp384r1],
    KS3 = [{key_share_entry,x25519,
                    <<255,97,115,123,234,96,209,19,138,155,185,132,162,207,
                      33,55,142,80,253,188,200,46,227,148,15,84,132,9,15,
                      126,155,63>>}],
    ok = validate_key_share(SG3, KS3),

    SG4 = [secp256r1,x448,secp521r1,secp384r1],
    KS4 = [{key_share_entry,x25519,
                    <<255,97,115,123,234,96,209,19,138,155,185,132,162,207,
                      33,55,142,80,253,188,200,46,227,148,15,84,132,9,15,
                      126,155,63>>}],
    {error, illegal_parameter} = validate_key_share(SG4, KS4),

    SG5 = [x25519,secp256r1,x448,secp521r1,secp384r1],
    KS5 = [{key_share_entry,x448,<<>>},
           {key_share_entry,x25519,
            <<255,97,115,123,234,96,209,19,138,155,185,132,162,207,
              33,55,142,80,253,188,200,46,227,148,15,84,132,9,15,
              126,155,63>>}],
    {error, illegal_parameter} = validate_key_share(SG5, KS5),

    SG6 = [x25519,secp256r1,x448,secp521r1,secp384r1],
    KS6 = [{key_share_entry,x25519,<<>>},
           {key_share_entry,secp521r1,
            <<255,97,115,123,234,96,209,19,138,155,185,132,162,207,
              33,55,142,80,253,188,200,46,227,148,15,84,132,9,15,
              126,155,63>>}],
    ok = validate_key_share(SG6, KS6),



    ok.


select_common_groups(_, []) ->
    {error, {insufficient_security, no_suitable_groups}};
select_common_groups(ServerGroups, ClientGroups) ->
    Fun = fun(E) -> lists:member(E, ClientGroups) end,
    case lists:filter(Fun, ServerGroups) of
        [] ->
            {error, {insufficient_security, no_suitable_groups}};
        L ->
            {ok, L}
    end.


new_server() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, "tls_server_cert.pem"},
             {keyfile, "tls_server_key.pem"},
             {versions, ['tlsv1.2','tlsv1.3']},
             {cacertfile, "tls_server_cacerts.pem"},
             {verify, verify_peer},
             {fail_if_no_peer_cert, true},
             {log_level, debug}
            %% ,{ciphers,[{ecdhe_rsa,aes_256_cbc,sha}]}
],
    %% LOpts = [{certfile, "server.pem"}, {keyfile, "server.key"},{log_level, debug}],

    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, S} = ssl:handshake(CSock),
    S.



create_certs() ->
    ChainConf = #{peer =>
                      [{digest, sha256}, {key, rsa_key(1)}],
                  intermediates =>
                      [[{digest, sha256}, {key, rsa_key(2)}]],
                  root =>
                      [{digest, sha256}, {key, rsa_key(3)}]},
    TestDataConf =
        #{client_chain => ChainConf,
          server_chain => ChainConf},

    #{server_config := ServerData,
      client_config := ClientData} = public_key:pkix_test_data(TestDataConf),

    write_data(client, ClientData),
    write_data(server, ServerData).


write_data(Atom, Data) ->
    CAs = proplists:get_value(cacerts, Data),
    Cert = proplists:get_value(cert, Data),
    Key = proplists:get_value(key, Data),

    der_to_pem("tls_" ++ atom_to_list(Atom) ++ "_cert.pem", [cert_entry(Cert)]),
    der_to_pem("tls_" ++ atom_to_list(Atom) ++ "_key.pem", [key_entry(Key)]),
    der_to_pem("tls_" ++ atom_to_list(Atom) ++ "_cacerts.pem", ca_entries(CAs)).

der_to_pem(File, Entries) ->
    PemBin = public_key:pem_encode(Entries),
    file:write_file(File, PemBin).


cert_entry(Cert) ->
    {'Certificate', Cert, not_encrypted}.

key_entry({'RSAPrivateKey', DERKey}) ->
    {'RSAPrivateKey', DERKey, not_encrypted};
key_entry({'DSAPrivateKey', DERKey}) ->
    {'DSAPrivateKey', DERKey, not_encrypted};
key_entry({'ECPrivateKey', DERKey}) ->
    {'ECPrivateKey', DERKey, not_encrypted}.

ca_entries(CAs) ->
    [{'Certificate', CACert, not_encrypted} || CACert <- CAs].


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Hardcoded Keys
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

rsa_key(1) ->
    #'RSAPrivateKey'{
       version = 'two-prime',
       modulus = 23995666614853919027835084074500048897452890537492185072956789802729257783422306095699263934587064480357348855732149402060270996295002843755712064937715826848741191927820899197493902093529581182351132392364214171173881547273475904587683433713767834856230531387991145055273426806331200574039205571401702219159773947658558490957010003143162250693492642996408861265758000254664396313741422909188635443907373976005987612936763564996605457102336549804831742940035613780926178523017685712710473543251580072875247250504243621640157403744718833162626193206685233710319205099867303242759099560438381385658382486042995679707669,
       publicExponent = 17,
       privateExponent = 11292078406990079542510627799764728892919007311761028269626724613049062486316379339152594792746853873109340637991599718616598115903530750002688030558925094987642913848386305504703012749896273497577003478759630198199473669305165131570674557041773098755873191241407597673069847908861741446606684974777271632545629600685952292605647052193819136445675100211504432575554351515262198132231537860917084269870590492135731720141577986787033006338680118008484613510063003323516659048210893001173583018220214626635609151105287049126443102976056146630518124476470236027123782297108342869049542023328584384300970694412006494684657,
       prime1 = 169371138592582642967021557955633494538845517070305333860805485424261447791289944610138334410987654265476540480228705481960508520379619587635662291973699651583489223555422528867090299996446070521801757353675026048850480903160224210802452555900007597342687137394192939372218903554801584969667104937092080815197,
       prime2 = 141675062317286527042995673340952251894209529891636708844197799307963834958115010129693036021381525952081167155681637592199810112261679449166276939178032066869788822014115556349519329537177920752776047051833616197615329017439297361972726138285974555338480581117881706656603857310337984049152655480389797687577,
       exponent1 = 119556097830058336212015217380447172615655659108450823901745048534772786676204666783627059584226579481512852103690850928442711896738555003036938088452023283470698275450886490965004917644550167427154181661417665446247398284583687678213495921811770068712485038160606780733330990744565824684470897602653233516609,
       exponent2 = 41669135975672507953822256864985956439473391144599032012999352737636422046504414744027363535700448809435637398729893409470532385959317485048904982111185902020526124121798693043976273393287623750816484427009887116945685005129205106462566511260580751570141347387612266663707016855981760014456663376585234613993,
       coefficient = 76837684977089699359024365285678488693966186052769523357232308621548155587515525857011429902602352279058920284048929101483304120686557782043616693940283344235057989514310975192908256494992960578961614059245280827077951132083993754797053182279229469590276271658395444955906108899267024101096069475145863928441,
       otherPrimeInfos = asn1_NOVALUE};

rsa_key(2) ->
    #'RSAPrivateKey'{
       version = 'two-prime',
       modulus = 21343679768589700771839799834197557895311746244621307033143551583788179817796325695589283169969489517156931770973490560582341832744966317712674900833543896521418422508485833901274928542544381247956820115082240721897193055368570146764204557110415281995205343662628196075590438954399631753508888358737971039058298703003743872818150364935790613286541190842600031570570099801682794056444451081563070538409720109449780410837763602317050353477918147758267825417201591905091231778937606362076129350476690460157227101296599527319242747999737801698427160817755293383890373574621116766934110792127739174475029121017282777887777,
       publicExponent = 17,
       privateExponent = 18832658619343853622211588088997845201745658451136447382185486691577805721584993260814073385267196632785528033211903435807948675951440868570007265441362261636545666919252206383477878125774454042314841278013741813438699754736973658909592256273895837054592950290554290654932740253882028017801960316533503857992358685308186680144968293076156011747178275038098868263178095174694099811498968993700538293188879611375604635940554394589807673542938082281934965292051746326331046224291377703201248790910007232374006151098976879987912446997911775904329728563222485791845480864283470332826504617837402078265424772379987120023773,
       prime1 = 146807662748886761089048448970170315054939768171908279335181627815919052012991509112344782731265837727551849787333310044397991034789843793140419387740928103541736452627413492093463231242466386868459637115999163097726153692593711599245170083315894262154838974616739452594203727376460632750934355508361223110419,
       prime2 = 145385325050081892763917667176962991350872697916072592966410309213561884732628046256782356731057378829876640317801978404203665761131810712267778698468684631707642938779964806354584156202882543264893826268426566901882487709510744074274965029453915224310656287149777603803201831202222853023280023478269485417083,
       exponent1 = 51814469205489445090252393754177758254684624060673510353593515699736136004585238510239335081623236845018299924941168250963996835808180162284853901555621683602965806809675350150634081614988136541809283687999704622726877773856604093851236499993845033701707873394143336209718962603456693912094478414715725803677,
       exponent2 = 51312467664734785681382706062457526359131540440966797517556579722433606376221663384746714140373192528191755406283051201483646739222992016094510128871300458249756331334105225772206172777487956446433115153562317730076172132768497908567634716277852432109643395464627389577600646306666889302334125933506877206029,
       coefficient = 30504662229874176232343608562807118278893368758027179776313787938167236952567905398252901545019583024374163153775359371298239336609182249464886717948407152570850677549297935773605431024166978281486607154204888016179709037883348099374995148481968169438302456074511782717758301581202874062062542434218011141540,
       otherPrimeInfos = asn1_NOVALUE};

rsa_key(3) ->
    #'RSAPrivateKey'{
       version = 'two-prime',
       modulus = 25089040456112869869472694987833070928503703615633809313972554887193090845137746668197820419383804666271752525807484521370419854590682661809972833718476098189250708650325307850184923546875260207894844301992963978994451844985784504212035958130279304082438876764367292331581532569155681984449177635856426023931875082020262146075451989132180409962870105455517050416234175675478291534563995772675388370042873175344937421148321291640477650173765084699931690748536036544188863178325887393475703801759010864779559318631816411493486934507417755306337476945299570726975433250753415110141783026008347194577506976486290259135429,
       publicExponent = 17,
       privateExponent = 8854955455098659953931539407470495621824836570223697404931489960185796768872145882893348383311931058684147950284994536954265831032005645344696294253579799360912014817761873358888796545955974191021709753644575521998041827642041589721895044045980930852625485916835514940558187965584358347452650930302268008446431977397918214293502821599497633970075862760001650736520566952260001423171553461362588848929781360590057040212831994258783694027013289053834376791974167294527043946669963760259975273650548116897900664646809242902841107022557239712438496384819445301703021164043324282687280801738470244471443835900160721870265,
       prime1 = 171641816401041100605063917111691927706183918906535463031548413586331728772311589438043965564336865070070922328258143588739626712299625805650832695450270566547004154065267940032684307994238248203186986569945677705100224518137694769557564475390859269797990555863306972197736879644001860925483629009305104925823,
       prime2 =146170909759497809922264016492088453282310383272504533061020897155289106805616042710009332510822455269704884883705830985184223718261139908416790475825625309815234508695722132706422885088219618698987115562577878897003573425367881351537506046253616435685549396767356003663417208105346307649599145759863108910523,
       exponent1 = 60579464612132153154728441333538327425711971378777222246428851853999433684345266860486105493295364142377972586444050678378691780811632637288529186629507258781295583787741625893888579292084087601124818789392592131211843947578009918667375697196773859928702549128225990187436545756706539150170692591519448797349,
       exponent2 = 137572620950115585809189662580789132500998007785886619351549079675566218169991569609420548245479957900898715184664311515467504676010484619686391036071176762179044243478326713135456833024206699951987873470661533079532774988581535389682358631768109586527575902839864474036157372334443583670210960715165278974609,
       coefficient = 15068630434698373319269196003209754243798959461311186548759287649485250508074064775263867418602372588394608558985183294561315208336731894947137343239541687540387209051236354318837334154993136528453613256169847839789803932725339395739618592522865156272771578671216082079933457043120923342632744996962853951612,
       otherPrimeInfos = asn1_NOVALUE}.


test_chacha() ->

    %% Plaintext:
    %% 000  4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c  Ladies and Gentl
    %% 016  65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73  emen of the clas
    %% 032  73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63  s of '99: If I c
    %% 048  6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f  ould offer you o
    %% 064  6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20  nly one tip for
    %% 080  74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73  the future, suns
    %% 096  63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69  creen would be i
    %% 112  74 2e                                            t.
    PlainText =
        hexstr2bin2("4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c
                     65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73
                     73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63
                     6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f
                     6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20
                     74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73
                     63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69
                     74 2e"),

    %%
    %%  AAD:
    %%  000  50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7              PQRS........
    AAD =
        hexstr2bin2("50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7"),

    %%
    %% Key:
    %% 000  80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f  ................
    %% 016  90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f  ................
    Key =
        hexstr2bin2("80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f
                     90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f"),

    %%
    %%  IV:
    %%  000  40 41 42 43 44 45 46 47                          @ABCDEFG
    IV =
        hexstr2bin2("40 41 42 43 44 45 46 47"),

    %%
    %%  32-bit fixed-common part:
    %%  000  07 00 00 00                                      ....
    Common =
        hexstr2bin2("07 00 00 00"),

    %%
    %%  Setup for generating Poly1305 one-time key (sender id=7):
    %%      61707865  3320646e  79622d32  6b206574
    %%      83828180  87868584  8b8a8988  8f8e8d8c
    %%      93929190  97969594  9b9a9998  9f9e9d9c
    %%      00000000  00000007  43424140  47464544
    %%
    %%  After generating Poly1305 one-time key:
    %%      252bac7b  af47b42d  557ab609  8455e9a4
    %%      73d6e10a  ebd97510  7875932a  ff53d53e
    %%      decc7ea2  b44ddbad  e49c17d1  d8430bc9
    %%      8c94b7bc  8b7d4b4b  3927f67d  1669a432
    %%
    %% Poly1305 Key:
    %% 000  7b ac 2b 25 2d b4 47 af 09 b6 7a 55 a4 e9 55 84  {.+%-.G...zU..U.
    %% 016  0a e1 d6 73 10 75 d9 eb 2a 93 75 78 3e d5 53 ff  ...s.u..*.ux>.S.
    %%
    %% Poly1305 r =  455e9a4057ab6080f47b42c052bac7b
    %% Poly1305 s = ff53d53e7875932aebd9751073d6e10a
    %%
    %%  keystream bytes:
    %%  9f:7b:e9:5d:01:fd:40:ba:15:e2:8f:fb:36:81:0a:ae:
    %%  c1:c0:88:3f:09:01:6e:de:dd:8a:d0:87:55:82:03:a5:
    %%  4e:9e:cb:38:ac:8e:5e:2b:b8:da:b2:0f:fa:db:52:e8:
    %%  75:04:b2:6e:be:69:6d:4f:60:a4:85:cf:11:b8:1b:59:
    %%  fc:b1:c4:5f:42:19:ee:ac:ec:6a:de:c3:4e:66:69:78:
    %%  8e:db:41:c4:9c:a3:01:e1:27:e0:ac:ab:3b:44:b9:cf:
    %%  5c:86:bb:95:e0:6b:0d:f2:90:1a:b6:45:e4:ab:e6:22:
    %%  15:38
    %%
    %% Ciphertext:
    %% 000  d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2  ...4d.`.{...S.~.
    %% 016  a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6  ...Q)n......6.b.
    %% 032  3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b  =..^..g....i..r.
    %% 048  1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36  .q.....)....~.;6
    %% 064  92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58  ....-w......(..X
    %% 080  fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc  ..$...u.U...H1..
    %% 096  3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b  ?....Kz..v.e...K
    %% 112  61 16                                            a.
    CipherText =
        hexstr2bin2("d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2
                     a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6
                     3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b
                     1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36
                     92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58
                     fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc
                     3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b
                     61 16"),

    %%
    %% AEAD Construction for Poly1305:
    %% 000  50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7 00 00 00 00  PQRS............
    %% 016  d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2  ...4d.`.{...S.~.
    %% 032  a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6  ...Q)n......6.b.
    %% 048  3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b  =..^..g....i..r.
    %% 064  1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36  .q.....)....~.;6
    %% 080  92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58  ....-w......(..X
    %% 096  fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc  ..$...u.U...H1..
    %% 112  3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b  ?....Kz..v.e...K
    %% 128  61 16 00 00 00 00 00 00 00 00 00 00 00 00 00 00  a...............
    %% 144  0c 00 00 00 00 00 00 00 72 00 00 00 00 00 00 00  ........r.......
    %%
    %%  Note the four zero bytes in line 000 and the 14 zero bytes in line
    %%  128
    %%
    %%  Tag:
    %%  1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91
    Tag =
        hexstr2bin2("1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb d0 60 06 91"),

    Nonce = <<Common/binary,IV/binary>>,
    erlang:display({nonce, Nonce}),
    erlang:display({key, Key}),
    erlang:display({aad, AAD}),
    erlang:display({plaintext, PlainText}),
    {CipherText, Tag} = crypto:block_encrypt(chacha20_poly1305, Key, Nonce, {AAD, PlainText, 16}).


test_formatter(Report) ->
    ssl_logger:format(#{level => debug,
                        msg => Report,
                        meta => #{}}, []).

maybe_truncate([B]) when is_binary(B) andalso
                       size(B) > 80 ->
    {H, _} = split_binary(B, 70),
    [<<H/binary,"-TRUNCATED">>];
maybe_truncate(V) ->
    V.

maybe_increase_buffers(Size, Opts) when Size >= 5000 ->
    case os:cmd("uname -mrs") of
        "OpenBSD " ++ _ ->
            [{rcvbuf, 65535}|Opts];
        "FreeBSD " ++ _ ->
            [{rcvbuf, 65535}|Opts];
        _ ->
            Opts
    end;
maybe_increase_buffers(_, Opts) ->
    Opts.


counter_prefix(Count0) ->
    Count = Count0 rem 100,
    counter_to_bin(Count).

counter_to_bin(Count) when Count < 10->
    <<0,Count>>;
counter_to_bin(Count) ->
    B = Count rem 10,
    A = (Count - B) div 10,
    <<A,B>>.





%% Receive Size bytes
ssl_echo_recv(Socket, 0) ->
    erlang_display({server, finished, ok}),
    ssl:close(Socket),
    ok;
ssl_echo_recv(Socket, Size) ->
    {ok, [SendBuf]} = ssl:getopts(Socket, [sndbuf]),
    {ok, [RecvBuf]} = ssl:getopts(Socket, [recbuf]),
    erlang_display({server,SendBuf,RecvBuf}),
    erlang_display({server, recv, Size}),
    {ok, Data} = ssl:recv(Socket, 0),
    erlang_display({server, send_echo, Size}),
    ok = ssl:send(Socket, Data),
    erlang_display({server, echo_sent, Size}),
    ssl_echo_recv(Socket, Size - byte_size(Data)).


ssl_send(Socket, _Data, 0, _) ->
    erlang_display({client, finished_sending, ok}),
    ssl:close(Socket),
    ok;
ssl_send(Socket, <<A,B,Data/binary>> = OrigData, Count, RecvEcho) ->
    {ok, [SendBuf]} = ssl:getopts(Socket, [sndbuf]),
    {ok, [RecvBuf]} = ssl:getopts(Socket, [recbuf]),
    erlang_display({client,SendBuf,RecvBuf}),
    C = counter_prefix(Count),
    erlang_display({client, send, Count, size, iolist_size( <<C/binary,Data/binary>>), data, C}),
    ok = ssl:send(Socket, <<C/binary,Data/binary>>),
    erlang_display({client, recv_echo, Count}),
    RecvEcho(),
    erlang_display({client, received_echo, Count}),
    ssl_send(Socket, OrigData, Count - 1, RecvEcho).

ssl_send_close(Socket, Data) ->
    ok = ssl:send(Socket, Data),
    ssl:close(Socket).

ssl_recv_disregard(_Socket, 0) ->
    ok;
ssl_recv_disregard(Socket, N) ->
    {ok, Bytes} = ssl:recv(Socket, 0),
    ssl_recv_disregard(Socket, N-byte_size(Bytes)).


echo_logger() ->
    process_flag(trap_exit, true),
    Pid = spawn_link(?MODULE, echo_logger_loop, []),
    register(echo_logger, Pid),
    io:format("\nEcho logger started\n").

echo_logger_loop() ->
    receive
        {log, Term} ->
            erlang:display(Term),
            echo_logger_loop()
    end.

erlang_display(Term) ->
    echo_logger ! {log, Term}.

echo_server() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    LOpts = [{certfile, "server.pem"},
             {keyfile, "server.key"},
             {mode, binary},
             {active, false},
             {versions, ['tlsv1.2']}
            %% , {log_level, debug}
             , {recbuf,1000}
            ],
    {ok, LSock} = ssl:listen(Port, LOpts),
    {ok, CSock} = ssl:transport_accept(LSock),
    {ok, Sock} = ssl:handshake(CSock),

    ssl_echo_recv(Sock, 500000 * 100).

echo_client() ->
    Data = binary:copy(<<"1234567890">>, 50000),
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [{verify, verify_peer},
             {cacertfile, "ca.pem"},
             {mode, binary},
             {active, false},
             {versions, ['tlsv1.2']}
            %% , {log_level, debug}
             ,{recbuf,1000}
            ],
    {ok, Sock} = ssl:connect("localhost", Port, COpts),

    ssl_send(Sock, Data, 100,
        fun() ->
                ssl_recv_disregard(Sock, byte_size(Data))
        end).

echo_client_theo() ->
    Data = binary:copy(<<"1234567890">>, 50000),
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [
             {cacertfile, "ca.pem"},
             {mode, binary},
             {active, false},
             {versions, ['tlsv1.2']}
            %% , {log_level, debug}
             ,{recbuf,1000}
            ],
    {ok, Sock} = ssl:connect("theo", Port, COpts),

    ssl_send(Sock, Data, 100,
        fun() ->
                ssl_recv_disregard(Sock, byte_size(Data))
        end).



%%% TCP TEST

%% Receive Size bytes
echo_recv(Socket, 0) ->
    erlang:display({server, finished, ok}),
    gen_tcp:close(Socket),
    ok;
echo_recv(Socket, Size) ->
    {ok, [SendBuf]} = inet:getopts(Socket, [sndbuf]),
    {ok, [RecvBuf]} = inet:getopts(Socket, [recbuf]),
    erlang:display({server,SendBuf,RecvBuf}),
    erlang:display({server, recv, Size}),
    {ok, Data} = gen_tcp:recv(Socket, 0),
    erlang:display({server, send_echo, Size}),
    ok = gen_tcp:send(Socket, Data),
    erlang:display({server, echo_sent, Size}),
    echo_recv(Socket, Size - byte_size(Data)).


send(Socket, _Data, 0, _) ->
    erlang:display({client, finished_sending, ok}),
    gen_tcp:close(Socket),
    ok;
send(Socket, Data, Count, RecvEcho) ->
    {ok, [SendBuf]} = inet:getopts(Socket, [sndbuf]),
    {ok, [RecvBuf]} = inet:getopts(Socket, [recbuf]),
    erlang:display({client,SendBuf,RecvBuf}),
    erlang:display({client, send, Count}),
    ok = gen_tcp:send(Socket, Data),
    erlang:display({client, recv_echo, Count}),
    RecvEcho(),
    erlang:display({client, received_echo, Count}),
    send(Socket, Data, Count - 1, RecvEcho).

send_close(Socket, Data) ->
    ok = gen_tcp:send(Socket, Data),
    gen_tcp:close(Socket).

recv_disregard(_Socket, 0) ->
    ok;
recv_disregard(Socket, N) ->
    {ok, Bytes} = gen_tcp:recv(Socket, 0),
    recv_disregard(Socket, N-byte_size(Bytes)).


tcp_server() ->
    {ok, LSock} = gen_tcp:listen(?PORT, [binary, {packet, 0},
                                         {active, false},{recbuf,4000}]),
    {ok, Sock} = gen_tcp:accept(LSock),
    echo_recv(Sock, 500000 * 100).

tcp_client() ->
    Data = binary:copy(<<"1234567890">>, 50000),
    {ok, Sock} = gen_tcp:connect(localhost, ?PORT,
                                 [binary, {packet, 0}, {active, false},{recbuf,4000}]),
    send(Sock, Data, 100,
        fun() ->
                recv_disregard(Sock, byte_size(Data))
        end).

fix_pcap(File) ->
    {ok, Device} = file:open(File, [read,write]),
    case file:read(Device, 1) of
        {ok, [16#D4]} ->
            erlang:display({first}),
            file:position(Device, 20);
        {ok, E} ->
            erlang:display({second,E}),
           file:position(Device, 23)
    end,
    ok = file:write(Device, [16#6C]),
    file:close(Device).



client_c() ->
    application:load(ssl),
    {ok, _} = application:ensure_all_started(ssl),
    Port = ?PORT,
    COpts = [
             {verify, verify_peer},
             {cacertfile, "ca.pem"},
             {versions, ['tlsv1.2']},
             {log_level, debug}


            ,{ciphers,[#{cipher => aes_128_cbc,key_exchange => dhe_psk,
                         mac => sha256,prf => default_prf}]},
             {psk_identity,"Test-User"},
             {user_lookup_fun,{fun ssl_test_lib:user_lookup/3,
                               <<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>}}


            %% ,{signature_algs, [{sha,rsa}]}
            %% ,{signature_algs_cert, [rsa_pkcs1_sha256,ecdsa_sha1]}
            %% ,{signature_algs_cert, [ecdsa_sha1]}
],
    %% COpts = [{verify, verify_peer}, {cacertfile, "ca.pem"},{versions, ['tlsv1.3']},{log_level, debug}],

    {ok, Sock} = ssl:connect("localhost", Port, COpts),
    Sock.

user_lookup(psk, _Identity, UserState) ->
    {ok, UserState};
user_lookup(srp, Username, _UserState) ->
    Salt = ssl_cipher:random_bytes(16),
    UserPassHash = crypto:hash(sha, [Salt, crypto:hash(sha, [Username, <<$:>>, <<"secret">>])]),
    {ok, {srp_1024, Salt, UserPassHash}}.


client_extensions() ->
    Map = #{a => 1, b => 2, c => undefined, d => 5},
    Fun = fun(_, undefined, Acc) ->
		  Acc;
	     (K, _, Acc) ->
		  [K|Acc]
	  end,
    maps:fold(Fun, [], Map).
