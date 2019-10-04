-module(rectest).
-compile(export_all).
-record(ssl_options, {
	  protocol    :: tls | dtls | 'undefined',
	  versions    :: [ssl_record:ssl_version()] | 'undefined' %% ssl_record:atom_version() in API
		     }).

test() ->
    R = #ssl_options{protocol = tls},
    %% record_info(fields, ssl_options).
    Fields = record_info(fields, ssl_options),
    erlang:display({fields,Fields}),
    [_Tag| Values] = tuple_to_list(R),
    L = lists:zip(Fields, Values),
    maps:from_list(L).


test2() ->
    ok.

test3() ->
    Map = #{hello => world, foo => bar},
    erlang:display(Map),
    Map.


test4() ->
    test4([{hello, world}, {foo, bar}], #{}).
%%
test4([], Map) ->
    erlang:display(Map),
    Map;
test4([{K,V}|T], Map) ->
    test4(T, Map#{K => V}).

test5() ->
    M1 = #{sni_hosts => [],renegotiate_at => 268435456,
	   psk_identity => undefined,hibernate_after => infinity,
	   signature_algs =>
	       [ecdsa_secp521r1_sha512,ecdsa_secp384r1_sha384,
		ecdsa_secp256r1_sha256,rsa_pss_pss_sha512,
		rsa_pss_pss_sha384,rsa_pss_pss_sha256,
		rsa_pss_rsae_sha512,rsa_pss_rsae_sha384,
		rsa_pss_rsae_sha256,rsa_pkcs1_sha512,rsa_pkcs1_sha384,
		rsa_pkcs1_sha256,ecdsa_sha1,rsa_pkcs1_sha1,
		{sha512,ecdsa},
		{sha512,rsa},
		{sha384,ecdsa},
		{sha384,rsa},
		{sha256,ecdsa},
		{sha256,rsa},
		{sha224,ecdsa},
		{sha224,rsa},
		{sha,ecdsa},
		{sha,rsa},
		{sha,dsa}],
	   server_name_indication => undefined,
	   signature_algs_cert => undefined,
	   eccs =>
	       {elliptic_curves,[{1,3,132,0,39},
				 {1,3,132,0,38},
				 {1,3,132,0,35},
				 {1,3,36,3,3,2,8,1,1,13},
				 {1,3,132,0,36},
				 {1,3,132,0,37},
				 {1,3,36,3,3,2,8,1,1,11},
				 {1,3,132,0,34},
				 {1,3,132,0,16},
				 {1,3,132,0,17},
				 {1,3,36,3,3,2,8,1,1,7},
				 {1,3,132,0,10},
				 {1,2,840,10045,3,1,7},
				 {1,3,132,0,3},
				 {1,3,132,0,26},
				 {1,3,132,0,27},
				 {1,3,132,0,32},
				 {1,3,132,0,33},
				 {1,3,132,0,24},
				 {1,3,132,0,25},
				 {1,3,132,0,31},
				 {1,2,840,10045,3,1,1},
				 {1,3,132,0,1},
				 {1,3,132,0,2},
				 {1,3,132,0,15},
				 {1,3,132,0,9},
				 {1,3,132,0,8},
				 {1,3,132,0,30}]},
	   beast_mitigation => one_n_minus_one,sni_fun => undefined,
	   key => undefined,customize_hostname_check => [],
	   crl_cache => {ssl_crl_cache,{internal,[]}},
	   reuse_session => undefined_fun,dhfile => undefined,
	   password => [],handshake => full,
	   max_handshake_size => 262144,fallback => undefined,
	   supported_groups =>
	       {supported_groups,[x25519,x448,secp256r1,secp384r1]},
	   dh => undefined,keyfile => <<"certs/server.pem">>,
	   srp_identity => undefined,erl_dist => false,
	   next_protocol_selector => undefined,padding_check => true,
	   crl_check => false,alpn_preferred_protocols => undefined,
	   client_renegotiation => true,honor_ecc_order => false,
	   ciphers =>
	       [<<19,2>>,
		<<19,1>>,
		<<19,3>>,
		<<19,4>>,
		<<"À,">>,<<"À0">>,<<"À$">>,<<"À(">>,<<"À.">>,<<"À2">>,
		<<"À&">>,<<"À*">>,
		<<0,159>>,
		<<0,163>>,
		<<0,107>>,
		<<0,106>>,
		<<"À+">>,<<"À/">>,<<"À#">>,<<"À'">>,<<"À-">>,<<"À1">>,
		<<"À%">>,<<"À)">>,
		<<0,158>>,
		<<0,162>>,
		<<0,103>>,
		<<0,64>>,
		<<"À\n">>,
		<<192,20>>,
		<<0,57>>,
		<<0,56>>,
		<<192,5>>,
		<<192,15>>,
		<<"À\t">>,
		<<192,19>>,
		<<0,51>>,
		<<0,50>>,
		<<192,4>>,
		<<192,14>>],
	   reuse_sessions => true,cert => undefined,
	   alpn_advertised_protocols => undefined,
	   honor_cipher_order => false,depth => 1,
	   secure_renegotiate => true,user_lookup_fun => undefined,
	   next_protocols_advertised => undefined},
    M2 = #{sni_hosts => undefined,renegotiate_at => undefined,
	   versions => [{3,4},{3,3}],
	   psk_identity => undefined,hibernate_after => undefined,
	   signature_algs => undefined,
	   server_name_indication => undefined,
	   signature_algs_cert => undefined,eccs => undefined,
	   cacertfile => <<>>,beast_mitigation => one_n_minus_one,
	   sni_fun => undefined,log_level => notice,key => undefined,
	   cacerts => undefined,customize_hostname_check => undefined,
	   crl_cache => undefined,reuse_session => undefined,
	   protocol => tls,dhfile => undefined,
	   verify_fun => {some_fun,[]},
	   password => undefined,handshake => undefined,
	   verify_client_once => false,max_handshake_size => undefined,
	   fallback => false,supported_groups => undefined,
	   dh => undefined,keyfile => <<"certs/server.key">>,
	   srp_identity => undefined,erl_dist => false,
	   next_protocol_selector => undefined,padding_check => true,
	   crl_check => undefined,alpn_preferred_protocols => undefined,
	   client_renegotiation => undefined,
	   honor_ecc_order => undefined,ciphers => undefined,
	   reuse_sessions => undefined,cert => undefined,
	   fail_if_no_peer_cert => false,
	   alpn_advertised_protocols => undefined,
	   validate_extensions_fun => undefined,
	   honor_cipher_order => false,depth => undefined,
	   certfile => <<"certs/server.pem">>,verify => verify_none,
	   secure_renegotiate => undefined,user_lookup_fun => undefined,
	   partial_chain => some_fun,
	   next_protocols_advertised => undefined},
    maps:merge(M1,M2).


ssl_options_list(SslOptions) ->
    Fileds = record_info(fields, ssl_options),
    Values = tl(tuple_to_list(SslOptions)),
    ssl_options_list(Fileds, Values, []).

ssl_options_list([],[], Acc) ->
    lists:reverse(Acc);
%% Skip internal options, only return user options
ssl_options_list([protocol | Keys], [_ | Values], Acc) ->
    ssl_options_list(Keys, Values, Acc);
ssl_options_list([erl_dist | Keys], [_ | Values], Acc) ->
    ssl_options_list(Keys, Values, Acc);
ssl_options_list([renegotiate_at | Keys], [_ | Values], Acc) ->
    ssl_options_list(Keys, Values, Acc);
ssl_options_list([ciphers = Key | Keys], [Value | Values], Acc) ->
   ssl_options_list(Keys, Values,
		    [{Key, lists:map(
			     fun(Suite) ->
				     ssl_cipher_format:suite_bin_to_map(Suite)
			     end, Value)}
		     | Acc]);
ssl_options_list([Key | Keys], [Value | Values], Acc) ->
   ssl_options_list(Keys, Values, [{Key, Value} | Acc]).


-record(ssl_options1, {
	  protocol    :: tls | dtls | 'undefined',
	  versions    :: [ssl_record:ssl_version()] | 'undefined', %% ssl_record:atom_version() in API
	  verify      :: verify_none | verify_peer | 'undefined',
	  verify_fun,  %%:: fun(CertVerifyErrors::term()) -> boolean(),
	  partial_chain       :: fun() | 'undefined',
	  fail_if_no_peer_cert ::  boolean() | 'undefined',
	  verify_client_once   ::  boolean() | 'undefined',
	  %% fun(Extensions, State, Verify, AccError) ->  {Extensions, State, AccError}
	  validate_extensions_fun,
	  depth                :: integer() | 'undefined',
	  certfile             :: binary() | 'undefined',
	  cert                ,
	  keyfile              :: binary() | 'undefined',
	  key	               ,
	  password	       ,
	  cacerts              ,
	  cacertfile           :: binary() | 'undefined',
	  dh                   ,
	  dhfile             ,
	  user_lookup_fun,  % server option, fun to lookup the user
	  psk_identity      ,
	  srp_identity,  % client option {User, Password}
	  ciphers,    %
	  %% Local policy for the server if it want's to reuse the session
	  %% or not. Defaluts to allways returning true.
	  %% fun(SessionId, PeerCert, Compression, CipherSuite) -> boolean()
	  reuse_session        :: fun() | binary() | undefined, %% Server side is a fun()
	  %% If false sessions will never be reused, if true they
	  %% will be reused if possible.
	  reuse_sessions       :: boolean() | save | 'undefined',  %% Only client side can use value save
	  renegotiate_at,
	  secure_renegotiate,
	  client_renegotiation,
	  %% undefined if not hibernating, or number of ms of
	  %% inactivity after which ssl_connection will go into
	  %% hibernation
	  hibernate_after      :: timeout() | 'undefined',
	  %% This option should only be set to true by inet_tls_dist
	  erl_dist = false     :: boolean(),
          alpn_advertised_protocols = undefined :: [binary()] | undefined,
          alpn_preferred_protocols = undefined  :: [binary()] | undefined,
	  next_protocols_advertised = undefined :: [binary()] | undefined,
	  next_protocol_selector = undefined,  %% fun([binary()]) -> binary())
	  log_level = notice :: atom(),
	  server_name_indication = undefined,
	  sni_hosts  :: [{inet:hostname(), [tuple()]}] | 'undefined',
	  sni_fun :: function() | undefined,
	  %% Should the server prefer its own cipher order over the one provided by
	  %% the client?
	  honor_cipher_order = false :: boolean(),
	  padding_check = true       :: boolean(),
	  %%Should we use 1/n-1 or 0/n splitting to mitigate BEAST, or disable
	  %%mitigation entirely?
	  beast_mitigation = one_n_minus_one :: one_n_minus_one | zero_n | disabled,
	  fallback = false           :: boolean(),
	  crl_check                  :: boolean() | peer | best_effort | 'undefined',
	  crl_cache,
	  signature_algs,
	  signature_algs_cert,
	  eccs,
	  supported_groups,  %% RFC 8422, RFC 8446
	  honor_ecc_order            :: boolean() | 'undefined',
          max_handshake_size         :: integer() | 'undefined',
          handshake,
          customize_hostname_check
    %%                 ,
      %%    save_session               :: boolean()
         }).
-define(SSL_OPTIONS, record_info(fields, ssl_options1)).

test6() ->
    A = sets:from_list(?SSL_OPTIONS),
    B = sets:from_list(
	  [protocol, versions, verify, verify_fun, partial_chain,
	   fail_if_no_peer_cert, verify_client_once,
	   depth, cert, certfile, key, keyfile,
	   password, cacerts, cacertfile, dh, dhfile,
	   user_lookup_fun, psk_identity, srp_identity, ciphers,
	   reuse_session, reuse_sessions, ssl_imp, client_renegotiation,
	   cb_info, renegotiate_at, secure_renegotiate, hibernate_after,
	   erl_dist, alpn_advertised_protocols, sni_hosts, sni_fun,
	   alpn_preferred_protocols, next_protocols_advertised,
	   client_preferred_next_protocols, log_alert, log_level,
	   server_name_indication, honor_cipher_order, padding_check, crl_check, crl_cache,
	   fallback, signature_algs, signature_algs_cert, eccs, honor_ecc_order,
	   beast_mitigation, max_handshake_size, handshake, customize_hostname_check,
	   supported_groups]),
    erlang:display({a, sets:to_list(sets:subtract(A,B))}),
    erlang:display({b, sets:to_list(sets:subtract(B,A))}).
