-module(ticket).
-compile(export_all).

-record(new_session_ticket, {
          ticket_lifetime,  %unit32
          ticket_age_add,   %unit32
          ticket_nonce,     %opaque ticket_nonce<0..255>;
          ticket,           %opaque ticket<1..2^16-1>
          extensions        %extensions<0..2^16-2>
         }).

get_offered_psks(UseTicket) ->
    [{Key, HKDF, SNI, RMS, Timestamp, NewSessionTicket}] = ets:lookup(tls13_session_ticket_db, UseTicket),
    #new_session_ticket{
       ticket_lifetime = LifeTime,
       ticket_age_add = AgeAdd,
       ticket_nonce = Nonce,
       ticket = Ticket,
       extensions = Extensions
      } = NewSessionTicket,

    TicketAge = gregorian_seconds() - Timestamp,
    ObfuscatedTicketAge = obfuscate_ticket_age(TicketAge, AgeAdd),
    {Ticket, AgeAdd}.

%% The "obfuscated_ticket_age"
%% field of each PskIdentity contains an obfuscated version of the
%% ticket age formed by taking the age in milliseconds and adding the
%% "ticket_age_add" value that was included with the ticket
%% (see Section 4.6.1), modulo 2^32.
obfuscate_ticket_age(TicketAge, AgeAdd) ->
    (TicketAge * 1000 + AgeAdd) rem round(math:pow(2,32)).


gregorian_seconds() ->
    calendar:datetime_to_gregorian_seconds(calendar:now_to_datetime(erlang:timestamp())).


store_ticket() ->
    Key = <<187,86,251,97,101,197,211,219,234,200,96,43,51,119,194,159,237,150,135,89,64,50,78,251,26,157,224,21,17,106,240,32>>,
    HKDF = sha384,
    SNI = "localhost",
    RMS = <<68,161,131,44,64,72,26,147,244,74,194,137,86,226,18,183,40,15,16,185,37,68,162,251,186,148,230,142,188,207,223,6,154,1,167,95,18,174,92,218,92,222,200,9,211,60,196,61>>,
    Timestamp = 63736122721,
    NewSessionTicket = {new_session_ticket,7200,1116323279,<<0,0,0,0,0,0,0,0>>,<<103,247,68,168,149,156,108,226,6,84,195,237,60,152,221,107,240,163,41,223,109,185,105,133,175,23,212,226,247,191,125,40,193,196,48,234,32,228,137,95,244,202,14,30,69,160,40,46,209,163,176,210,33,115,66,2,182,216,252,246,83,30,160,138,60,105,40,145,82,195,83,65,244,222,182,43,238,252,29,97,15,53,68,200,146,222,52,182,14,25,91,10,77,135,25,65,8,39,3,172,80,163,122,12,170,96,2,254,85,138,254,141,240,192,91,97,235,2,0,82,133,184,198,131,162,211,229,66,224,202,32,38,250,154,82,20,116,4,217,38,95,71,146,22,9,246,191,125,60,220,79,73,89,248,56,126,52,78,86,250,101,217,130,189,104,24,100,176,230,154,197,7,130,75,57,219,80,66,61,246,8,251,66,214,67,196,201,96,73,161,196,235>>,#{}},

    _TicketDb =
        case ets:whereis(tls13_session_ticket_db) of
            undefined ->
                ets:new(tls13_session_ticket_db, [public, named_table, ordered_set]);
            Tid ->
                Tid
        end,
    ets:insert(tls13_session_ticket_db, {Key, HKDF, SNI, RMS, Timestamp, NewSessionTicket}).

read() ->
    Key = <<187,86,251,97,101,197,211,219,234,200,96,43,51,119,194,159,237,150,135,89,64,50,78,251,26,157,224,21,17,106,240,32>>,
     ets:lookup(tls13_session_ticket_db, Key).
