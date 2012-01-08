%% Copyright (c) 2011, Magnus Klaar <magnus.klaar@gmail.com>
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-module(cowboy_static_hdrs).

%% include files
-include_lib("cowboy/include/http.hrl").

%% range header functions
-export([get_range/1,
         parse_range/2,
         make_range/3,
         make_range/2]).

%% location header functions
-export([make_location/1]).

-type uint() :: non_neg_integer().


%% @doc Get the range requested by a client.
%% This function will return the raw value of the Range header. The parse_range
%% function must be used to convert this into a usable form.
%% @end
-spec get_range(T) -> {boolean(), T}.
get_range(Req) ->
    cowboy_http_req:header(<<"Range">>, Req).


%% @doc Make a Content-Range header with a known Content-Length.
%% The content range header is included in 206 (Partial Content) responses
%% and indicates which byte range is sent in the response. The content range
%% header also includes the content length of the resource to aid clients
%% making subsequent requests.
%% @end
-spec make_range(uint(), uint(), uint()) -> {binary(), binary()}.
make_range(Start, End, ContentLength) ->
    SStr = integer_to_list(Start),
    EStr = integer_to_list(End),
    LStr = integer_to_list(ContentLength),
    HVal = iolist_to_binary([<<"bytes ">>, SStr, $-, EStr, $/, LStr]),
    {<<"Content-Range">>, HVal}.


%% @doc Make a Content-Range header with an unknown Content-Length.
%% This is equivalent to make_range/2. The total content range is replaced
%% with an asterix (*) to indicate that the total content is unknown.
%% @end
-spec make_range(uint(), uint()) -> {binary(), binary()}.
make_range(Start, End) ->
    SStr = integer_to_list(Start),
    EStr = integer_to_list(End),
    HVal = iolist_to_binary([<<"bytes ">>, SStr, $-, EStr, $/, $*]),
    {<<"Content-Range">>, HVal}.


%% @private Convert a binary to an integr. Return error on invalid input.
-spec binary_to_integer(binary()) -> non_neg_integer().
binary_to_integer(<<>>) ->
    none;
binary_to_integer(Bin) ->
    Str = binary_to_list(Bin),
    case string:to_integer(Str) of
        {error, _Reason} -> error;
        {Integer, ""} -> Integer;
        {_Integer, _} -> error
    end.

%% @doc Return the value of the Location header in a 301 response.
%% @end
-spec make_location(#http_req{}) -> {binary(), #http_req{}}.
make_location(Req0) ->
    #http_req{transport=Transport} = Req0,
    Protocol = Transport:name(),
    %% @todo If we are running behind a proxy this is not a
    %% reliable mechanism to determine if the client connects
    %% using an http or https connection. likely downgrade.
    Scheme = case Protocol of
        tcp -> <<"http://">>;
        ssl -> <<"https://">>
    end,
    {Port, Req1} = cowboy_http_req:port(Req0),
    PortStr = case Scheme of
        <<"http://">> when Port =:= 80 -> <<>>;
        <<"https://">> when Port =:= 443 -> <<>>;
        <<"http://">> -> [$:|integer_to_list(Port)];
        <<"https://">> -> [$:|integer_to_list(Port)]
    end,
    {RawHost, Req2} = cowboy_http_req:raw_host(Req1),
    {RawPath, Req3} = cowboy_http_req:raw_path(Req2),
    {RawQS, Req4} = cowboy_http_req:raw_qs(Req3),
    QueryStr = case RawQS of
        <<>> -> <<>>;
        _ -> [$?|RawQS]
    end,
    RedirectURL = iolist_to_binary([
        Scheme, RawHost, PortStr, RawPath, $/, QueryStr]),
    {RedirectURL, Req4}.


-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

rfc2615_examples_test_() ->
    P = fun(Bin) -> parse_range(Bin, 10000) end,
    [?_assertEqual([{0, 499, 500}], P(<<"bytes=0-499">>)),
     ?_assertEqual([{500, 999, 500}], P(<<"bytes=500-999">>)),
     ?_assertEqual([{9500,9999, 500}], P(<<"bytes=-500">>)),
     ?_assertEqual([{9500,9999, 500}], P(<<"bytes=9500-">>)),
     ?_assertEqual([{0, 0, 1}], P(<<"bytes=0-0">>)),
     ?_assertEqual([{9999,9999,1}], P(<<"bytes=-1">>)),
     ?_assertEqual([{0, 0, 1}, {9999, 9999, 1}], P(<<"bytes=0-0,-1">>)),
     ?_assertEqual(
        [{500, 600,101},{601,999,399}], P(<<"bytes=500-600,601-999">>)),
     ?_assertEqual(
        [{500,700,201},{601,999,399}], P(<<"bytes=500-700,601-999">>)),
     ?_assertEqual(error, P(<<"notbytes=1-2">>)),
     ?_assertEqual(error, P(<<"bytes=10000-">>)),
     ?_assertEqual(error, P(<<"bytes=-">>)),
     ?_assertEqual(error, P(<<"bytes=2-1">>)),
     ?_assertEqual(error, P(<<"bytes=1-b">>)),
     ?_assertEqual(error, P(<<"bytes=a-2">>))
    ].

range_header_test_() ->
    Name = <<"Content-Range">>,
    [?_assertEqual({Name, <<"bytes 0-0/2">>}, make_range(0, 0, 2)),
     ?_assertEqual({Name, <<"bytes 1-3/4">>}, make_range(1, 3, 4)),
     ?_assertEqual({Name, <<"bytes 0-4/*">>}, make_range(0, 4))
    ].

-endif.
