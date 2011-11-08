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

-module(cowboy_static).
-behaviour(cowboy_http_handler).

%% include files
-include_lib("kernel/include/file.hrl").
-include_lib("cowboy/include/http.hrl").

%% exported functions
-export([rule/1]).

%% cowboy callbacks
-export([init/3, handle/2, terminate/2]).

%% type aliases
-type uint() :: non_neg_integer().
-type cache_handle() :: cowboy_static_cache:handle().

%% handler config
-record(conf, {
    dir      :: [binary()],
    prefix   :: [binary()],
    csize    :: pos_integer(),
    ranges   :: boolean(),
    usesfile :: boolean(),
    mimemod  :: atom(),
    mimearg  :: term(),
    chandle  :: cache_handle()}).

%% handler state
-record(state, {
    method  :: 'GET' | 'HEAD',
    path    :: [binary()],
    finfo   :: #file_info{},
    fname   :: binary(),
    ctype   :: binary(),
    ranges  :: [{uint(), uint(), uint()}],
    filemod :: atom(),
    filearg :: term()}).

-type option()
   :: {prefix, [binary()]}
    | {chunk_size, pos_integer()}
    | {ranges, boolean()}
    | {sendfile, boolean()}
    | {mimetypes, atom(), term()}.

%% @doc Return a cowboy dispatch rule.
%% @end
-spec rule([option()]) -> term().
rule(Opts) ->
    is_list(Opts) orelse erlang:error({badarg, option_list_required}),

    {_, Dir} = lists:keyfind(dir, 1, Opts),
    Dir1 = path_to_segments(Dir),
    Size = case lists:keyfind(chunk_size, 1, Opts) of
        {_, ISize} -> ISize;
        false -> 10240
    end,
    Prefix1 = case lists:keyfind(prefix, 1, Opts) of
        {_, Prefix} -> path_to_segments(Prefix);
        false -> []
    end,
    Ranges = case lists:keyfind(ranges, 1, Opts) of
        {_, IRanges} -> IRanges;
        false -> true
    end,
    Sendfile1 = case lists:keyfind(sendfile, 1, Opts) of
        {_, Sendfile} -> detect_sendfile(Sendfile);
        false -> true
    end,
    {MimeMod, MimeArg} = case lists:keyfind(mimetypes, 1, Opts) of
        {_, IMimeMod, IMimeArg} -> {IMimeMod, IMimeArg};
        false -> {mimetypes, default}
    end,
    %% @todo Create this elsewhere.
    {ok, CacheHandle} = cowboy_static_cache:make(),
    Conf = #conf{
        dir=Dir1,
        csize=Size,
        prefix=Prefix1,
        ranges=Ranges,
        usesfile=Sendfile1,
        mimemod=MimeMod,
        mimearg=MimeArg,
        chandle=CacheHandle},
    Pattern = Prefix1 ++ ['...'],
    {Pattern, ?MODULE, Conf}.


init({Transport, http}, Req, Opts) when is_list(Opts) ->
    {_, _, Conf} = rule(Opts),
    init({Transport, http}, Req, Conf);
    
init({Transport, http}, Req, Conf) ->
    Filemod = choose_filemod(Transport, Conf#conf.usesfile),
    State = #state{filemod=Filemod},
    {ok, Req, {Conf, State}}.

handle(Req, {Conf, State}) ->
    method_allowed(Req, Conf, State).

terminate(_Req, _Conf) ->
    ok.

method_allowed(Req0, Conf, State) ->
    case cowboy_http_req:method(Req0) of
        {'GET', Req1} ->
            validate_path(Req1, Conf, State#state{method='GET'});
        {'HEAD', Req1} ->
            validate_path(Req1, Conf, State#state{method='HEAD'});
        {_, Req1} ->
            {ok, Req2} = cowboy_http_req:reply(405, [], <<>>, Req1),
            {ok, Req2, Conf}
    end.


validate_path(Req0, #conf{dir=Dir}=Conf, State) ->
    {Path0, Req1} = cowboy_http_req:path_info(Req0),
    case abs_path(Dir, esc_path(Path0)) of
        invalid ->
            %% @todo Better response code?
            {ok, Req2} = cowboy_http_req:reply(404, [], <<>>, Req1),
            {ok, Req2, Conf};
        Path1 ->
            validate_path_allowed(Req1, Conf, State#state{path=Path1})
    end.


validate_path_allowed(Req0, #conf{dir=Dir}=Conf, #state{path=Path}=State0) ->
    case lists:prefix(Dir, Path) of
        false ->
            {ok, Req1} = cowboy_http_req:reply(404, [], <<>>, Req0),
            {ok, Req1, Conf};
        true ->
            State1 = State0#state{fname=lists:last(Path), path=filename:join(Path)},
            resource_exists(Req0, Conf, State1)
    end.

resource_exists(Req0, #conf{chandle=Cache}=Conf, #state{path=Path}=State) ->
    case cowboy_static_cache:read_info(Path, Cache) of
        {ok, #file_info{}=FInfo} ->
            validate_resource_type(Req0, Conf, State#state{finfo=FInfo});
        {error, enoent} ->
            {ok, Req1} = cowboy_http_req:reply(404, [], <<>>, Req0),
            {ok, Req1, Conf}
    end.

validate_resource_type(Req0, Conf, #state{finfo=FInfo}=State) ->
    {RawPath, Req1} = cowboy_http_req:raw_path(Req0),
    LastChar = binary:last(RawPath),
    case FInfo of
        #file_info{type=regular} ->
            validate_resource_access(Req1, Conf, State);
        #file_info{type=directory} when LastChar =:= $/ ->
            {ok, Req2} = cowboy_http_req:reply(404, [], <<>>, Req1),
            {ok, Req2, Conf};
        #file_info{type=directory} when LastChar =/= $/ ->
            {RedirectURL, Req2} = cowboy_static_hdrs:make_location(Req1),
            Headers = [{<<"Location">>, RedirectURL}],
            {ok, Req3} = cowboy_http_req:reply(301, Headers, <<>>, Req2),
            {ok, Req3, Conf};
        _Other ->
            {ok, Req2} = cowboy_http_req:reply(404, [], <<>>, Req1),
            {ok, Req2, Conf}
    end.

validate_resource_access(Req0, Conf, #state{finfo=FInfo}=State) ->
    case FInfo of
        #file_info{access=read} ->
            detect_content_type(Req0, Conf, State);
        #file_info{access=read_write} ->
            detect_content_type(Req0, Conf, State);
        _Other ->
            {ok, Req1} = cowboy_http_req:reply(403, [], <<>>, Req0),
            {ok, Req1, Conf}
    end.

detect_content_type(Req, Conf, #state{fname=Filename}=State) ->
    #conf{mimemod=MimeMod, mimearg=MimeArg} = Conf,
    Default = <<"application/octet-stream">>,
    case filename:extension(Filename) of
        <<>> ->
            range_header_exists(Req, Conf, State#state{ctype=Default});
        <<$.,Ext/binary>> ->
            case MimeMod:ext_to_mimes(Ext, MimeArg) of
                [] ->
                    range_header_exists(Req, Conf, State#state{ctype=Default});
                [H|_] ->
                    range_header_exists(Req, Conf, State#state{ctype=H});
                Other ->
                    exit({detect_content, Other})
            end;
        Other ->
            exit({detect_content, Other})
    end.

range_header_exists(Req0, Conf, #state{finfo=FInfo}=State) when Conf#conf.ranges ->
    #file_info{size=ContentLength} = FInfo,
    case cowboy_http_req:header('Range', Req0) of
        {undefined, Req1} ->
            open_file_handle(Req1, Conf, State#state{ranges=none});
        {RangesBin, Req1} ->
            Ranges = cowboy_static_hdrs:parse_range(RangesBin, ContentLength),
            open_file_handle(Req1, Conf, State#state{ranges=Ranges})
    end;
range_header_exists(Req, Conf, State) ->
    open_file_handle(Req, Conf, State#state{ranges=none}).


open_file_handle(Req0, Conf, #state{path=Path, filemod=Filemod}=State) ->
    case Filemod:open(Path, []) of
        {ok, File} ->
            init_send_reply(Req0, Conf, State#state{filearg=File});
        {error, eacces} ->
            {ok, Req1} = cowboy_http_req:reply(403, [], <<>>, Req0),
            {ok, Req1, Conf};
        {error, eisdir} ->
            {ok, Req1} = cowboy_http_req:reply(403, [], <<>>, Req0),
            {ok, Req1, Conf};
        {error, enoent} ->
            {ok, Req1} = cowboy_http_req:reply(404, [], <<>>, Req0),
            {ok, Req1, Conf};
        {error, Reason} ->
            %% @todo Log error reason using logging function.
            Error = io_lib:format("Error opening file: ~p~n", [Reason]),
            {ok, Req1} = cowboy_http_req:reply(500, [], Error, Req0),
            {ok, Req1, Conf}
    end.


init_send_reply(Req, Conf, #state{ranges=[_]}=State) ->
    init_send_partial_response(Req, Conf, State);
init_send_reply(Req, Conf, #state{ranges=[_|_]}=State) ->
    init_send_multipart_response(Req, Conf, State);
init_send_reply(Req, Conf, #state{ranges=error}=State) ->
    init_send_complete_response(Req, Conf, State);
init_send_reply(Req, Conf, State) ->
    init_send_complete_response(Req, Conf, State).


init_send_complete_response(Req0, Conf, State) ->
    #state{finfo=FInfo, ctype=CType} = State,
    CacheEntry = cowboy_static_cache:read_entry(FInfo, Conf#conf.chandle),
    LastModified = cowboy_static_cache:last_modified(CacheEntry),
    ContentLength = cowboy_static_cache:content_length(CacheEntry),
    Headers = [
        {<<"Content-Length">>, ContentLength},
        {<<"Content-Type">>, CType},
        {<<"Last-Modified">>, LastModified}],
    {ok, Req1} = cowboy_http_req:reply(200, Headers, <<>>, Req0),
    %% The response to a HEAD Request is expected to be the same as a GET
    %% except for the lack of a Response body. Stop right before sending
    %% the response body and use the same code for everything else.
    case State#state.method of
        'HEAD' ->
            {ok, Req1, {Conf, State}};
        'GET' ->
            Filesize = FInfo#file_info.size,
            Filemod = State#state.filemod,
            Filearg = State#state.filearg,
            Socket = Req1#http_req.socket,
            Transport = Req1#http_req.transport,
            ok = Filemod:stream(0, Filesize, Filearg, Transport, Socket),
            {ok, Req1, {Conf, State}}
    end.


%% If a byte-range request only contains one byte range, the contents of
%% that range can be sent to the client using a normal response body.
init_send_partial_response(Req0, Conf, State) ->
    #state{ranges=[{Start, End, Length}], finfo=FInfo} = State,
    #file_info{size=ContentLength} = FInfo,
    Headers = [
        {<<"Content-Length">>, list_to_binary(integer_to_list(Length))},
        cowboy_static_hdrs:make_range(Start, End, ContentLength)],
    {ok, Req1} = cowboy_http_req:reply(206, Headers, <<>>, Req0),
    Filemod = State#state.filemod,
    Filearg = State#state.filearg,
    Socket = Req1#http_req.socket,
    Transport = Req1#http_req.transport,
    ok = Filemod:stream(Start, Length, Filearg, Transport, Socket),
    {ok, Req1, {Conf, State}}.

%% If a byte-range request contains multiple ranges. The contents of
%% the ranges must be sent as parts of a multipart response.
init_send_multipart_response(Req0, Conf, State) ->
    #state{ranges=Ranges, finfo=FInfo} = State,
    #file_info{size=FileSize} = FInfo,
    Boundary = cowboy_static_multipart:make_boundary(),
    Partial = cowboy_static_multipart:partial(Ranges, Boundary, FileSize),
    ContentLength = cowboy_static_multipart:content_length(Partial),
    ContentLengthStr = list_to_binary(integer_to_list(ContentLength)),
    ContentTypeStr = cowboy_static_multipart:content_type(Boundary),
    Headers = [
        {<<"Content-Type">>, ContentTypeStr},
        {<<"Content-Length">>, ContentLengthStr}],
    {ok, Req1} = cowboy_http_req:reply(206, Headers, <<>>, Req0),
    send_multipart_response(Req1, Conf, State, Partial).


send_multipart_response(Req, Conf, State, []) ->
    {ok, Req, {Conf, State}};

send_multipart_response(Req, Conf, State, [{_,_,_}=H|T]) ->
    {Start, _, Length} = H,
    Filemod = State#state.filemod,
    Filearg = State#state.filearg,
    Socket = Req#http_req.socket,
    Transport = Req#http_req.transport,
    ok = Filemod:stream(Start, Length, Filearg, Transport, Socket),
    send_multipart_response(Req, Conf, State, T);

send_multipart_response(Req, Conf, State, [IOList|T]) ->
    Socket = Req#http_req.socket,
    Transport = Req#http_req.transport,
    ok = Transport:send(Socket, IOList),
    send_multipart_response(Req, Conf, State, T).


%% @private Check if sendfile is supported on this node, if used.
-spec detect_sendfile(boolean()) -> boolean().
detect_sendfile(false) ->
    false;
detect_sendfile(true) ->
    erlang:function_exported(sendfile, send, 4).


%% @private Return the file module to use for this request.
-spec choose_filemod(tcp | ssl, boolean()) -> atom().
choose_filemod(ssl, true)  -> cowboy_static_file;
choose_filemod(ssl, false) -> cowboy_static_file;
choose_filemod(tcp, false) -> cowboy_static_file;
choose_filemod(tcp, true)  -> cowboy_static_sfile.


%% @private Ensure that a path is a list of binary segments.
%% This ensures that any path that filename:split/2 accepts can be used.
-spec path_to_segments([binary()] | string() | binary()) -> [binary()].
path_to_segments([H|_]=Path) when is_binary(H) ->
    Path;
path_to_segments([H|_]=Path) when is_integer(H) ->
    [list_to_binary(E) || E <- filename:split(Path)];
path_to_segments(<<Path/binary>>) ->
    filename:split(Path);
path_to_segments([]) ->
    [].


%% @private Return an absolute file path based on the static file root.
-spec abs_path(Dir::[binary()], Path::[binary()]) -> [binary()].
abs_path(Dir, Path) ->
    Path0 = Dir ++ Path,
    abs_path_(Path0, []).

%% @private Normalize a path, removing all occurances of . and ..
-spec abs_path_(Path::[binary()], Stack::[binary()]) -> [binary()].
abs_path_([<<".">>|T], Stack) ->
    abs_path_(T, Stack);
abs_path_([<<"..">>|T], [_|Stack]) ->
    abs_path_(T, Stack);
abs_path_([<<"..">>|_], _Stack) ->
    invalid;
abs_path_([H|T], Stack) ->
    abs_path_(T, [H|Stack]);
abs_path_([], Stack) ->
    lists:reverse(Stack).


%% @private Escape all path segments of a file system path.
-spec esc_path(Path::[binary()]) -> [binary()].
esc_path(Path) ->
    [esc_segment(E, <<>>) || E <- Path].


%% @private Escape a segment of a file system path.
%% - Replaces occurrances of / not prefixed by an odd number of \ with \/.
-spec esc_segment(Segment::binary(), Acc::binary()) -> binary().
esc_segment(<<$\\,$\\, Rest/binary>>, Acc) ->
    esc_segment(Rest, <<Acc/binary, $\\,$\\>>);
esc_segment(<<$\\,$/, Rest/binary>>, Acc) ->
    esc_segment(Rest, <<Acc/binary, $\\,$/>>);
esc_segment(<<$/, Rest/binary>>, Acc) ->
    esc_segment(Rest, <<Acc/binary, $\\,$/>>);
esc_segment(<<C, Rest/binary>>, Acc) ->
    esc_segment(Rest, <<Acc/binary, C>>);
esc_segment(<<>>, Acc) ->
    Acc.


-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

abs_path_test_() ->
    TestDir = [<<"tmp">>, <<"static">>],
    Tests = [
        %% Tests for ..
        {[<<"tmp">>, <<"static">>, <<"foo.css">>], [<<"foo.css">>]},
        {[<<"tmp">>, <<"foo.css">>], [<<"..">>, <<"foo.css">>]},
        {[<<"foo.css">>], [<<"..">>, <<"..">>, <<"foo.css">>]},
        {invalid, [<<"..">>, <<"..">>, <<"..">>, <<"foo.css">>]},
        %% Tests for .
        {[<<"tmp">>, <<"static">>, <<"foo.css">>], [<<".">>, <<"foo.css">>]}
    ],
    [?_assertEqual(Exp, abs_path(TestDir, Path)) || {Exp, Path} <- Tests].

split_path_test_() ->
    [?_assertEqual([], path_to_segments([])),
     ?_assertEqual([<<"/">>], path_to_segments("/")),
     ?_assertEqual([<<"/">>], path_to_segments(<<"/">>)),
     ?_assertEqual([<<"/">>], path_to_segments([<<"/">>])),
     ?_assertEqual([<<"b">>], path_to_segments("b/")),
     ?_assertEqual([<<"b">>], path_to_segments(<<"b/">>)),
     ?_assertEqual([<<"b">>], path_to_segments([<<"b">>]))
    ].

-endif.
