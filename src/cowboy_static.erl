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
-module(cowboy_http_static).
%% @doc Static resource handler.
%%
%% This built in HTTP handler provides a simple file serving capability for
%% cowboy applications. It is only recommended to be used during development
%% and for small deployments. It has limited support for mimetype detection
%% based on the extension part of the file name served.
%%
%% The available options are:
%% <dl>                                                                         
%%  <dt>directory</dt><dd>The directory to search for files under.</dd>
%%  <dt>mimetypes</dt><dd>The function mapping file names to mime types.
%%   Defaults to `{fun cowboy_http_static:path_to_mimes/2, default}'</dd>              
%% </dl>
%%
%% === Mimetype configuration ===
%%
%% === Directory configuration ===


%% include files
-include_lib("kernel/include/file.hrl").

%% cowboy_http_protocol callbacks
-export([init/3]).

%% cowboy_http_rest callbacks
-compile(export_all).

%% type aliases
-type req() :: #http_req{}.

%% handler state
-record(state, {
	filepath  :: binary(),
	fileinfo  :: #file_info{},
	mimetypes :: {fun((binary(), T) -> [{binary(), binary(), _}]), T}}).


%% @private Upgrade from HTTP handler to REST handler.
init({_Transport, http}, _Req, _Opts) ->
    {upgrade, protocol, cowboy_http_rest}.

%% @private unused callback for cowboy_http_protocol behaviour.
handle(_Req, _State) ->
    ignore.

%% @private unused callback for cowboy_http_protocol behaviour.
terminate(_Req, _State) ->
    ok.


%% @private Set up initial state of REST handler.
-spec rest_init(req(), list()) -> {ok, req(), #state{}}.
rest_init(Req, Opts) ->
	Directory = proplists:get_value(directory, Opts),
	DefaultMimetypes = {fun path_to_mimetypes/2, default},
	Mimetypes = proplists:get_value(mimetypes, Opts, DefaultMimetypes),
    {Filepath, Req1} = cowboy_http_req:path_info(Req),
    Filepath1 = esc_path(Filepath),
	Filepath2 = abs_path(Directory, Filepath1),
	Filepath3 = join_path(Filepath2),
    Fileinfo = case Filepath of
        invalid -> {error, badpath};
        _Valid -> file:read_file_info(Filepath)
    end,
    State = #state{filepath=Filepath, fileinfo=Fileinfo, mimetypes=Mimetypes},
    {ok, Req1, State}.


%% @private Only allow GET and HEAD requests on static resources.
-spec allowed_methods(req(), #state{}) -> {[atom()], req(), #state{}}.
allowed_methods(Req, State) ->
    {['GET', 'HEAD'], Req, State}.


%% @private Check if the resource exists under the document root.
-spec resource_exists(req(), #state{}) -> {boolean(), req(), #state{}}.
resource_exists(Req, #state{fileinfo={Status, Fileinfo}}=State) ->
    Exists = Status =:= ok andalso Fileinfo#file_info.type =:= regular,
    {Exists, Req, State}.


%% @private Check if the requested resource can be accessed.
-spec forbidden(req(), #state{}) -> {boolean(), req(), #state{}}.
forbidden(Req, #state{fileinfo={Status, Fileinfo}}=State) ->
    Readable = case Status =:= ok andalso Fileinfo#file_info.access of
        read -> true; read_write -> true; false -> true; _ -> false end,
    {not Readable, Req, State}.


%% @private Read the time a file system system object was last modified.
-spec last_modified(req(), #state{}) -> {cowboy_clock:datetime(), req(), #state{}}.
last_modified(Req, #state{fileinfo={ok, Fileinfo}}=State) ->
    Modified = Fileinfo#file_info.mtime,
    {Modified, Req, State}.


%% @private Return the content type of a file.
-spec content_types_provided(req(), #state{}) -> tuple().
content_types_provided(Req, #state{filepath=Filepath,
		mimetypes={MimetypesFun, MimetypesData}}=State) ->
	Mimetypes = [begin {I, J, K} = Type, {{I, J, K}, file_contents} end
		|| Type <- MimetypesFun(Filepath, MimetypesData)],
    {Mimetypes, Req, State}.


%% @private Read and return the contents of a file.
-spec file_contents(req(), #state{}) -> tuple().
file_contents(Req, #state{filepath=Filepath, fileinfo=Fileinfo}=State) ->
	{ok, Transport, Socket} = cowboy_http_req:transport(Req),
	StreamFun = content_function(Transport, Socket, Filepath),
	StreamLen = Fileinfo#file_info.size,
    {{stream, StreamLen, StreamFun}, Req, State}.


%% @private Return a function writing the contents of a file to a socket.
%% The function returns the number of bytes written to the socket to enable
%% the calling function to determine if the expected number of bytes were
%% written to the socket.
-spec content_function(module(), inet:socket(), binary()) ->
	fun(() -> {sent, non_neg_integer()}).
content_function(Transport, Socket, Filepath) ->
    case erlang:function_exported(file, sendfile, 4) of
        %% `file:sendfile/4' will only work with the `cowboy_tcp_transport'
        %% transport module. SSL or future SPDY transports that require the
        %% content to be encryptet or framed as the content is sent.
        false ->
			fun() -> sfallback(Transport, Socket, Filepath) end;
		_ when Transport =/= cowboy_tcp_transport ->
			fun() -> sfallback(Transport, Socket, Filepath) end;
        true ->
			fun() -> sendfile(Socket, Filepath) end
    end.


%% @private Sendfile fallback function.
%% For older Erlang releases. Fall back to using the file:read/2 and
%% Transport:send/2 functions to send the file contents to the client.
%% Transports other than `cowboy_tcp_transport' also require using this
%% functions because they may rely on the transport module encrypting or
%% framing the response body.
-spec sfallback(module(), inet:socket(), binary()) -> {sent, non_neg_integer()}.
sfallback(Transport, Socket, Filepath) ->
	{ok, File} = file:open(Path, [read,binary,raw]),
	sfallback_(Transport, Socket, File, 0).

-spec sfallback(module(), inet:socket(), binary(), non_neg_integer()) ->
		{sent, non_neg_integer()}.
sfallback_(Transport, Socket, File, Sent) ->
	case file:read(File, 1024), 
		eof ->
			file:close(File);
			{sent, Sent};
		{ok, Bin} ->
			ok = Transport:write(Socket, Bin),
			sfallback(Transport, Socket, File, Sent + byte_size(Bin))
	end.

%% @private Wrapper for sendfile function.
-spec sendfile(inet:socket(), binary()) -> {sent, non_neg_integer()}.
sendfile(Socket, Filepath) ->
	{ok, Sent} = file:sendfile(Filepath, Socket), %% @todo
	{sent, Sent}.



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


%% @private Module local alias for filename:join
-spec join_path([binary()]) -> binary().
join_path(Path) ->
    filename:join(Path).

%% @private Use application/octet-stream as the default mimetype.
path_to_mimetypes(Path, default) ->
	[{<<"application">>, <<"octet-stream">>, []}].


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
