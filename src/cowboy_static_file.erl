-module(cowboy_static_file).
%% @doc Erlang file module wrapper.
%%
%% This module implements a callback module for interfacing with the built in
%% file module from the cowboy_static http handler. It extends the file module
%% with support for writing a range of the contents to a socket using a user
%% specified stream transport module.

-export([open/2, stream/5, close/1]).


%% @doc Open a file handle.
open(Filepath, Options) ->
    Fileopts = merge_fileopts(Options),
    case file:open(Filepath, Fileopts) of
        {ok, File} -> {ok, {File, Options}};
        {error, E} -> {error, E}
    end.


%% @doc Stream range of a file to a socket.
stream(Start, Length, {File, Options}, Transport, Socket) ->
    ChunkSize = proplists:get_value(chunk_size, Options, 16#FFFF),
    {ok, Start} = file:position(File, {bof, Start}),
    stream_file(Length, ChunkSize, File, Transport, Socket).

stream_file(0, _ChunkSize, _File, _Transport, _Socket) ->
    ok;
stream_file(N, ChunkSize, File, Transport, Socket) ->
    Bytes = if N < ChunkSize -> N; true -> ChunkSize end,
    case file:read(File, Bytes) of
        {ok, Data} ->
            Bytes = byte_size(Data),
            ok = Transport:send(Socket, Data),
            stream_file(N - Bytes, ChunkSize, File, Transport, Socket)
    end.


%% @doc Close a file handle.
close({File, _Options}) ->
    file:close(File).


%% @private Merge the value of the fileopts parameter with the default values.
merge_fileopts(Options) ->
    Opts = proplists:get_value(fileopts, Options, []),
    Opts ++ [read,raw,binary].
