-module(cowboy_static_sfile).
%% @doc Erlang sendfile wrapper.
%%
%% This module implements a callback module for interfacing with the sendfile
%% module written by tuncer and in the future the file:sendfile support in the
%% standard library.

-export([open/2, stream/5, close/1]).


%% @doc Open a file handle.
open(Filepath, Options) ->
    {ok, {Filepath, Options}}.


%% @doc Stream range of a file to a socket.
stream(Start, Length, {Filepath, _Options}, _Transport, Socket) ->
    {ok, Length} = sendfile:send(Socket, Filepath, Start, Length),
    ok.

%% @doc Close a file handle.
close({_Filepath, _Options}) ->
    ok.
