-module(cowboy_static_example).
-export([start/2]).

start(Dir, Port) ->
    application:start(cowboy),
    Dispatch = [
        %% {Host, list({Path, Handler, Opts})}
        {'_', [{'_', cowboy_static, [{dir, Dir}, {chunk_size, 16#FF}]}]}],
    cowboy:start_listener({http, Port}, 100,
        cowboy_tcp_transport, [{port, Port}],
        cowboy_http_protocol, [{dispatch, Dispatch}]).
