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

%% @doc Read through cache for path properties.
%%
%% Simple path properties such as the value of the Last-Modified header and
%% Content-Length header are computed by readers and pushed into the cache.
%%
%% More expensive path properties such as the ETag value associated with a path
%% are computed by background workers and pushed into the cache once they are
%% available.

-module(cowboy_static_cache).

%% include files
-include_lib("kernel/include/file.hrl").

%% exported functions
-export([make/0,
         read_info/2,
         read_entry/2,
         content_length/1,
         last_modified/1]).

%% entry access functions

-record(cache_handle, {
    table  :: ets:tid(),
    server :: pid()}).

-opaque handle() :: #cache_handle{}.
-export_type([handle/0]).

-record(cache_entry, {
    inode = exit(required) :: pos_integer(),
    mtime = exit(required) :: file:date_time(),
    content_length :: binary(),
    last_modified  :: binary()}).

-opaque entry() :: #cache_entry{}.
-export_type([entry/0]).


%% @doc Make a new cache instance.
-spec make() -> {ok, handle()}.
make() ->
    {ok, #cache_handle{}}.


%% @doc Read file info from disk.
-spec read_info([binary()], handle()) -> {ok, #file_info{}} | {error, _}.
read_info(Path, _Handle) ->
    file:read_file_info(Path).


%% @doc Read a cache entry for a file.
-spec read_entry(#file_info{}, handle()) -> {ok, _}.
read_entry(Fileinfo, _Handle) ->
    make_entry(Fileinfo).


%% @private Make a new cache entry.
-spec make_entry(#file_info{}) -> {ok, entry()}.
make_entry(Fileinfo) ->
    Inode = Fileinfo#file_info.inode,
    Size = Fileinfo#file_info.size,
    MTime = Fileinfo#file_info.mtime,
    ContentLength = list_to_binary(integer_to_list(Size)),
    LastModified = cowboy_clock:rfc2109(MTime),
    #cache_entry{
        inode=Inode, mtime=MTime,
        content_length=ContentLength,
        last_modified=LastModified}.

%% @doc Return the Content-Length value of a cache entry.
-spec content_length(entry()) -> binary().
content_length(CacheEntry) ->
    CacheEntry#cache_entry.content_length.

%% @doc Return the Last-Modified value of a cache entry.
-spec last_modified(entry()) -> binary().
last_modified(CacheEntry) ->
    CacheEntry#cache_entry.last_modified.
