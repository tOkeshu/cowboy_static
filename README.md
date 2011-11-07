## Usage

`cowboy_static:rule/1` should be used to build dispatch rules using this
static file handler. The return value of this function depends on a list
of options. The `dir` and `prefix` options must be supplied.

### {dir, [binary()]}

The `dir` option specifies which file system directory to serve static files from.
This path should be an absolute path such as `[<<"/">>, <<"var">>, <<"www">>]`.

### {prefix, [binary()]}

The`prefix` option speficies the request path prefix to serve static files under.

## Example

    Dir = [<<"/">>, <<"var">>, <<"www">>],
    Dispatch = [
        {'_', [
            cowboy_static:rule([{dir, Dir}, {prefix, [<<"static">>]}])
            cowboy_static:rule([{dir, Dir}, {prefix, []}])]}],
    cowboy:start_listener({http, Port}, 100,
        cowboy_tcp_transport, [{port, Port}],
        cowboy_http_protocol, [{dispatch, Dispatch}])

A cowboy listener with these dispatch rules will serve files from `/var/www`
under the request path prefix `/static/` or `/`.
