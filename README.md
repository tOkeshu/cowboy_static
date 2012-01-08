# Status

This library has been superceded by the built in file handler in the cowboy
web server, see [cowboy_http_static](https://github.com/extend/cowboy/blob/master/src/cowboy_http_static.erl).


## Usage

`cowboy_static:rule/1` should be used to build dispatch rules using this
static file handler. The return value of this function depends on a list
of options. The `dir` and `prefix` options must be supplied.

### dir

    {dir, [binary()]}

The `dir` option specifies which file system directory to serve static files from.
This path should be an absolute path such as `[<<"/">>, <<"var">>, <<"www">>]`.

### prefix

    {prefix, [binary()]}

The`prefix` option speficies the request path prefix to serve static files under.
The value of this option should be set to `[]` to specify the `/` request path prefix.

## sendfile

    {sendfile, boolean()}.

The `sendfile` option specified whether the sendfile (2) system call should be
used to send the file contents to the client. The value of this option defaults
to `true`.

Using the sendfile (2) system call on SSL encrypted sockets will bypass the
encryption phase, therefore this option is always effectively `false` if the
`cowboy_ssl_transport` is used.

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
