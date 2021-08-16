# nginx_oauth_sso_auth

This is a backend server for oauth authentication with Nginx auth_request module.

## Installation

TODO: List C libraries that required to install

```shell
git clone https://github.com/danny8376/nginx_oauth_sso_auth.git
shards build
bin/server
```

## Usage

Before start, edit the config.yml as you need.

First, run this server with ways you like.
For example, with systemd like:

```
[Unit]
Description=Nginx OAuth SSO Auth Backend
After=network.target

[Service]
User=http
WorkingDirectory=<path to cloned location>
ExecStart=<path to cloned location>/bin/server
Restart=always

[Install]
WantedBy=default.target
```

Then, configure your nginx to use it. (Require to install auth_request module for Nginx first. Please follow instruction of your distribution.)

```
upstream oauth_sso_auth {
    server 127.0.0.1:54321; # the same as bind in config
    keepalive 8; # adjust this as required, or remove to disable keepalive for backend connections.
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name authrequired.example.com;

    # must be the same as prefix in config, or you may need more configuration.
    location /oauth_sso_auth/ {
        proxy_pass http://oauth_sso_auth;
        proxy_set_header Host $host; # required, or redirect won't work correctly.
        # this is optional, cookie path default to /, you may change it with your requirement
        #proxy_set_header X-CookiePath "/";
    
        # make this endpoint only accessible to nginx internally, maybe not required?
        location /oauth_sso_auth/check {
            internal;
            proxy_pass http://oauth_sso_auth;
            proxy_set_header Host $host;
            # this sets auth rule
            # in format of "<OAuth Attribute>|<Operator>|<Required Value>" (don't put any whitespace.)
            # <OAuth Attribute>: attribute that you want to check
            # <Operator> : "=" or "~"
            # "=" => equals, for String/Number
            # "~" => includes, for Array, can match multiple value, sperate values with ","
            # the following will check for "roles" if includes "admin"
            proxy_set_header X-AuthRule "roles|~|admin";
        }
    }

    # 401 page, redirect to sso login page
    # query string $request_uri is for bring user back to the page before login
    location @oauth_sso_auth_401 {
        return 302 /oauth_sso_auth/login?$request_uri;
    }

    location / {
        error_page 401 = @oauth_sso_auth_401;
        # this is for cookie refresh
        auth_request_set $auth_cookie $upstream_http_set_cookie;
        add_header set-cookie $auth_cookie;

        <normal nginx config here>
    }

    location /god_only/ {
        error_page 401 = @oauth_sso_auth_401;
        # you can also defile auth rule here, put the rule after check as subpath
        auth_request /oauth_sso_auth/check/username|=|god;
        auth_request_set $auth_cookie $upstream_http_set_cookie;
        add_header set-cookie $auth_cookie;

        <normal nginx config here>
    }
}
```

## Development

TODO: Write development instructions here

## Contributing

1. Fork it ( https://github.com/danny8376/nginx_oauth_sso_auth/fork )
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create a new Pull Request

## Contributors

- [danny8376](https://github.com/danny8376) DannyAAM - creator, maintainer
