require "http/server"
require "http/client"
require "openssl/hmac"
require "base64"
require "yaml"
require "json"

module Server
  module Base64Decoder
    def self.from_yaml(ctx : YAML::ParseContext, node : YAML::Nodes::Node) : Bytes
      unless node.is_a?(YAML::Nodes::Scalar)
        node.raise "Expected scalar, not #{node.class}"
      end
      Base64.decode(node.value)
    end
  end
  struct Config
    struct Bind
      YAML.mapping(
        host:   String,
        port:   Int32,
      )
    end
    struct OAuth
      YAML.mapping(
        auth_url:      String,
        token_url:     String,
        user_url:      String,
        client_id:     String,
        client_secret: String,
        scope:         String,
      )
    end
    struct Cookie
      YAML.mapping(
        name:   String,
        secure: Bool,
        secret: {
          type: Bytes,
          converter: Base64Decoder,
        },
        refresh_time: Int32,
        valid_time:   Int32,
        field:  String,
      )
    end
    YAML.mapping(
      bind:    Bind,
      oauth:   OAuth,
      cookie:  Cookie,
      prefix:  String,
    )
  end

  # read example as default config value 030
  @@conf = Config.from_yaml(File.read("./config.yml.example"))
  def self.load_config(yaml = File.read("./config.yml"))
    @@conf = Config.from_yaml yaml
  end

  DIGEST_ALG = :sha256
  DIGEST_LEN = 32
  AUTH_PREFIX_LEN = 32 + 8 # digest + unix(int64)

  def self.digest_cookie_auth(data, time = Time.utc_now)
    slice = data.to_slice
    auth = Bytes.new(AUTH_PREFIX_LEN + slice.bytesize)
    io = IO::Memory.new(auth)
    io.skip DIGEST_LEN
    io.write_bytes time.to_unix
    io.write slice
    io.rewind
    digest = OpenSSL::HMAC.digest(DIGEST_ALG, @@conf.cookie.secret, auth)
    io.write digest
    auth
  end

  def self.check_cookie_auth(cookie, rule) # (return) code, cookie_refresh
    refresh = nil

    auth = Base64.decode cookie.value
    return 401, refresh if auth.bytesize <= AUTH_PREFIX_LEN

    io = IO::Memory.new(auth)
    io.skip DIGEST_LEN # skip digest
    time = Time.unix io.read_bytes(Int64)
    data = io.read_string(auth.bytesize - AUTH_PREFIX_LEN)
    return 401, refresh if auth != digest_cookie_auth(data, time)

    now = Time.utc_now
    span = (now - time).seconds
    return 401, refresh if span > @@conf.cookie.valid_time

    if span > @@conf.cookie.refresh_time
      refresh = refresh_cookie_auth digest_cookie_auth(data)
    end

    json = JSON.parse data
    key, sym, val = rule.split("|")
    target = json[key]?
    return 403, refresh if target.nil?
    case sym
    when "="
      return (target.as_s == val ? 200 : 403), refresh
    when "~"
      val.split(",") do |v|
        if target.as_a.includes?(v)
          return 200, refresh
        end
      end
    end
    return 403, refresh
  end

  def self.gen_cookie(name, data)
    cookies = HTTP::Cookies.new
    cookies << HTTP::Cookie.new(name, data, secure: @@conf.cookie.secure, http_only: true)
    cookies
  end

  def self.gen_cookie_back(uri)
    gen_cookie("#{@@conf.cookie.name}XBACK", uri)
  end

  def self.refresh_cookie_auth(auth)
    gen_cookie(@@conf.cookie.name, Base64.urlsafe_encode(auth, false))
  end

  def self.gen_cookie_auth(json)
    obj = JSON.parse json
    gen_cookie(@@conf.cookie.name, Base64.urlsafe_encode(digest_cookie_auth(JSON.build { |json|
      json.object do
        @@conf.cookie.field.split("|").each do |f|
          json.field f, obj[f]
        end
      end
    }), false))
  end

  def self.handle_request(context)
    case context.request.path
    when /^#{@@conf.prefix}\/check(?:\/(?<rule>.+))?/ # nginx auth_request handler
      if context.request.cookies.has_key? @@conf.cookie.name
        cookie = context.request.cookies[@@conf.cookie.name]
        rule = $~["rule"]? || context.request.headers["X-AuthRule"] || "none|=|none"
        code, refresh = check_cookie_auth cookie, rule
        unless refresh.nil?
          refresh.add_response_headers context.response.headers
        end
      else
        code = 401
      end
      case code
      when 200
        context.response.status_code = 200
        context.response.print "OK"
      when 403
        context.response.status_code = 403
        context.response.print "access denied"
      when 401
        context.response.status_code = 401
        context.response.print "Auth required"
      end
    when /^#{@@conf.prefix}\/login/
      query = context.request.query || ""
      if !query.empty?
        gen_cookie_back(query).add_response_headers context.response.headers
      end
      context.response.status_code = 302
      context.response.headers["Location"] =
        "#{@@conf.oauth.auth_url}?#{HTTP::Params.encode({
          response_type: "code",
          client_id: @@conf.oauth.client_id,
          scope: @@conf.oauth.scope,
          redirect_uri: "https://#{context.request.host}#{@@conf.prefix}/callback",
        })}"
      context.response.print "Redirect to SSO"
    when /^#{@@conf.prefix}\/callback/
      if context.request.query_params.has_key? "code"
        res = HTTP::Client.post @@conf.oauth.token_url, form: HTTP::Params.encode({
          code: context.request.query_params["code"],
          grant_type: "authorization_code",
          client_id: @@conf.oauth.client_id,
          client_secret: @@conf.oauth.client_secret,
          redirect_uri: "https://#{context.request.host}#{@@conf.prefix}/callback",
        })
        if res.status_code == 200
          token = JSON.parse(res.body)["access_token"]?
          if token.nil?
            context.response.status_code = 502
            context.response.print "SSO Server error - no token"
          else
            res = HTTP::Client.get @@conf.oauth.user_url, HTTP::Headers{"Authorization" => "Bearer #{token.as_s}"}
            if res.status_code == 200
              gen_cookie_auth(res.body).add_response_headers context.response.headers
              if context.request.cookies.has_key? "#{@@conf.cookie.name}XBACK"
                context.response.status_code = 302
                context.response.headers["Location"] = context.request.cookies["#{@@conf.cookie.name}XBACK"].value
                context.response.print "Redirect"
              else
                context.response.status_code = 200
                context.response.print "Logged in"
              end
            else
              context.response.status_code = 502
              context.response.print "SSO Server error - fail to get userinfo"
            end
          end
        else
          context.response.status_code = 502
          context.response.print "SSO Server error - fail to get token"
        end
      else
        context.response.status_code = 400
        context.response.print "Bad request"
      end
    end
  end

  def self.start_server(host = "", port = -1)
    load_config

    host = @@conf.bind.host if host.empty?
    port = @@conf.bind.port if port < 0

    server = HTTP::Server.new([
      HTTP::ErrorHandler.new ENV["ENV"] == "debug",
    ]) { |context| handle_request context }

    puts "Listening on http://#{host}:#{port}"
    server.bind_tcp host, port
    server.listen
  end
end


ENV["ENV"] ||= "production"

Server.start_server
