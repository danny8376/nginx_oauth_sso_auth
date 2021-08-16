require "http/server"
require "http/client"
require "openssl/hmac"
require "base64"
require "yaml"
require "json"

module Server
  struct Config
    module Base64Decoder
      def self.from_yaml(ctx : YAML::ParseContext, node : YAML::Nodes::Node) : Bytes
        unless node.is_a?(YAML::Nodes::Scalar)
          node.raise "Expected scalar, not #{node.class}"
        end
        Base64.decode(node.value)
      end
    end
    module RegexParser
      def self.from_yaml(ctx : YAML::ParseContext, node : YAML::Nodes::Node) : Regex
        unless node.is_a?(YAML::Nodes::Scalar)
          node.raise "Expected scalar, not #{node.class}"
        end
        Regex.new(node.value)
      end
    end
    struct Bind
      include YAML::Serializable
      property host : String
      property port : Int32
      property unix : String
      property perm : Int16
    end
    struct OAuth
      include YAML::Serializable
      property auth_url      : String
      property token_url     : String
      property user_url      : String
      property client_id     : String
      property client_secret : String
      property scope         : String
      @[YAML::Field(converter: Server::Config::RegexParser)]
      property ip_whitelist  : Regex
    end
    struct Cookie
      include YAML::Serializable
      property name   : String
      property secure : Bool
      @[YAML::Field(converter: Server::Config::Base64Decoder)]
      property secret : Bytes
      property refresh_time : Int32
      property valid_time   : Int32
      property field  : String
    end
    include YAML::Serializable
    property bind   : Bind
    property oauth  : OAuth
    property cookie : Cookie
    property prefix : String
  end

  # read example as default config value 030
  @@conf = Config.from_yaml(File.read("./config.yml.example"))
  def self.load_config(yaml = File.read("./config.yml"))
    @@conf = Config.from_yaml yaml
  end

  DIGEST_ALG = OpenSSL::Algorithm::SHA256
  DIGEST_LEN = 32
  AUTH_PREFIX_LEN = 32 + 8 # digest + unix(int64)

  def self.digest_cookie_auth(data, time = Time.utc)
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

    now = Time.utc
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
  rescue ArgumentError # from Time.unix ?
    return 401, nil # wrong cookie format, auth again
  rescue TypeCastError # from JSON::Any as_a/as_s ?
    return 401, nil # wrong json payload, auth again
  rescue Base64::Error | IO::EOFError | JSON::ParseException
    return 401, nil # wrong cookie format, auth again
  end

  def self.gen_cookie(name, data)
    HTTP::Cookie.new(name, data, secure: @@conf.cookie.secure, http_only: true)
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
  # wrong config or bad oauth server, lazy to handle this
  # (shouldn't happen, or not our fault, isn't it?)
  #rescue JSON::ParseException
  end

  def self.handle_request(context)
    case context.request.path
    when /^#{@@conf.prefix}\/check(?:\/(?<rule>.+))?/ # nginx auth_request handler
      rule = $~["rule"]? || context.request.headers["X-AuthRule"]? || "none|=|none"
      if context.request.headers.has_key?("X-Real-IP") && @@conf.oauth.ip_whitelist.match(context.request.headers["X-Real-IP"])
        code = 200
      elsif context.request.cookies.has_key? @@conf.cookie.name
        cookie = context.request.cookies[@@conf.cookie.name]
        code, refresh = check_cookie_auth cookie, rule
        unless refresh.nil?
          context.response.cookies << refresh
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
        context.response.cookies << gen_cookie_back(query)
      end
      context.response.status_code = 302
      context.response.headers["Location"] =
        "#{@@conf.oauth.auth_url}?#{HTTP::Params.encode({
          response_type: "code",
          client_id: @@conf.oauth.client_id,
          scope: @@conf.oauth.scope,
          redirect_uri: "https://#{context.request.headers["Host"]?}#{@@conf.prefix}/callback",
        })}"
      context.response.print "Redirect to SSO"
    when /^#{@@conf.prefix}\/callback/
      if context.request.query_params.has_key? "code"
        res = HTTP::Client.post @@conf.oauth.token_url, form: HTTP::Params.encode({
          code: context.request.query_params["code"],
          grant_type: "authorization_code",
          client_id: @@conf.oauth.client_id,
          client_secret: @@conf.oauth.client_secret,
          redirect_uri: "https://#{context.request.headers["Host"]?}#{@@conf.prefix}/callback",
        })
        if res.status_code == 200
          token = JSON.parse(res.body)["access_token"]?
          if token.nil?
            context.response.status_code = 502
            context.response.print "SSO Server error - no token"
          else
            res = HTTP::Client.get @@conf.oauth.user_url, HTTP::Headers{"Authorization" => "Bearer #{token.as_s}"}
            if res.status_code == 200
              context.response.cookies << gen_cookie_auth(res.body)
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
