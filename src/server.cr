require "http/server"
require "http/client"
require "openssl/hmac"
require "base64"
require "yaml"
require "json"

module Server
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
        secret: String,
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
  DIGEST_B64_LEN = 44
  # base64 digest => 44 chars

  def self.digest_cookie(cookie)
    Base64.strict_encode(OpenSSL::HMAC.digest(DIGEST_ALG, @@conf.cookie.secret, cookie)) + cookie
  end

  def self.extract_cookie(cookie)
    digest = cookie.value
    return "" if digest.size <= DIGEST_B64_LEN
    val = digest[DIGEST_B64_LEN..-1]
    return "" if digest != digest_cookie val
    return val
  end

  def self.auth_cookie(cookie, rule)
    json = JSON.parse cookie
    key, sym, val = rule.split("|")
    target = json[key]?
    return false if target.nil?
    case sym
    when "="
      return target.as_s == val
    when "~"
      val.split(",") do |v|
        return target.as_a.includes? v
      end
    end
  end

  def self.back_cookie(uri)
    cookies = HTTP::Cookies.new
    cookies << HTTP::Cookie.new("#{@@conf.cookie.name}XBACK", uri, secure: true)
    cookies
  end

  def self.gen_cookie(json)
    obj = JSON.parse json
    cookies = HTTP::Cookies.new
    cookies << HTTP::Cookie.new(@@conf.cookie.name, digest_cookie(JSON.build { |json|
      json.object do
        @@conf.cookie.field.split("|").each do |f|
          json.field f, obj[f]
        end
      end
    }), secure: true)
    cookies
  end

  def self.handle_request(context)
    case context.request.path
    when /^#{@@conf.prefix}\/check(?:\/(?<rule>.+))?/ # nginx auth_request handler
      if context.request.cookies.has_key? @@conf.cookie.name
        cookie = extract_cookie context.request.cookies[@@conf.cookie.name]
        rule = $~["rule"]? || context.request.headers["X-AuthRule"] || "none|=|none"
        if !cookie.empty? && auth_cookie cookie, rule
          context.response.status_code = 200
          context.response.print "OK"
        else
          context.response.status_code = 403
          context.response.print "access denied"
        end
      else
        context.response.status_code = 401
        context.response.print "Auth required"
      end
    when /^#{@@conf.prefix}\/login/
      query = context.request.query || ""
      if !query.empty?
        back_cookie(query).add_response_headers context.response.headers
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
              gen_cookie(res.body).add_response_headers context.response.headers
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
