require "active_support/core_ext"
require "base64"
require "yajl"
require "openssl"

class SaeOauth2
  attr_accessor :client_id, :client_secret, :access_token, :refresh_token
  attr_accessor :http_code, :url, :host, :timeout, :connect_timeout
  attr_accessor :ssl_verify_peer, :format, :decode_json

  attr_accessor :http_info, :user_agent, :debug

  attr_reader :access_token_url, :authorize_url

  def initialize(client_id, client_secret, access_token = nil, refresh_token = nil)
    @host, @timeout, @connect_timeout, @ssl_verify_peer  = "https://api.t.sina.com.cn", 30, 30, false

    @format, @decode_json = "json", true
    @user_agent = "Sae OAuth2 v0.1"
    @debug = false

    @access_token_url = "https://api.t.sina.com.cn/oauth2/access_token"
    @authorize_url = "https://api.t.sina.com.cn/oauth2/authorize"

    @client_id = client_id
    @client_secret = client_secret
    @access_token = access_token
    @refresh_token = refresh_token
  end  #
  #
  #
  # def get_authorize_url(redirect_url, response_type = "code")
  #   params = {}
  #   params[:client_id] = self.client_id
  #   params[:redirect_uri] = redirect_url
  #   params[:response_type] = response_type
  #   "#{self.authorize_url}?#{params.to_param}"
  # end
  #
  # def get_access_token($keys, $type = "code")
  #   params = {}
  #   params["client_id"] = self.client_id
  #   params["client_secret"] = self.client_secret
  #
  # end


  ######################################################
	# 解析 signed_request
	#
	# @param string $signed_request 应用框架在加载iframe时会通过向Canvas URL post的参数signed_request
	#
	# @return array
	#####################################################
  def parse_signed_request(signed_request)
    encoded_sig, payload = signed_request.split(".")
    sig = Base64.decode64(encoded_sig)
    data = Yajl::Parser.parse(Base64.decode64(payload))
    return "-1" if data["algorithm"].upcase != "HMAC-SHA256"
    expected_sig = OpenSSL::HMAC.hexdigest("sha256", self.client_secret, payload)
    (sig != expected_sig) ? "-2" : data
  end
  
  
end
