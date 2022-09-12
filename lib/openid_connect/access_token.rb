module OpenIDConnect
  class AccessToken < Rack::OAuth2::AccessToken::Bearer
    REQUIRE_TOKEN = ['tradewing.com']

    attr_required :client
    attr_optional :id_token

    def initialize(attributes = {})
      super
      @token_type = :bearer
    end

    def userinfo!(params = {})
      hash = resource_request do
        params = { "access_token" => @access_token }.merge(params) if requires_token?
        get client.userinfo_uri, params
      end
      ResponseObject::UserInfo.new hash
    end

    private

    def requires_token?
      REQUIRE_TOKEN.any? { |host| client.host.to_s.include?(host) }
    end

    def resource_request
      res = yield
      case res.status
      when 200
        JSON.parse(res.body).with_indifferent_access
      when 400
        raise BadRequest.new('API Access Faild', res)
      when 401
        raise Unauthorized.new('Access Token Invalid or Expired', res)
      when 403
        raise Forbidden.new('Insufficient Scope', res)
      else
        raise HttpError.new(res.status, 'Unknown HttpError', res)
      end
    end
  end
end