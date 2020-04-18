class HomeController < ApplicationController

  # We use state instead
  skip_before_action :verify_authenticity_token, only: :redirect

  def index
    # Save to session for verification
    session[:state] = SecureRandom.hex(24)
  end

  def redirect
    @state = params[:state]
    @code = params[:code]
    @id_token = params[:id_token]
    @user = params[:user]

    unless session[:state] == @state
      puts "WARNING: Can't verify state"
      handle_unverified_request
    end

    session.delete(:state)

    # End of implicit flow
    @decoded_token = JsonWebToken.verify(@id_token)

    # Validate Authorization Code
    private_key = ENV['PRIVATE_KEY']
    kid = ENV['KID']
    team_id = ENV['TEAM_ID']

    if !private_key.blank? && !kid.blank? && !team_id.blank?
      hash_code = Digest::SHA256.digest @code
      base64url_encode = Base64.urlsafe_encode64(hash_code[0, hash_code.size/2.to_i], padding: false)
          
      payload = @decoded_token[0]

      unless base64url_encode == payload["c_hash"]
        raise "Invalid Authorization Code"
      end

      # Valid code
      pem_content = private_key

      ecdsa_key = OpenSSL::PKey::EC.new pem_content


      headers = {
        'kid' => kid
      }

      claims = {
        'iss' => team_id,
        'iat' => Time.now.to_i,
        'exp' => Time.now.to_i + 60 * 5,
        'aud' => 'https://appleid.apple.com',
        'sub' => ENV['CLIENT_ID'],
      }

      token = JWT.encode claims, ecdsa_key, 'ES256', headers
      
      uri = URI.parse("https://appleid.apple.com/auth/token")

      header = {'Content-Type': 'application/x-www-form-urlencoded'}

      body = {
        client_id: ENV['CLIENT_ID'],
        client_secret: token,
        code: @code,
        grant_type: "authorization_code",
        redirect_uri: ENV['REDIRECT_URI']
      }

      # Create the HTTP objects
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      request = Net::HTTP::Post.new(uri.request_uri, header)
      request.set_form_data(body)

      # Send the request
      response = http.request(request)

      @token_response = response.body
    end

    render 'redirect'
  end

  def handle_unverified_request
    raise(ActionController::InvalidAuthenticityToken)
  end
end
