# frozen_string_literal: true
require 'net/http'
require 'uri'
require 'jwt'

class JsonWebToken
  def self.verify(token)

    JWT.decode(
      token, nil,
      true, # Verify the signature of this token
      algorithm: 'RS256',
      iss: 'https://appleid.apple.com',
      verify_iss: true,
      verify_expiration: false,
      aud: ENV['CLIENT_ID'],
      verify_aud: true) do |header|
        jwks_hash[header['kid']]
      end
  end

  def self.jwks_hash
    jwks_raw = Net::HTTP.get URI("https://appleid.apple.com/auth/keys")
    jwks_keys = Array(JSON.parse(jwks_raw)['keys'])
  
    Hash[
      jwks_keys.map do |k|
        n = k['n']
        e = k['e']
    
        if RUBY_VERSION <= "2.3.1"
          key = OpenSSL::PKey::RSA.new
          key.e = OpenSSL::BN.new(Base64.urlsafe_decode64(e), 2)
          key.n = OpenSSL::BN.new(Base64.urlsafe_decode64(n), 2)
        else
          key = OpenSSL::PKey::RSA.new
          key.set_key(OpenSSL::BN.new(Base64.urlsafe_decode64(n), 2), OpenSSL::BN.new(Base64.urlsafe_decode64(e), 2), nil)
        end

        [
          k['kid'],
          key
        ]
      end
    ]
  end
end