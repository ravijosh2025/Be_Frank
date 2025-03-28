class JsonWebToken
  SECRET_KEY = Rails.application.secret_key_base

  def self.encode(payload, exp = 24.hours.from_now)
    payload[:exp] = exp.to_i
    JWT.encode(payload, SECRET_KEY)
  end

  def self.decode(token)
    body = JWT.decode(token, SECRET_KEY)[0]  # 1. Decode the token using SECRET_KEY
    HashWithIndifferentAccess.new(body)       # 2. Convert it into a hash that allows both string & symbol keys
    rescue
     nil                                       # 3. If decoding fails (invalid token), return nil
  end
end
