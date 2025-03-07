class AuthenticationControllersController < ApplicationController
  before_action :authenticate_request
  skip_before_action :authenticate_request, only: [ :login ]
  skip_before_action :verify_authenticity_token # This does not work

  def login
    user = User.find_by(email: params[:email])
    if user && user.valid_password?(params[:password])
      token = JsonWebToken.encode(user_id: user.id)
      save_jwt_to_redis(user.id, token)
      render json: { user: user, token: token }, status: :ok
    else
      render json: { error: "Invalid email or password" }, status: :unauthorized
    end
  end

  def logout
    REDIS.del(@current_user.id)
    render json: { message: "Logged out successfully" }, status: :ok
  end

  private

  def save_jwt_to_redis(user_id, token)
    REDIS.set(user_id, token)
    REDIS.expire(user_id, 24.hours.to_i)
  end
end
