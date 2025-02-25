module Auth
  def authenticate_request
    header = request.headers["Authorization"]
    token = header.split(" ").last if header
    decoded = JsonWebToken.decode(token)

    if decoded && decoded[:user_id] && is_valid_token?(token, decoded["user_id"])
      @current_user = User.find_by(id: decoded[:user_id])
    else
      render json: { error: "Unauthorized" }, status: :unauthorized
    end
  end

  def is_valid_token?(token, user_id)
    get_stored_token(user_id)==token
  end

  def get_stored_token(user_id)
    REDIS.get(user_id)
  end
end
