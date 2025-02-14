module Auth
  def authenticate_request
    header = request.headers['Authorization']
    token = header.split(' ').last if header
    decoded = JsonWebToken.decode(token)
    user_id = decoded['user_id']
    
    stored_token = REDIS.get(user_id)
    
    if stored_token == token && decoded && decoded[:user_id]
      @current_user = User.find_by(id: decoded[:user_id])
    else
      render json: { error: 'Unauthorized' }, status: :unauthorized
    end
  end
end
