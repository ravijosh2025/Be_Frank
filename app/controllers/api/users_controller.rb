module Api
  class UsersController < ApiController
    skip_before_action :authenticate_request, only: [ :create ]

    def index
      users = User.all
      render json: users, status: :ok
    end

    def show
      render json: user, status: :ok
    end

    def create
      user = User.new(user_params)
      if user.save
        render json: user, status: :created
      else
        render json: { errors: user.errors.full_messages }, status: :unprocessable_entity
      end
    end

    def update
      if user.update(user_params)
        render json: user, status: :ok
      else
        render json: { errors: user.errors.full_messages }, status: :unprocessable_entity
      end
    end

    def destroy
      if user.destroy
        render json: { message: "User deleted successfully" }, status: :ok
      else
        render json: { errors: user.errors.full_messages }, status: :unprocessable_entity
      end
    end

    private

    def user
      User.find(params[:id])
    end

    def user_params
      params.require(:user).permit(
        :first_name,
        :last_name,
        :email,
        :password,
        :mobile_number,
        :address,
        :role
        )
    end
  end
end
