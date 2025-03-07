module Api
  class SchoolsController < ApiController
    before_action :set_school, only: %i[show update destroy]

    def index
      schools = School.all
      render json: schools, status: :ok
    end

    def show
      render json: @school, status: :ok
    end

    def create
      school = School.new(school_params)
      if school.save
        render json: school, status: :created
      else
        render json: { errors: school.errors.full_messages }, status: :unprocessable_entity
      end
    end

    def update
      if @school.update(school_params)
        render json: @school, status: :ok
      else
        render json: { errors: @school.errors.full_messages }, status: :unprocessable_entity
      end
    end

    def destroy
      if @school.destroy
        render json: { message: "School deleted successfully" }, status: :ok
      else
        render json: { errors: "Failed to delete school" }, status: :unprocessable_entity
      end
    end

    private

    def set_school
      @school = School.find_by(id: params[:id])
      render json: { errors: "School not found" }, status: :not_found unless @school
    end

    def school_params
      params.require(:school).permit(:name, :city, :state)
    end
  end
end
