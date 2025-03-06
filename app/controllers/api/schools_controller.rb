module Api
    class SchoolsController < ApplicationController
        before_action :set_school, only: [ :show, :update, :destroy ]

        def index
            schools=School.all
            render json: schools
        end

        def show
            render json: @school
        end

        def create
           school=School.new(school_params)
           if school.save
            render json: school, status: :created
           else
            render json: { error: school.error.full_messages }, status: :unprocessable_entity
           end
        end

        def update
            if @school.update(school_params)
                render json: @school, status: :ok
            else
                render json: { error: @school.error.full_messages }, status: :unprocessable_entity
            end
        end

        def destroy
            if @school.destroy
                render json: { message: "School deleted" }, status: :ok
            else
                render json: { message: "School could not find or invalid input" }
            end
        end

        private

        def set_school
            @school=School.find(params[:id])
            rescue ActiveRecord::RecordNotFound
                render json: { error: "School not found" }, status: :not_found
        end

        def school_params
            params.require(:school).permit(
                :name,
                :city,
                :state
                )
        end
    end
end
