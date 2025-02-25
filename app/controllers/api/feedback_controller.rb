module Api
    class FeedbackController < ApplicationController
        before_action :set_feedback, only: [ :update, :destroy ]

        def index
            feedbacks = Feedback.all
            render json: feedbacks, include: [ "feedback_reply" ]
        end

        def create
            feedback = Feedback.new(feedback_params)
            if feedback.save
                render json: feedback, status: :created
            else
                render json: { error: feedback.error.full_messages }, status: :unprocessable_entity
            end
        end

        def update
            if @feedback.update(feedback_params)
                render json: @feedback, status: :ok
            else
                render json: { error: @feedback.error.full_messages }, status: :unprocessable_entity
            end
        end

        def destroy
            if @feedback.destroy
                render json: { message: "Feedback deleteed succesfully." }, status: :ok
            else
                render json: { error: @feedback.error.full_messages }, status: :unprocessable_entity
            end
        end

        private

        def set_feedback
            @feedback = Feedback.find(params[:id])
        end

        def feedback_params
            params.require(:feedback).permit(:feedback, :user_id, :event_id)
        end
    end
end
