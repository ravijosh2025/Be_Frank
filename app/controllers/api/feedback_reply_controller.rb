module Api
    class FeedbackReplyController < ApplicationController
        before_action :set_reply, only: [ :update, :destroy ]

        def index
            replies = FeedbackReply.all
            render json: replies
        end

        def create
            reply = FeedbackReply.new(reply_params)
            if reply.save
                render json: reply, status: :created
            else
                render json: { error: feedback.error.full_messages }, status: :unprocessable_entity
            end
        end

        def update
            if @reply.update(reply_params)
                render json: @reply, status: :ok
            else
                render json: { error: @reply.error.full_messages }, status: :unprocessable_entity
            end
        end

        def destroy
            if @reply.destroy
                render json: @reply, status: :ok
            else
                render json: { error: @reply.error.full_messages }, status: :unprocessable_entity
            end
        end

        private
        def set_reply
            @reply = FeedbackReply.find(params[:id])
        end

        def reply_params
            params.require(:feedback_reply).permit(
                :reply,
                :user_id,
                :feedback_id
                )
        end
    end
end
