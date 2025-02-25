module Api
    class EventsController < ApplicationController
        before_action :set_event, only: [ :show, :update, :destroy ]
        skip_before_action :authenticate_request, only: [ :index ]

        def index
            events = Event.all
            render json: events
        end

        def show
            render json: @event
        end

        def create
            event = Event.new(event_params)
            if event.save
                render json: event, status: :created
            else
                render json: { error: event.error.full_messages }, status: :unprocessable_entity
            end
        end

        def update
            if @event.update(event_params)
                render json: @event, status: :ok
            else
                render json: { error: event.error.full_messages }, status: :unprocessable_entity
            end
        end

        def destroy
            if @event.destroy
                render json: @event, status: :ok
            else
                render json: { message: @event.error.full_messages }, status: :unprocessable_entity
            end
        end

        private

        def set_event
            @event = Event.find(params[:id])
        end

        def event_params
            params.require(:event).permit(:name, :description, :date, { image_urls: [] }, { video_urls: [] }, :user_id, :school_id)
        end
    end
end
