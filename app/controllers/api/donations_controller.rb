module Api
    class DonationsController < ApplicationController
        def index
            donations = Donation.all
            render json: donations
        end

        def create
            donation = Donation.new(donation_params)
            if donation.save
                render json: donation, status: :created
            else
                render json: { error: donation.error.full_messages }, status: :unprocessable_entity
            end
        end

        private

        def donation_params
            params.require(:donation).permit(:amount, :note, :user_id, :event_id)
        end
    end
end
