class UserDonationsController < ApplicationController
  before_action :authenticate_user!
  def index
    @donations = Donation.all
  end
end
