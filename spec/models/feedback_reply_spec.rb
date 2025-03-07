require 'rails_helper'

RSpec.describe FeedbackReply, type: :model do
  describe "associations" do
    it { should belong_to(:user) }
    it { should belong_to(:feedback) }
  end

  describe "validations" do
    it { should validate_presence_of(:reply) }
    it { should validate_length_of(:reply).is_at_least(5).is_at_most(500).with_message("should be between 5 to 500 characters") }
    it { should validate_presence_of(:user) }
    it { should validate_presence_of(:feedback) }
  end
end
