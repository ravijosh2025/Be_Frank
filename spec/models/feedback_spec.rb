require 'rails_helper'

RSpec.describe Feedback, type: :model do
  describe "associations" do
    it { should belong_to(:user) }
    it { should belong_to(:event) }
    it { should have_many(:feedback_replies).dependent(:destroy) }
  end

  describe "validations" do
    it { should validate_presence_of(:feedback) }
    it { should validate_length_of(:feedback).is_at_least(10).is_at_most(1000).with_message("should be between 10 to 1000 characters") }
    it { should validate_presence_of(:user) }
    it { should validate_presence_of(:event) }
  end
end
