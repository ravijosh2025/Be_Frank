require 'rails_helper'

RSpec.describe Donation, type: :model do
  describe "associations" do
    it { should belong_to(:user) }
    it { should belong_to(:event) }
  end

  describe "validations" do
    it { should validate_presence_of(:amount) }
    it { should validate_presence_of(:user) }
    it { should validate_presence_of(:event) }
  end

  describe "database columns" do
    it { should have_db_column(:amount).of_type(:string) }
    it { should have_db_column(:note).of_type(:text) }
    it { should have_db_column(:user_id).of_type(:integer) }
    it { should have_db_column(:event_id).of_type(:integer) }
  end
end
