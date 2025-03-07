require 'rails_helper'

RSpec.describe User, type: :model do
  describe "associations" do
    it { should have_many(:events).dependent(:destroy) }
    it { should have_many(:donations).dependent(:destroy) }
    it { should have_many(:feedbacks).dependent(:destroy) }
    it { should have_many(:feedback_replies).dependent(:destroy) }
  end

  describe "validations" do
    it { should validate_presence_of(:first_name) }
    it { should validate_presence_of(:last_name) }
    it { should validate_presence_of(:role) }
    it { should validate_presence_of(:email) }
    it { should validate_presence_of(:mobile_number) }
    it { should validate_presence_of(:address) }
    it { should validate_uniqueness_of(:email).case_insensitive }
    it { should allow_value("user@example.com").for(:email) }
    it { should_not allow_value("invalid_email").for(:email) }
    it { should allow_value("+911234567890").for(:mobile_number) }
    it { should allow_value("1234567890").for(:mobile_number) }
    it { should_not allow_value("12345").for(:mobile_number) }
    it { should_not allow_value("abcd12345").for(:mobile_number) }
  end

  describe "database columns" do
    it { should have_db_column(:first_name).of_type(:string) }
    it { should have_db_column(:last_name).of_type(:string) }
    it { should have_db_column(:email).of_type(:string) }
    it { should have_db_column(:encrypted_password).of_type(:string) }
    it { should have_db_column(:role).of_type(:string) }
    it { should have_db_column(:mobile_number).of_type(:string) }
    it { should have_db_column(:address).of_type(:text) }
  end

  describe "callbacks" do
    it "downcases email before saving" do
      user = User.create!(first_name: "John", last_name: "Doe", role: "user",
                          email: "TEST@EXAMPLE.COM", password: "password",
                          mobile_number: "1234567890", address: "Somewhere")
      expect(user.reload.email).to eq("test@example.com")
    end
  end
end
