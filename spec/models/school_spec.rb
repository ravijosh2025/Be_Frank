require 'rails_helper'

RSpec.describe School, type: :model do
  describe "associations" do
    it { should have_many(:events).dependent(:destroy) }
  end

  describe "validations" do
    it { should validate_presence_of(:name) }
    it { should validate_presence_of(:city) }
    it { should validate_presence_of(:state) }
  end

  describe "database columns" do
    it { should have_db_column(:name).of_type(:string) }
    it { should have_db_column(:city).of_type(:string) }
    it { should have_db_column(:state).of_type(:string) }
  end
end
