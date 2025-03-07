require 'rails_helper'

RSpec.describe Event, type: :model do
  describe "associations" do
    it { should belong_to(:user).with_foreign_key(:user_id) }
    it { should belong_to(:school).with_foreign_key(:school_id) }
    it { should have_many(:donations).dependent(:destroy) }
    it { should have_many(:feedbacks).dependent(:destroy) }
    it { should have_many_attached(:images) }
  end

  describe "validations" do
    it { should validate_presence_of(:name) }
    it { should validate_presence_of(:description) }
    it { should validate_presence_of(:date) }
  end

  describe "database columns" do
    it { should have_db_column(:name).of_type(:string) }
    it { should have_db_column(:description).of_type(:string) }
    it { should have_db_column(:date).of_type(:date) }
    it { should have_db_column(:image_urls).of_type(:text).with_options(array: true, default: []) }
    it { should have_db_column(:video_urls).of_type(:text).with_options(array: true, default: []) }
    it { should have_db_column(:user_id).of_type(:integer) }
    it { should have_db_column(:school_id).of_type(:integer) }
  end
end
