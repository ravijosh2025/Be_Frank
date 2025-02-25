class Event < ApplicationRecord
    belongs_to :user, foreign_key: :user_id
    belongs_to :school, foreign_key: :school_id
    has_many :donations, dependent: :destroy
    has_many :feedbacks, dependent: :destroy
    
    validates :name, presence:true
    validates :description, presence:true
    validates :date, presence:true
end
