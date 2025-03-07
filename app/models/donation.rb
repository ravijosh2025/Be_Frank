class Donation < ApplicationRecord
    belongs_to :user, foreign_key: :user_id
    belongs_to :event, foreign_key: :event_id

    validates :amount, presence: true, numericality: { greater_than: 0, message: "must be a valid positive number" }
    validates :note, length: { maximum: 500, message: "should not exceed 500 characters" }, allow_blank: true
    validates :user, presence: true
    validates :event, presence: true
end
