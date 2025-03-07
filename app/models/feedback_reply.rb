class FeedbackReply < ApplicationRecord
    belongs_to :feedback, foreign_key: :feedback_id
    belongs_to :user, foreign_key: :user_id

    validates :reply, presence: true, length: { minimum: 5, maximum: 500, message: "should be between 5 to 500 characters" }
    validates :user, presence: true
    validates :feedback, presence: true
end
