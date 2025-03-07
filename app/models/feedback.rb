class Feedback < ApplicationRecord
    belongs_to :user, foreign_key: :user_id
    belongs_to :event, foreign_key: :event_id
    has_many :feedback_replies, dependent: :destroy, class_name: "FeedbackReply", foreign_key: :feedback_id

    validates :feedback, presence: true, length: { minimum: 10, maximum: 1000, message: "should be between 10 to 1000 characters" }
    validates :user, presence: true
    validates :event, presence: true
end
