class FeedbackReply < ApplicationRecord
    belongs_to :feedback, foreign_key: :feedback_id
    belongs_to :user, foreign_key: :user_id

    validates :reply, presence:true
end
