class FeedbackReplySerializer < ActiveModel::Serializer
  attributes :id, :reply, :feedback_id
end
