class FeedbackSerializer < ActiveModel::Serializer
  attributes :id,
             :feedback,
             :user,
             :feedback_replies
end
