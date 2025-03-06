class EventSerializer < ActiveModel::Serializer
  include Rails.application.routes.url_helpers

  attributes :id,
             :name,
             :description,
             :date,
             :video_urls,
             :image_urls

  belongs_to :user, key: :user, if: -> { object.user.present? } do
    { id: object.user.id, first_name: object.user.first_name, last_name: object.user.last_name, role: object.user.role }
  end
  belongs_to :school
  has_many :feedbacks
end
