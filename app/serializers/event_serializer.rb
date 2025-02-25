class EventSerializer < ActiveModel::Serializer
  attributes :id, :name, :description, :date, :image_urls, :video_urls

  belongs_to :user, key: :user, if: -> { object.user.present? } do
    { id: object.user.id, first_name: object.user.first_name, last_name: object.user.last_name, role: object.user.role }
  end
  belongs_to :school
  has_many :feedbacks
end
