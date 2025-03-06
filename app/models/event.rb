class Event < ApplicationRecord
    has_many_attached :images

    belongs_to :user, foreign_key: :user_id
    belongs_to :school, foreign_key: :school_id
    has_many :donations, dependent: :destroy
    has_many :feedbacks, dependent: :destroy

    validates :name, presence: true
    validates :description, presence: true
    validates :date, presence: true

  def image_urls
    if images.attached?
      images.map { |image| Rails.application.routes.url_helpers.rails_blob_path(image, only_path: true) }
    else
        []
    end
  end
end
