class DonationSerializer < ActiveModel::Serializer
  attributes :amount,
             :note

  belongs_to :user, key: :user, if: -> { object.user.present? } do
    { id: object.user.id, first_name: object.user.first_name, last_name: object.user.last_name, role: object.user.role }
  end

  belongs_to :event, key: :event, if: -> { object.event.present? } do
    { id: object.event.id, name: object.event.name }
  end
end
