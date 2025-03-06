class SchoolSerializer < ActiveModel::Serializer
  attributes :id,
             :name,
             :city,
             :state
end
