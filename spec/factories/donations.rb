FactoryBot.define do
  factory :donation do
    amount { Faker::Number.number(digits: 3).to_s }
    note { Faker::Lorem.sentence(word_count: 8) }
    association :user
    association :event
  end
end
