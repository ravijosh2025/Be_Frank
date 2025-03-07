FactoryBot.define do
  factory :feedback do
    feedback { Faker::Lorem.sentence(word_count: 20) }
    association :user
    association :event
  end
end
