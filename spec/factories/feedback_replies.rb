FactoryBot.define do
  factory :feedback_reply do
    reply { Faker::Lorem.sentence(word_count: 10) }
    association :user
    association :feedback
  end
end
