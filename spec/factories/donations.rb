FactoryBot.define do
  factory :donation do
    amount { Faker::Number.decimal(l_digits: 2, r_digits: 2).to_s } # "75.50"
    note { Faker::Lorem.sentence(word_count: 8) }
    association :user
    association :event
  end
end
