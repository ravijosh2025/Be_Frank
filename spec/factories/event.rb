FactoryBot.define do
  factory :event do
    name { Faker::Lorem.sentence(word_count: 3) }
    description { Faker::Lorem.paragraph(sentence_count: 2) }
    date { Faker::Date.forward(days: 30) } # This generates a random date within the next 30 days from today.
    user
    school
  end
end
